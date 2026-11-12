// Copyright 2026 SnckBoy
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultConfig = "/etc/snckfrp/panel.json"
	sessionCookie = "snckfrp_session"
	sessionTTL    = 12 * time.Hour
)

type Config struct {
	Listen     string `json:"listen"`
	PanelURL   string `json:"panelUrl"`
	ServerAddr string `json:"serverAddr"`
	ServerPort int    `json:"serverPort"`
	AuthToken  string `json:"authToken"`
	StateFile  string `json:"stateFile"`
}
type Admin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}
type Tunnel struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	LocalIP    string `json:"localIp"`
	LocalPort  int    `json:"localPort"`
	RemotePort int    `json:"remotePort,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Enabled    bool   `json:"enabled"`
}
type Profile struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"createdAt"`
	Tunnels   []Tunnel  `json:"tunnels"`
}
type State struct {
	Admin    Admin     `json:"admin"`
	Profiles []Profile `json:"profiles"`
}
type Session struct {
	CSRF    string
	Expires time.Time
}
type App struct {
	cfg           Config
	mu            sync.Mutex
	state         State
	sessions      map[string]Session
	loginAttempts map[string][]time.Time
}

func main() {
	configPath := flag.String("config", defaultConfig, "panel configuration file")
	initAdmin := flag.Bool("init-admin", false, "initialize the first administrator")
	flag.Parse()
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if *initAdmin {
		user, pass := os.Getenv("SNCKFRP_ADMIN_USER"), os.Getenv("SNCKFRP_ADMIN_PASSWORD")
		if user == "" || len(pass) < 12 {
			log.Fatal("SNCKFRP_ADMIN_USER and a SNCKFRP_ADMIN_PASSWORD of at least 12 characters are required")
		}
		app := &App{cfg: cfg}
		if err := app.loadState(); err != nil {
			log.Fatal(err)
		}
		if app.state.Admin.Username != "" {
			log.Fatal("an administrator already exists; refusing to overwrite it")
		}
		hash, err := passwordHash(pass)
		if err != nil {
			log.Fatal(err)
		}
		app.state.Admin = Admin{Username: user, PasswordHash: hash}
		if err := app.saveState(); err != nil {
			log.Fatal(err)
		}
		log.Printf("administrator %q initialized", user)
		return
	}
	app := &App{cfg: cfg, sessions: map[string]Session{}, loginAttempts: map[string][]time.Time{}}
	if err := app.loadState(); err != nil {
		log.Fatal(err)
	}
	if app.state.Admin.Username == "" {
		log.Fatal("no administrator configured; rerun installer to initialize an admin")
	}
	server := &http.Server{Addr: cfg.Listen, Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("SnckFRP panel listening on %s", cfg.Listen)
	log.Fatal(server.ListenAndServe())
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleHome)
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/session", a.requireAuth(a.handleSession))
	mux.HandleFunc("/api/logout", a.requireAuth(a.handleLogout))
	mux.HandleFunc("/api/settings", a.requireAuth(a.handleSettings))
	mux.HandleFunc("/api/profiles", a.requireAuth(a.handleProfiles))
	mux.HandleFunc("/api/profiles/", a.requireAuth(a.handleProfileResource))
	mux.HandleFunc("/bootstrap/", a.handleBootstrap)
	return securityHeaders(mux)
}

func loadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config: %w", err)
	}
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8080"
	}
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return c, errors.New("serverPort must be between 1 and 65535")
	}
	if c.AuthToken == "" || c.StateFile == "" {
		return c, errors.New("authToken and stateFile are required")
	}
	return c, nil
}
func (a *App) loadState() error {
	if err := os.MkdirAll(filepath.Dir(a.cfg.StateFile), 0700); err != nil {
		return err
	}
	b, err := os.ReadFile(a.cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		a.state = State{Profiles: []Profile{}}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &a.state); err != nil {
		return err
	}
	if a.state.Profiles == nil {
		a.state.Profiles = []Profile{}
	}
	return nil
}
func (a *App) saveState() error {
	b, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.cfg.StateFile), 0700); err != nil {
		return err
	}
	tmp := a.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.cfg.StateFile); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(a.cfg.StateFile, 0600)
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func pbkdf2SHA256(password, salt []byte, rounds, keyLen int) []byte {
	const hashLen = 32
	blocks := (keyLen + hashLen - 1) / hashLen
	derived := make([]byte, 0, blocks*hashLen)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		mac.Write(counter[:])
		u := mac.Sum(nil)
		out := append([]byte(nil), u...)
		for i := 1; i < rounds; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range out {
				out[j] ^= u[j]
			}
		}
		derived = append(derived, out...)
	}
	return derived[:keyLen]
}

func passwordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const rounds = 210000
	derived := pbkdf2SHA256([]byte(password), salt, rounds, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", rounds, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(derived)), nil
}
func verifyPassword(password, encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	rounds, err := strconv.Atoi(p[1])
	if err != nil || rounds < 100000 || rounds > 1000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(p[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(p[3])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, rounds, len(want))
	return hmac.Equal(got, want)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}
func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, pageHTML)
}
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNotAllowed(w)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	a.mu.Lock()
	attempts := a.loginAttempts[ip]
	cutoff := time.Now().Add(-10 * time.Minute)
	fresh := attempts[:0]
	for _, t := range attempts {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	a.loginAttempts[ip] = fresh
	if len(a.loginAttempts) > 10000 {
		for key, values := range a.loginAttempts {
			if len(values) == 0 {
				delete(a.loginAttempts, key)
			}
		}
	}
	blocked := len(fresh) >= 8
	a.mu.Unlock()
	if blocked {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Username != a.state.Admin.Username || !verifyPassword(in.Password, a.state.Admin.PasswordHash) {
		a.mu.Lock()
		a.loginAttempts[ip] = append(a.loginAttempts[ip], time.Now())
		a.mu.Unlock()
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	sid, err := randomHex(32)
	if err != nil {
		http.Error(w, "session error", 500)
		return
	}
	csrf, err := randomHex(24)
	if err != nil {
		http.Error(w, "session error", 500)
		return
	}
	a.mu.Lock()
	delete(a.loginAttempts, ip)
	a.sessions[sid] = Session{CSRF: csrf, Expires: time.Now().Add(sessionTTL)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", MaxAge: int(sessionTTL.Seconds())})
	writeJSON(w, 200, map[string]any{"csrf": csrf, "username": a.state.Admin.Username})
}
func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Error(w, "authentication required", 401)
			return
		}
		a.mu.Lock()
		s, ok := a.sessions[c.Value]
		if ok && time.Now().After(s.Expires) {
			delete(a.sessions, c.Value)
			ok = false
		}
		a.mu.Unlock()
		if !ok {
			http.Error(w, "authentication required", 401)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("X-CSRF-Token") != s.CSRF {
			http.Error(w, "invalid CSRF token", 403)
			return
		}
		next(w, r)
	}
}
func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		methodNotAllowed(w)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c, _ := r.Cookie(sessionCookie)
	s := a.sessions[c.Value]
	writeJSON(w, 200, map[string]any{"username": a.state.Admin.Username, "csrf": s.CSRF, "serverAddr": a.cfg.ServerAddr, "serverPort": a.cfg.ServerPort, "panelUrl": a.cfg.PanelURL, "profiles": a.state.Profiles})
}
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		methodNotAllowed(w)
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PATCH" {
		methodNotAllowed(w)
		return
	}
	var in struct {
		ServerAddr string `json:"serverAddr"`
		PanelURL   string `json:"panelUrl"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.ServerAddr) > 253 || strings.ContainsAny(in.ServerAddr, " /\\\n\r") {
		http.Error(w, "invalid server address", 422)
		return
	}
	if len(in.PanelURL) > 512 || (in.PanelURL != "" && !(strings.HasPrefix(in.PanelURL, "http://") || strings.HasPrefix(in.PanelURL, "https://"))) {
		http.Error(w, "panel URL must start with http:// or https://", 422)
		return
	}
	a.mu.Lock()
	previous := a.cfg
	a.cfg.ServerAddr = strings.TrimSpace(in.ServerAddr)
	a.cfg.PanelURL = strings.TrimRight(strings.TrimSpace(in.PanelURL), "/")
	if err := writeConfig(a.cfg, os.Getenv("SNCKFRP_CONFIG")); err != nil {
		a.cfg = previous
		a.mu.Unlock()
		http.Error(w, "could not save settings", 500)
		return
	}
	updated := map[string]any{"serverAddr": a.cfg.ServerAddr, "panelUrl": a.cfg.PanelURL}
	a.mu.Unlock()
	writeJSON(w, 200, updated)
}
func writeConfig(c Config, path string) error {
	if path == "" {
		path = defaultConfig
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
func (a *App) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		a.mu.Lock()
		defer a.mu.Unlock()
		writeJSON(w, 200, a.state.Profiles)
	case "POST":
		var in struct {
			Name string `json:"name"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		name := strings.TrimSpace(in.Name)
		if name == "" || len(name) > 64 {
			http.Error(w, "profile name must be 1-64 characters", 422)
			return
		}
		id, err := randomHex(8)
		if err != nil {
			http.Error(w, "id generation failed", 500)
			return
		}
		key, err := randomHex(24)
		if err != nil {
			http.Error(w, "key generation failed", 500)
			return
		}
		p := Profile{ID: id, Name: name, Key: key, CreatedAt: time.Now().UTC(), Tunnels: []Tunnel{}}
		a.mu.Lock()
		a.state.Profiles = append(a.state.Profiles, p)
		err = a.saveState()
		a.mu.Unlock()
		if err != nil {
			http.Error(w, "could not save profile", 500)
			return
		}
		writeJSON(w, 201, p)
	default:
		methodNotAllowed(w)
	}
}
func (a *App) allTunnels(exceptProfileID, exceptTunnelID string) []Tunnel {
	var out []Tunnel
	for _, profile := range a.state.Profiles {
		for _, tunnel := range profile.Tunnels {
			if profile.ID == exceptProfileID && tunnel.ID == exceptTunnelID {
				continue
			}
			out = append(out, tunnel)
		}
	}
	return out
}

func (a *App) handleProfileResource(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "profiles" {
		http.NotFound(w, r)
		return
	}
	id := parts[2]
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := -1
	for i := range a.state.Profiles {
		if a.state.Profiles[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	p := &a.state.Profiles[idx]
	if len(parts) == 3 {
		switch r.Method {
		case "PATCH":
			var in struct {
				Name string `json:"name"`
			}
			if !decodeJSON(w, r, &in) {
				return
			}
			n := strings.TrimSpace(in.Name)
			if n == "" || len(n) > 64 {
				http.Error(w, "invalid profile name", 422)
				return
			}
			p.Name = n
			if err := a.saveState(); err != nil {
				http.Error(w, "save failed", 500)
				return
			}
			writeJSON(w, 200, p)
		case "DELETE":
			a.state.Profiles = append(a.state.Profiles[:idx], a.state.Profiles[idx+1:]...)
			if err := a.saveState(); err != nil {
				http.Error(w, "save failed", 500)
				return
			}
			writeJSON(w, 200, map[string]bool{"ok": true})
		default:
			methodNotAllowed(w)
		}
		return
	}
	if len(parts) == 4 && parts[3] == "config" {
		if r.Method != "GET" {
			methodNotAllowed(w)
			return
		}
		config, err := renderClientConfig(a.cfg, *p)
		if err != nil {
			http.Error(w, "could not render config", 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="frpc-`+p.ID+`.toml"`)
		_, _ = io.WriteString(w, config)
		return
	}
	if len(parts) == 4 && parts[3] == "tunnels" {
		if r.Method != "POST" {
			methodNotAllowed(w)
			return
		}
		var in Tunnel
		if !decodeJSON(w, r, &in) {
			return
		}
		t, err := normalizeTunnel(in, a.allTunnels("", ""))
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		t.ID, _ = randomHex(8)
		p.Tunnels = append(p.Tunnels, t)
		if err := a.saveState(); err != nil {
			http.Error(w, "save failed", 500)
			return
		}
		writeJSON(w, 201, t)
		return
	}
	if len(parts) == 5 && parts[3] == "tunnels" {
		tid := parts[4]
		ti := -1
		for i := range p.Tunnels {
			if p.Tunnels[i].ID == tid {
				ti = i
				break
			}
		}
		if ti < 0 {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case "PATCH":
			var in Tunnel
			if !decodeJSON(w, r, &in) {
				return
			}
			in.ID = tid
			t, err := normalizeTunnel(in, a.allTunnels(id, tid))
			if err != nil {
				http.Error(w, err.Error(), 422)
				return
			}
			p.Tunnels[ti] = t
			if err := a.saveState(); err != nil {
				http.Error(w, "save failed", 500)
				return
			}
			writeJSON(w, 200, t)
		case "DELETE":
			p.Tunnels = append(p.Tunnels[:ti], p.Tunnels[ti+1:]...)
			if err := a.saveState(); err != nil {
				http.Error(w, "save failed", 500)
				return
			}
			writeJSON(w, 200, map[string]bool{"ok": true})
		default:
			methodNotAllowed(w)
		}
		return
	}
	http.NotFound(w, r)
}
func withoutTunnel(items []Tunnel, id string) []Tunnel {
	out := make([]Tunnel, 0, len(items))
	for _, t := range items {
		if t.ID != id {
			out = append(out, t)
		}
	}
	return out
}

var safeName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,48}$`)

func normalizeTunnel(t Tunnel, existing []Tunnel) (Tunnel, error) {
	t.Name = strings.TrimSpace(t.Name)
	if !safeName.MatchString(t.Name) {
		return t, errors.New("tunnel name must use 1-48 letters, numbers, _ or -")
	}
	for _, e := range existing {
		if e.Name == t.Name {
			return t, errors.New("tunnel name is already used by another profile")
		}
	}
	switch t.Type {
	case "tcp", "udp", "http", "https":
	default:
		return t, errors.New("type must be tcp, udp, http or https")
	}
	if t.LocalIP == "" {
		t.LocalIP = "127.0.0.1"
	}
	if net.ParseIP(t.LocalIP) == nil {
		return t, errors.New("local IP must be a valid IP address")
	}
	if t.LocalPort < 1 || t.LocalPort > 65535 {
		return t, errors.New("local port must be between 1 and 65535")
	}
	if t.Type == "tcp" || t.Type == "udp" {
		if t.RemotePort == 0 {
			used := map[int]bool{}
			for _, e := range existing {
				if e.Type == t.Type && e.RemotePort > 0 {
					used[e.RemotePort] = true
				}
			}
			for port := 20000; port <= 40000; port++ {
				if !used[port] {
					t.RemotePort = port
					break
				}
			}
		}
		if t.RemotePort < 1 || t.RemotePort > 65535 {
			return t, errors.New("remote port must be between 1 and 65535")
		}
		for _, e := range existing {
			if e.Type == t.Type && e.RemotePort == t.RemotePort {
				return t, errors.New("remote port is already assigned for this protocol")
			}
		}
	} else {
		t.Domain = strings.TrimSpace(t.Domain)
		if t.Domain == "" || len(t.Domain) > 253 || strings.ContainsAny(t.Domain, " /\\\n\r") {
			return t, errors.New("HTTP and HTTPS tunnels require a valid domain")
		}
		for _, e := range existing {
			if e.Type == t.Type && strings.EqualFold(e.Domain, t.Domain) {
				return t, errors.New("domain is already assigned for this protocol")
			}
		}
	}
	return t, nil
}
func (a *App) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		methodNotAllowed(w)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "bootstrap" {
		http.NotFound(w, r)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.state.Profiles {
		if p.ID == parts[1] && hmac.Equal([]byte(p.Key), []byte(parts[2])) {
			cfg, err := renderClientConfig(a.cfg, p)
			if err != nil {
				http.Error(w, "config unavailable", 500)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, cfg)
			return
		}
	}
	http.NotFound(w, r)
}
func renderClientConfig(c Config, p Profile) (string, error) {
	if strings.TrimSpace(c.ServerAddr) == "" {
		return "", errors.New("server address is not configured")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = %q\nserverPort = %d\n\n[auth]\nmethod = \"token\"\ntoken = %q\n\n", c.ServerAddr, c.ServerPort, c.AuthToken)
	for _, t := range p.Tunnels {
		if !t.Enabled {
			continue
		}
		fmt.Fprintf(&b, "[[proxies]]\nname = %q\ntype = %q\nlocalIP = %q\nlocalPort = %d\n", p.ID+"-"+t.Name, t.Type, t.LocalIP, t.LocalPort)
		if t.Type == "tcp" || t.Type == "udp" {
			fmt.Fprintf(&b, "remotePort = %d\n", t.RemotePort)
		} else {
			fmt.Fprintf(&b, "customDomains = [%q]\n", t.Domain)
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		http.Error(w, "invalid JSON request", 400)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func methodNotAllowed(w http.ResponseWriter) { http.Error(w, "method not allowed", 405) }

//go:embed index.html
var pageHTML string
