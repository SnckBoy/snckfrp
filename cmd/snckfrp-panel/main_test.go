package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPBKDF2SHA256MatchesStandardVector(t *testing.T) {
	got := fmtHex(pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32))
	const want = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("PBKDF2 result = %s, want %s", got, want)
	}
}
func fmtHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&15]
	}
	return string(out)
}

func TestNormalizeTunnelAssignsGloballyAvailableRemotePort(t *testing.T) {
	got, err := normalizeTunnel(Tunnel{Name: "ssh2", Type: "tcp", LocalIP: "127.0.0.1", LocalPort: 22}, []Tunnel{{Name: "ssh", Type: "tcp", RemotePort: 20000}})
	if err != nil {
		t.Fatal(err)
	}
	if got.RemotePort != 20001 {
		t.Fatalf("remote port = %d, want 20001", got.RemotePort)
	}
}
func TestNormalizeTunnelRejectsDuplicateRemotePort(t *testing.T) {
	_, err := normalizeTunnel(Tunnel{Name: "ssh2", Type: "tcp", LocalIP: "127.0.0.1", LocalPort: 22, RemotePort: 2222}, []Tunnel{{Name: "ssh", Type: "tcp", RemotePort: 2222}})
	if err == nil || !strings.Contains(err.Error(), "already assigned") {
		t.Fatalf("expected duplicate-port error, got %v", err)
	}
}
func TestNormalizeTunnelRejectsUnsafeName(t *testing.T) {
	_, err := normalizeTunnel(Tunnel{Name: "../../bad", Type: "tcp", LocalPort: 22}, nil)
	if err == nil {
		t.Fatal("expected unsafe name to be rejected")
	}
}
func TestNormalizeTunnelRejectsDuplicateDomain(t *testing.T) {
	_, err := normalizeTunnel(Tunnel{Name: "site2", Type: "https", LocalIP: "127.0.0.1", LocalPort: 443, Domain: "example.test"}, []Tunnel{{Name: "site", Type: "https", Domain: "EXAMPLE.TEST"}})
	if err == nil || !strings.Contains(err.Error(), "domain is already assigned") {
		t.Fatalf("expected duplicate-domain error, got %v", err)
	}
}
func TestRenderClientConfigUsesSharedServerTokenAndProfileScopedNames(t *testing.T) {
	got, err := renderClientConfig(Config{ServerAddr: "frp.example.test", ServerPort: 7000, AuthToken: "shared-secret"}, Profile{ID: "abc123", Tunnels: []Tunnel{{Name: "ssh", Type: "tcp", LocalIP: "127.0.0.1", LocalPort: 22, RemotePort: 2222, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`serverAddr = "frp.example.test"`, `token = "shared-secret"`, `name = "abc123-ssh"`, `remotePort = 2222`} {
		if !strings.Contains(got, want) {
			t.Errorf("config missing %q", want)
		}
	}
}
func TestRenderClientConfigOmitsDisabledTunnels(t *testing.T) {
	got, err := renderClientConfig(Config{ServerAddr: "frp.example.test", ServerPort: 7000, AuthToken: "secret"}, Profile{ID: "profile", Tunnels: []Tunnel{{Name: "off", Type: "tcp", LocalIP: "127.0.0.1", LocalPort: 80, RemotePort: 20000, Enabled: false}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "profile-off") {
		t.Fatal("disabled tunnel appeared in client config")
	}
}
func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := passwordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword("correct horse battery staple", h) {
		t.Fatal("valid password did not verify")
	}
	if verifyPassword("wrong password", h) {
		t.Fatal("invalid password verified")
	}
}
func TestAPIRequiresCSRFForProfileCreation(t *testing.T) {
	hash, err := passwordHash("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: Config{ServerAddr: "127.0.0.1", ServerPort: 7000, AuthToken: "secret", StateFile: t.TempDir() + "/state.json"}, state: State{Admin: Admin{Username: "admin", PasswordHash: hash}, Profiles: []Profile{}}, sessions: map[string]Session{}, loginAttempts: map[string][]time.Time{}}
	h := app.routes()
	login := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"a-long-test-password"}`))
	login.RemoteAddr = "127.0.0.1:12345"
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, login)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var loginBody struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginBody); err != nil {
		t.Fatal(err)
	}
	cookie := loginRec.Result().Cookies()[0]
	withoutCSRF := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"desktop"}`))
	withoutCSRF.AddCookie(cookie)
	withoutCSRFRec := httptest.NewRecorder()
	h.ServeHTTP(withoutCSRFRec, withoutCSRF)
	if withoutCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("without CSRF status=%d, want 403", withoutCSRFRec.Code)
	}
	withCSRF := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"desktop"}`))
	withCSRF.AddCookie(cookie)
	withCSRF.Header.Set("X-CSRF-Token", loginBody.CSRF)
	withCSRFRec := httptest.NewRecorder()
	h.ServeHTTP(withCSRFRec, withCSRF)
	if withCSRFRec.Code != http.StatusCreated {
		t.Fatalf("with CSRF status=%d body=%s", withCSRFRec.Code, withCSRFRec.Body.String())
	}
}
