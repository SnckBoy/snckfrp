# SnckFRP management panel

SnckFRP packages the FRP client/server binaries with a small, self-hosted management panel. The panel runs on TCP **8080** by default; the FRP control listener runs on TCP **7000** by default.

## One-command installation (Ubuntu / Debian)

```bash
curl -fsSL https://raw.githubusercontent.com/SnckBoy/snckfrp/main/install.sh | sudo bash
```

The installer builds `frpc`, `frps`, and `snckfrp-panel`, asks for the public VPS address and initial administrator credentials, creates a shared FRP authentication token, installs two systemd services, and starts them. Set `SNCKFRP_ADMIN_USER`, `SNCKFRP_ADMIN_PASSWORD`, and `SNCKFRP_SERVER_ADDR` before running for non-interactive setup. Administrator passwords must be at least 12 characters.

Open `http://YOUR_VPS_IP:8080` and sign in with the administrator account created during installation. The panel supports multiple named client profiles and TCP, UDP, HTTP, and HTTPS tunnel definitions; profile-specific configuration downloads; private bootstrap links; profile/tunnel editing and deletion; and a configurable public server address.

## Services and files

- `snckfrp-panel.service` — authenticated management UI on `0.0.0.0:8080`.
- `snckfrp-frps.service` — FRP server on `0.0.0.0:7000`.
- `/etc/snckfrp/frps.toml` — FRP server configuration.
- `/var/lib/snckfrp/panel.json` — panel listener, server address, shared token and state path.
- `/var/lib/snckfrp/state.json` — administrator password hash and client profiles.

Useful commands:

```bash
systemctl status snckfrp-panel snckfrp-frps
journalctl -u snckfrp-panel -f
journalctl -u snckfrp-frps -f
```

Open TCP 8080 and TCP 7000 in both the VPS firewall and cloud security group. Also allow the public remote ports assigned to TCP/UDP tunnels. HTTP/HTTPS tunnels require the corresponding FRP vhost listeners and DNS records; configure these before using those tunnel types.

## Authentication model and client setup

Native FRP token authentication is server-wide. SnckFRP therefore uses one shared FRP authentication token for the server and a separate random bootstrap key for each client profile. The bootstrap key protects access to that profile's generated configuration; it is not a per-profile FRP authentication token.

Install the `frpc` binary on the client device, then use the profile's **Copy setup command** action to fetch `frpc.toml` and start the client. After changing a tunnel, download the updated configuration and restart `frpc` on that client. The panel does not silently control remote PCs or auto-install software on them.

## Security notes

The panel uses administrator authentication, HttpOnly/SameSite session cookies, CSRF checks for state-changing API requests, rate-limited login attempts, hashed administrator passwords, and private file permissions. The bootstrap URL is a bearer secret: keep it private and rotate/delete the profile if it is exposed. Do not expose the panel over plain HTTP on an untrusted network; put it behind HTTPS with a trusted reverse proxy. The installer does not modify cloud firewall rules.

---

