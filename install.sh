#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/SnckBoy/snckfrp.git"
PREFIX="${PREFIX:-/usr/local/bin}"
CONFIG_DIR="/etc/snckfrp"
DATA_DIR="/var/lib/snckfrp"
SERVICE_USER="snckfrp"
PANEL_PORT="${SNCKFRP_PANEL_PORT:-8080}"
FRP_PORT="${SNCKFRP_FRP_PORT:-7000}"
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run with root privileges: curl -fsSL ... | sudo bash"
[ -r /etc/os-release ] || fail "cannot identify this Linux distribution"
. /etc/os-release
case "${ID:-}" in ubuntu|debian) ;; *) fail "automatic installation supports Ubuntu and Debian" ;; esac

for value in "$PANEL_PORT" "$FRP_PORT"; do
  [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || fail "ports must be between 1 and 65535"
done
[ "$PANEL_PORT" != "$FRP_PORT" ] || fail "panel and FRP ports must be different"

printf '[1/6] Installing build prerequisites...\n'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y git make golang-go ca-certificates curl python3 iproute2
command -v go >/dev/null || fail "Go is required"
BOOTSTRAP_VERSION="$(go env GOVERSION | sed 's/^go//')"
MIN_BOOTSTRAP="1.21.0"
if [ "$(printf '%s\n' "$MIN_BOOTSTRAP" "$BOOTSTRAP_VERSION" | sort -V | head -n1)" != "$MIN_BOOTSTRAP" ]; then
  fail "Go 1.21+ is required for automatic toolchain selection; found $BOOTSTRAP_VERSION"
fi
export GOTOOLCHAIN=auto

printf '[2/6] Downloading SnckFRP source...\n'
git clone --depth 1 "$REPO" "$WORKDIR/src"
cd "$WORKDIR/src"

printf '[3/6] Building FRP and the SnckFRP panel...\n'
mkdir -p bin
make build
go build -trimpath -ldflags "-s -w" -o bin/snckfrp-panel ./cmd/snckfrp-panel
[ -x bin/frpc ] || fail "frpc build output missing"
[ -x bin/frps ] || fail "frps build output missing"
[ -x bin/snckfrp-panel ] || fail "snckfrp-panel build output missing"

printf '[4/6] Installing binaries...\n'
install -d -m 0755 "$PREFIX"
install -m 0755 bin/frpc "$PREFIX/frpc"
install -m 0755 bin/frps "$PREFIX/frps"
install -m 0755 bin/snckfrp-panel "$PREFIX/snckfrp-panel"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"

if [ ! -f "$DATA_DIR/panel.json" ]; then
  printf '[5/6] First-time administrator setup...\n'
  ADMIN_USER="${SNCKFRP_ADMIN_USER:-admin}"
  ADMIN_PASSWORD="${SNCKFRP_ADMIN_PASSWORD:-}"
  SERVER_ADDR="${SNCKFRP_SERVER_ADDR:-}"
  if [ -z "$ADMIN_PASSWORD" ] || [ -z "$SERVER_ADDR" ]; then
    [ -r /dev/tty ] || fail "set SNCKFRP_ADMIN_PASSWORD and SNCKFRP_SERVER_ADDR for non-interactive installation"
    if [ -z "$SERVER_ADDR" ]; then read -r -p "Public IP or hostname for this VPS: " SERVER_ADDR </dev/tty; fi
    if [ -z "$ADMIN_PASSWORD" ]; then
      read -r -p "Administrator username [admin]: " entered_user </dev/tty
      [ -n "$entered_user" ] && ADMIN_USER="$entered_user"
      read -r -s -p "Administrator password (12+ characters): " ADMIN_PASSWORD </dev/tty; printf '\n'
      read -r -s -p "Confirm password: " ADMIN_PASSWORD_CONFIRM </dev/tty; printf '\n'
      [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ] || fail "passwords do not match"
    fi
  fi
  [ "${#ADMIN_PASSWORD}" -ge 12 ] || fail "administrator password must contain at least 12 characters"
  [ -n "$SERVER_ADDR" ] || fail "SNCKFRP_SERVER_ADDR or a public IP/hostname is required"
  [[ "$SERVER_ADDR" != *[[:space:]/\\]* ]] || fail "server address must be a hostname or IP without a scheme or path"
  PANEL_URL="${SNCKFRP_PANEL_URL:-http://${SERVER_ADDR}:${PANEL_PORT}}"
  AUTH_TOKEN="${SNCKFRP_AUTH_TOKEN:-$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')}"
  [[ "$AUTH_TOKEN" =~ ^[A-Za-z0-9_-]{32,256}$ ]] || fail "SNCKFRP_AUTH_TOKEN must be 32-256 letters, numbers, underscores or hyphens"
  cat > "$CONFIG_DIR/frps.toml" <<EOF_FRPS
bindPort = ${FRP_PORT}
vhostHTTPPort = 8081
vhostHTTPSPort = 8443

[auth]
method = "token"
token = "${AUTH_TOKEN}"
EOF_FRPS
  chmod 0640 "$CONFIG_DIR/frps.toml"
  export SNCKFRP_CONFIG="$DATA_DIR/panel.json"
  export SNCKFRP_PANEL_PORT="$PANEL_PORT" SNCKFRP_FRP_PORT="$FRP_PORT"
  export SNCKFRP_PANEL_URL_VALUE="$PANEL_URL" SNCKFRP_SERVER_ADDR_VALUE="$SERVER_ADDR" SNCKFRP_AUTH_TOKEN_VALUE="$AUTH_TOKEN"
  python3 - "$DATA_DIR/panel.json" <<'PY_CONFIG'
import json, os, sys
config = {
    "listen": "0.0.0.0:" + os.environ.get("SNCKFRP_PANEL_PORT", "8080"),
    "panelUrl": os.environ["SNCKFRP_PANEL_URL_VALUE"],
    "serverAddr": os.environ["SNCKFRP_SERVER_ADDR_VALUE"],
    "serverPort": int(os.environ["SNCKFRP_FRP_PORT"]),
    "authToken": os.environ["SNCKFRP_AUTH_TOKEN_VALUE"],
    "stateFile": "/var/lib/snckfrp/state.json",
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
os.chmod(sys.argv[1], 0o640)
PY_CONFIG
  chown "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR/panel.json"
  SNCKFRP_ADMIN_USER="$ADMIN_USER" SNCKFRP_ADMIN_PASSWORD="$ADMIN_PASSWORD" "$PREFIX/snckfrp-panel" --init-admin --config "$DATA_DIR/panel.json"
  unset ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM 2>/dev/null || true
else
  printf '[5/6] Existing panel configuration found; preserving administrator and server settings.\n'
fi

# Pass installer values to the config writer without exposing secrets in process arguments.
if [ ! -f "$CONFIG_DIR/frps.toml" ]; then
  fail "missing $CONFIG_DIR/frps.toml; existing installation is incomplete"
fi
chown root:"$SERVICE_USER" "$CONFIG_DIR/frps.toml"
chmod 0640 "$CONFIG_DIR/frps.toml"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR"

cat > /etc/systemd/system/snckfrp-frps.service <<EOF_FRPS_UNIT
[Unit]
Description=SnckFRP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${PREFIX}/frps -c ${CONFIG_DIR}/frps.toml
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=${CONFIG_DIR}/frps.toml

[Install]
WantedBy=multi-user.target
EOF_FRPS_UNIT

cat > /etc/systemd/system/snckfrp-panel.service <<EOF_PANEL_UNIT
[Unit]
Description=SnckFRP web management panel
After=network-online.target snckfrp-frps.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
Environment=SNCKFRP_CONFIG=${DATA_DIR}/panel.json
ExecStart=${PREFIX}/snckfrp-panel -config ${DATA_DIR}/panel.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF_PANEL_UNIT

printf '[6/6] Enabling services...\n'
systemctl daemon-reload
systemctl enable --now snckfrp-frps.service snckfrp-panel.service

printf '\nSnckFRP installation completed.\n'
printf 'Panel: http://%s:%s\n' "${SNCKFRP_SERVER_ADDR:-${SERVER_ADDR:-your-vps-ip}}" "$PANEL_PORT"
printf 'FRP server port: %s/tcp\n' "$FRP_PORT"
printf 'Services: systemctl status snckfrp-panel snckfrp-frps\n'
printf '\nAllow TCP %s (panel), TCP %s (FRP), TCP 8081 (HTTP vhost), and TCP 8443 (HTTPS vhost) in your VPS firewall and cloud firewall.\n' "$PANEL_PORT" "$FRP_PORT"
printf 'Also allow each public tunnel port you assign in the panel. Use HTTPS via a trusted reverse proxy before exposing the panel to untrusted networks.\n'
