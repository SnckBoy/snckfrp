#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/SnckBoy/snckfrp.git"
PREFIX="${PREFIX:-/usr/local/bin}"
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
need_apt() {
  [ -r /etc/os-release ] || fail "cannot identify this Linux distribution"
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) ;;
    *) fail "automatic dependency setup supports Ubuntu and Debian; install git, make, and Go 1.21+ manually" ;;
  esac
}

if ! command -v git >/dev/null || ! command -v make >/dev/null || ! command -v go >/dev/null; then
  need_apt
  printf '[1/4] Installing build prerequisites...
'
  if [ "$(id -u)" -eq 0 ]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y git make golang-go ca-certificates
  else
    command -v sudo >/dev/null || fail "sudo is required to install build prerequisites"
    sudo apt-get update
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y git make golang-go ca-certificates
  fi
fi

command -v git >/dev/null || fail "git is required"
command -v make >/dev/null || fail "make is required"
command -v go >/dev/null || fail "Go is required"
command -v install >/dev/null || fail "install utility is required"

BOOTSTRAP_VERSION="$(go env GOVERSION | sed 's/^go//')"
MIN_BOOTSTRAP="1.21.0"
if [ "$(printf '%s\n' "$MIN_BOOTSTRAP" "$BOOTSTRAP_VERSION" | sort -V | head -n1)" != "$MIN_BOOTSTRAP" ]; then
  fail "Go 1.21+ is required for automatic toolchain selection; found $BOOTSTRAP_VERSION"
fi

# go.mod selects the project's required Go toolchain automatically.
export GOTOOLCHAIN=auto

printf '[2/4] Checking out source...
'
git clone --depth 1 "$REPO" "$WORKDIR/src"
cd "$WORKDIR/src"

printf '[3/4] Building frpc and frps...
'
make build
[ -x bin/frpc ] || fail "frpc build output missing"
[ -x bin/frps ] || fail "frps build output missing"

printf '[4/4] Installing to %s...
' "$PREFIX"
if [ ! -d "$PREFIX" ] || [ ! -w "$PREFIX" ]; then
  command -v sudo >/dev/null || fail "write access to $PREFIX required (or set PREFIX to a writable directory)"
  sudo install -d "$PREFIX"
  sudo install -m 0755 bin/frpc "$PREFIX/frpc"
  sudo install -m 0755 bin/frps "$PREFIX/frps"
else
  install -m 0755 bin/frpc "$PREFIX/frpc"
  install -m 0755 bin/frps "$PREFIX/frps"
fi

"$PREFIX/frpc" --version
"$PREFIX/frps" --version
printf '\nInstalled successfully. No services were started and no firewall rules were changed.\n'
printf 'Use these binaries only on systems and networks you own or are authorized to administer.\n'
