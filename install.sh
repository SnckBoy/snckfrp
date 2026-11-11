#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/SnckBoy/snckfrp.git"
APP="snckfrp"
VERSION="1.26.0"
PREFIX="${PREFIX:-/usr/local/bin}"
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
command -v git >/dev/null || fail "git is required"
command -v make >/dev/null || fail "make is required"
command -v go >/dev/null || fail "Go ${VERSION} or newer is required; install Go first"
command -v install >/dev/null || fail "install utility is required"

GO_ACTUAL="$(go env GOVERSION | sed 's/^go//')"
if [ "$(printf '%s\n' "$VERSION" "$GO_ACTUAL" | sort -V | head -n1)" != "$VERSION" ]; then
  fail "Go ${VERSION}+ required; found ${GO_ACTUAL}"
fi

printf '[1/4] Checking out source...\n'
git clone --depth 1 "$REPO" "$WORKDIR/src"
cd "$WORKDIR/src"

printf '[2/4] Building frpc and frps...\n'
make build

[ -x bin/frpc ] || fail "frpc build output missing"
[ -x bin/frps ] || fail "frps build output missing"

printf '[3/4] Installing to %s...\n' "$PREFIX"
if [ ! -d "$PREFIX" ] || [ ! -w "$PREFIX" ]; then
  command -v sudo >/dev/null || fail "write access to $PREFIX required (or set PREFIX to a writable directory)"
  sudo install -d "$PREFIX"
  sudo install -m 0755 bin/frpc "$PREFIX/frpc"
  sudo install -m 0755 bin/frps "$PREFIX/frps"
else
  install -m 0755 bin/frpc "$PREFIX/frpc"
  install -m 0755 bin/frps "$PREFIX/frps"
fi

printf '[4/4] Verifying installed binaries...\n'
"$PREFIX/frpc" --version
"$PREFIX/frps" --version
printf '\nInstalled successfully. No services were started and no firewall rules were changed.\n'
printf 'Review the official documentation and configure only systems you own or administer.\n'
