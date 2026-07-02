#!/bin/sh
# netcage installer: download the latest release, verify its checksum, and put
# BOTH binaries (netcage + its required netcage-dns helper) on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/wighawag/netcage/main/install.sh | sh
#
# Options (environment variables):
#   NETCAGE_VERSION   version tag to install (default: latest, e.g. v0.2.0)
#   PREFIX            install dir (default: $HOME/.local/bin; falls back to
#                     /usr/local/bin when writable). Both binaries go here so
#                     netcage finds netcage-dns as its sibling.
#
# netcage is Linux-only (its jail is built on Linux netns + nftables). This
# script refuses to install on non-Linux.
set -eu

REPO="wighawag/netcage"
BIN="netcage"
HELPER="netcage-dns"

info() { printf '%s\n' "netcage-install: $*" >&2; }
err() {
	printf '%s\n' "netcage-install: error: $*" >&2
	exit 1
}

# --- platform ---------------------------------------------------------------
os="$(uname -s)"
[ "$os" = "Linux" ] || err "netcage is Linux-only (got $os). On macOS/Windows it runs only inside a Linux VM; install it there."

arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) target="linux_amd64" ;;
aarch64 | arm64) target="linux_arm64" ;;
armv7l | armv7) target="linux_armv7" ;;
armv6l | armv6) target="linux_armv6" ;;
arm*)
	# Unqualified arm: prefer armv7, the common 32-bit Raspberry Pi target.
	info "unrecognised arm variant '$arch'; defaulting to armv7 (set the tarball manually if wrong)"
	target="linux_armv7"
	;;
*) err "unsupported architecture '$arch' (supported: amd64, arm64, armv7, armv6)" ;;
esac

# --- tools ------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
	dl() { curl -fsSL "$1" -o "$2"; }
	dlout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	dl() { wget -qO "$2" "$1"; }
	dlout() { wget -qO- "$1"; }
else
	err "need curl or wget on PATH"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
	err "need sha256sum or shasum to verify the download"
fi

# --- version ----------------------------------------------------------------
version="${NETCAGE_VERSION:-}"
if [ -z "$version" ]; then
	info "resolving the latest release..."
	version="$(dlout "https://api.github.com/repos/$REPO/releases/latest" |
		grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
	[ -n "$version" ] || err "could not resolve the latest release tag (set NETCAGE_VERSION=vX.Y.Z)"
fi
# The archive uses the version WITHOUT the leading v (e.g. v0.2.0 -> 0.2.0).
ver_noV="${version#v}"

archive="${BIN}_${ver_noV}_${target}.tar.gz"
base="https://github.com/$REPO/releases/download/$version"

info "installing $BIN $version ($target)"

# --- download + verify ------------------------------------------------------
tmp="$(mktemp -d "${TMPDIR:-/tmp}/netcage-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "downloading $archive"
dl "$base/$archive" "$tmp/$archive" || err "download failed: $base/$archive"
dl "$base/checksums.txt" "$tmp/checksums.txt" || err "download failed: $base/checksums.txt"

want="$(grep " $archive\$" "$tmp/checksums.txt" | awk '{print $1}')"
[ -n "$want" ] || err "no checksum for $archive in checksums.txt"
got="$(sha256 "$tmp/$archive")"
[ "$want" = "$got" ] || err "checksum mismatch for $archive
  expected: $want
  got:      $got"
info "checksum ok"

tar -xzf "$tmp/$archive" -C "$tmp" "$BIN" "$HELPER" || err "failed to extract $BIN and $HELPER"

# --- install dir ------------------------------------------------------------
if [ -n "${PREFIX:-}" ]; then
	dest="$PREFIX"
else
	dest="$HOME/.local/bin"
	# Prefer /usr/local/bin if it exists and is writable (a common PATH dir).
	if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
		dest="/usr/local/bin"
	fi
fi
mkdir -p "$dest" || err "cannot create install dir $dest"

install_one() {
	# Install into the same dir so netcage finds netcage-dns as a sibling.
	if mv "$tmp/$1" "$dest/$1" 2>/dev/null; then :; else
		cp "$tmp/$1" "$dest/$1" || err "cannot write $dest/$1 (try: PREFIX=~/.local/bin, or run with sudo)"
	fi
	chmod +x "$dest/$1"
}
install_one "$BIN"
install_one "$HELPER"

info "installed:"
info "  $dest/$BIN"
info "  $dest/$HELPER"

# --- PATH hint --------------------------------------------------------------
case ":$PATH:" in
*":$dest:"*) ;;
*)
	info ""
	info "NOTE: $dest is not on your PATH. Add it, e.g.:"
	info "  echo 'export PATH=\"$dest:\$PATH\"' >> ~/.profile && . ~/.profile"
	;;
esac

info ""
info "done. Verify the jail with:"
info "  $BIN verify --proxy socks5h://127.0.0.1:9050"
