#!/bin/bash
# install.sh - install dpt in /usr/local/bin on Linux or macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/install.sh | bash
# or, from a checkout:
#   bash ~/dpt/scripts/install.sh
#
# Downloads the latest release for this system (amd64 or arm64), checks
# it against the release's SHA256SUMS, and copies it to /usr/local/bin/dpt
# (sudo asks for your password when needed).  Nothing is built.
# Run it again to update.
set -eu

DEST=/usr/local/bin
URL=https://github.com/openipv8-org/dpt/releases/latest/download

case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) echo "install.sh: Linux or macOS only (Windows: dpt-windows-*.exe from the release page)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) echo "install.sh: no dpt build for $(uname -m)" >&2; exit 1 ;;
esac
BIN=dpt-$os-$arch

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "downloading $BIN (latest release)"
curl -fsSL -o "$TMP/$BIN" "$URL/$BIN"
curl -fsSL -o "$TMP/SHA256SUMS" "$URL/SHA256SUMS"

if command -v sha256sum >/dev/null 2>&1; then
	sum() { sha256sum -c -; }
else
	sum() { shasum -a 256 -c -; }
fi
if ! (cd "$TMP" && grep " $BIN\$" SHA256SUMS | sum >/dev/null); then
	echo "install.sh: checksum does not match: not installing" >&2
	exit 1
fi
echo "checksum OK"
chmod 755 "$TMP/$BIN"
[ "$os" = darwin ] && xattr -d com.apple.quarantine "$TMP/$BIN" 2>/dev/null || true

SUDO=
if [ ! -w "$DEST" ] || { [ -e "$DEST/dpt" ] && [ ! -w "$DEST/dpt" ]; }; then
	[ "$(id -u)" = 0 ] || SUDO=sudo
fi
$SUDO mkdir -p "$DEST"
$SUDO install -m 755 "$TMP/$BIN" "$DEST/dpt"
echo "installed: $("$DEST/dpt" --version) in $DEST/dpt"
case ":$PATH:" in
	*":$DEST:"*) ;;
	*) echo "note: $DEST is not on your PATH" ;;
esac
