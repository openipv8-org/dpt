#!/bin/bash
# mac-test.sh - test dpt on this Mac and send the log to the dev VM.
# Get it with git (public: no login), once:
#   git clone https://github.com/openipv8-org/dpt ~/dpt
# and run it:
#   bash ~/dpt/scripts/mac-test.sh
# Later, for the newest version first:  git -C ~/dpt pull
#
# 1. The program: built from this checkout when Go is installed,
#    otherwise the release binary for this Mac (Apple Silicon or Intel)
#    from github.com/openipv8-org/dpt, checked against SHA256SUMS.
# 2. Runs the tests: help, version, bad usage, ping, DNS, time, JSON,
#    the shell, and dhcp (without root: must refuse; with sudo: the
#    real probe; macOS asks for your Mac password once).
# 3. Copies the log to the dev VM (~/ipv8dev/testlogs/dpt-mac-test.log);
#    scp asks for the VM password.
# Nothing is installed; everything stays in ~/dpt-mac-test/.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
DIR="$HOME/dpt-mac-test"
LOG="$DIR/dpt-mac-test.log"
mkdir -p "$DIR" && cd "$DIR" || exit 1
: > "$LOG"

case "$(uname -m)" in
	arm64) BIN=dpt-darwin-arm64 ;;
	x86_64) BIN=dpt-darwin-amd64 ;;
	*) echo "unknown Mac CPU: $(uname -m)" | tee -a "$LOG"; exit 1 ;;
esac
URL=https://github.com/openipv8-org/dpt/releases/latest/download

say() { echo "$*" | tee -a "$LOG"; }

# run <title> <expected exit> <command...>: logs the command, its output
# and whether the exit code was the one expected
PASS=0 FAIL=0
run() {
	local title=$1 want=$2
	shift 2
	say ""
	say "=== $title"
	say "\$ $*"
	"$@" >> "$LOG" 2>&1 < /dev/null
	local got=$?
	if [ "$got" = "$want" ]; then
		say "--- exit $got (expected $want): PASS"
		PASS=$((PASS + 1))
	else
		say "--- exit $got (expected $want): FAIL"
		FAIL=$((FAIL + 1))
	fi
}

say "dpt Mac test  $(date)"
say "macOS $(sw_vers -productVersion) $(uname -m)"

say "checkout: $(git -C "$REPO" log --oneline -1 2>/dev/null)"
if command -v go >/dev/null; then
	say "building from the checkout with $(go version)"
	(cd "$REPO" && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(git describe --tags --always --dirty)" -o "$DIR/$BIN" ./cmd/dpt) >> "$LOG" 2>&1 || {
		say "build FAILED"
		exit 1
	}
	say "built OK"
	(cd "$REPO" && go test ./...) >> "$LOG" 2>&1 && say "go test: PASS" || say "go test: FAIL"
else
	say "no Go here: the release binary instead"
	curl -fsSL -o "$BIN" "$URL/$BIN" && curl -fsSL -o SHA256SUMS "$URL/SHA256SUMS" || {
		say "download failed from $URL"
		exit 1
	}
	if grep " $BIN\$" SHA256SUMS | shasum -a 256 -c - >> "$LOG" 2>&1; then
		say "checksum OK"
	else
		say "checksum FAILED: not running it"
		exit 1
	fi
fi
chmod +x "$BIN"
xattr -d com.apple.quarantine "$BIN" 2>/dev/null
D="./$BIN"

run "version" 0 "$D" --version
run "help" 0 "$D" --help
run "bad usage" 3 "$D" --bogus
run "two targets" 3 "$D" 1.1.1.1 8.8.8.8
run "all tests on 1.1.1.1" 0 "$D" 1.1.1.1 -c 3
run "ping only, verbose" 0 "$D" 8.8.8.8 -p -c 3 --verbose
run "DNS only on 1.1.1.1" 0 "$D" 1.1.1.1 -d -c 3
run "time only, time.apple.com as the target" 0 "$D" time.apple.com -t
run "a name with every IPv4 address" 0 "$D" one.one.one.one -4 --all -c 2
run "IPv6 ping (fails if this network has no IPv6)" 0 "$D" 2606:4700:4700::1111 -p -c 2
run "a dead address (must FAIL)" 1 "$D" 192.0.2.1 -p -c 2 -w 1
run "JSON" 0 "$D" 1.1.1.1 -tdp -c 2 --json
run "dhcp without root (must refuse)" 2 "$D" dhcp

say ""
say "=== shell"
printf 'set type=mx\nietf.org\nset type=a\ngoogle.com 1.1.1.1\n8.8.8.8\nset all\nping 1.1.1.1 2\ntime time.apple.com\nexit\n' | "$D" >> "$LOG" 2>&1
say "--- shell exit $?"

say ""
say "=== dhcp with sudo (macOS asks for your Mac password)"
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
say "default interface: ${IFACE:-none}"
if [ -n "$IFACE" ]; then
	sudo "$D" dhcp -td --iface "$IFACE" --random-mac >> "$LOG" 2>&1 < /dev/null
	say "--- dhcp exit $? (0 or 1 means it ran; 2 means it could not)"
fi

say ""
say "SUMMARY: $PASS passed, $FAIL failed (shell and sudo dhcp: read the log)"
say "log: $LOG"

echo
echo "Copying the log to the dev VM (asks for the VM password)..."
if scp -P 2222 "$LOG" jamie@127.0.0.1:ipv8dev/testlogs/dpt-mac-test.log; then
	echo "Sent. Tell spock: dpt Mac test is in."
else
	echo "Copy failed. The log is at $LOG"
fi
