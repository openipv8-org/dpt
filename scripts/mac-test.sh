#!/bin/bash
# mac-test.sh - test dpt on this Mac and send the log to the dev VM.
# Get it with git (public: no login), once:
#   git clone https://github.com/openipv8-org/dpt ~/dpt
# and run it:
#   bash ~/dpt/scripts/mac-test.sh
# Later, for the newest version first:  git -C ~/dpt pull
#
# 1. Downloads the latest release of dpt for this Mac (Apple Silicon or
#    Intel) from github.com/openipv8-org/dpt and checks it against
#    SHA256SUMS.  Nothing is built.
# 2. Runs the tests: help, version, bad usage, ping, DNS, time, JSON,
#    the shell, dhcp (from a script: must refuse without asking;
#    typed: dpt runs sudo itself, macOS asks for your Mac password),
#    dpt install (typed: sudo, then /usr/local/bin/dpt is this release)
#    and dpt upgrade (must say up to date).
# 3. Copies the log to the dev VM (~/ipv8dev/testlogs/dpt-mac-test.log);
#    scp asks for the VM password.
# The program is left in the checkout as ~/dpt/dpt (run it: ~/dpt/dpt 1.1.1.1),
# the log as ~/dpt/mac-test.log.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
DIR="$REPO"
LOG="$DIR/mac-test.log"
cd "$DIR" || exit 1
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

say "downloading $BIN from the latest release"
curl -fsSL -o "$BIN" "$URL/$BIN" && curl -fsSL -o SHA256SUMS "$URL/SHA256SUMS" || {
	say "download failed from $URL"
	exit 1
}
if grep " $BIN\$" SHA256SUMS | shasum -a 256 -c - >> "$LOG" 2>&1; then
	say "checksum OK"
	mv -f "$BIN" dpt
	rm -f SHA256SUMS
else
	say "checksum FAILED: not running it"
	rm -f "$BIN" SHA256SUMS
	exit 1
fi
chmod +x dpt
xattr -d com.apple.quarantine dpt 2>/dev/null
D="./dpt"

run "version" 0 "$D" --version
run "help" 0 "$D" --help
run "bad usage" 3 "$D" --bogus
run "two targets" 3 "$D" 1.1.1.1 8.8.8.8
run "all tests on 1.1.1.1" 0 "$D" 1.1.1.1 -c 3
run "ping only, verbose" 0 "$D" 8.8.8.8 -p -c 3 --verbose
run "DNS only on 1.1.1.1" 0 "$D" 1.1.1.1 -d -c 3
run "time only, time.apple.com as the target" 0 "$D" time.apple.com -t
run "a name with every IPv4 address" 0 "$D" one.one.one.one -4 --all -c 2
run "a dead address (must FAIL)" 1 "$D" 192.0.2.1 -p -c 2 -w 1
run "JSON" 0 "$D" 1.1.1.1 -tdp -c 2 --json
run "info (reads this Mac, sends nothing)" 0 "$D" info
run "dhcp from a script (must not ask; says it needs sudo)" 2 "$D" dhcp

say ""
say "=== shell"
printf 'set type=mx\nietf.org\nset type=a\ngoogle.com 1.1.1.1\n8.8.8.8\nset all\nping 1.1.1.1 2\ntime time.apple.com\nexit\n' | "$D" >> "$LOG" 2>&1
say "--- shell exit $?"

say ""
say "=== dhcp typed at a terminal: dpt runs sudo itself (macOS asks for your Mac password)"
# no --iface: dpt picks the Ethernet interface with the LAN gateway
# (the default route may be a VPN tunnel, utun*, which has no DHCP)
say "default route: $(route -n get default 2>/dev/null | awk '/interface:/{print $2}') (utun* is a VPN, which can stop offers arriving)"
# script(1) gives dpt a terminal, as if typed; it records what it shows
script -q "$DIR/dhcp.out" "$D" dhcp -td
DX=$?
tr -d '\r' < "$DIR/dhcp.out" | sed "s/$(printf '\033')\[[0-9;]*m//g" >> "$LOG"
rm -f "$DIR/dhcp.out"
say "--- dhcp exit $DX (0 or 1 means it ran; 2 means it could not)"

say ""
say "=== install typed at a terminal: dpt runs sudo itself, copies to /usr/local/bin"
script -q "$DIR/install.out" "$D" install
IX=$?
tr -d '\r' < "$DIR/install.out" >> "$LOG"
rm -f "$DIR/install.out"
REL=$("$D" --version | awk '{print $2}')
GOT=$(/usr/local/bin/dpt --version 2>/dev/null | awk '{print $2}')
if [ "$IX" = 0 ] && [ "$GOT" = "$REL" ]; then
	say "--- install exit $IX, /usr/local/bin/dpt is $GOT: PASS"
	PASS=$((PASS + 1))
else
	say "--- install exit $IX, /usr/local/bin/dpt is ${GOT:-missing} (want $REL): FAIL"
	FAIL=$((FAIL + 1))
fi
run "upgrade (just installed the newest: must say up to date, no sudo)" 0 "$D" upgrade

say ""
say "SUMMARY: $PASS passed, $FAIL failed (shell and sudo dhcp: read the log)"
say "program: $DIR/dpt   log: $LOG"

echo
echo "Copying the log to the dev VM (asks for the VM password)..."
if scp -P 2222 "$LOG" jamie@127.0.0.1:ipv8dev/testlogs/dpt-mac-test.log; then
	echo "Sent. Tell spock: dpt Mac test is in."
else
	echo "Copy failed. The log is at $LOG"
fi
