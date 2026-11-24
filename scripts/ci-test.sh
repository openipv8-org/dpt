#!/bin/bash
# ci-test.sh <dpt binary> <version> - test a dpt build on this machine,
# with nobody at the keyboard: GitHub Actions runs it on Linux, macOS and
# Windows (Git Bash), Intel and ARM.  The same checks as mac-test.sh and
# windows-test.ps1, less the hands-on ones (typing at the shell, UAC,
# double-click).
#
# Exact exit codes where the answer does not depend on the network.  Where
# it does (ping is blocked on GitHub's runners, so PING may FAIL), 0 or 1
# with what it must say: it ran and gave an answer.  A Go panic exits 2,
# so a crash is never let through.
set -u
DL=$1 VER=$2
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'   # Git Bash: leave /c:2 alone
chmod +x "$DL" 2>/dev/null

case "$(uname -s)" in
	Linux) OS=linux ;;
	Darwin) OS=darwin ;;
	MINGW* | MSYS* | CYGWIN*) OS=windows ;;
	*) echo "unknown system $(uname -s)"; exit 1 ;;
esac
case "${RUNNER_ARCH:-$(uname -m)}" in
	X64 | x86_64 | amd64) ARCH=amd64 ;;
	ARM64 | arm64 | aarch64) ARCH=arm64 ;;
	*) echo "unknown CPU ${RUNNER_ARCH:-$(uname -m)}"; exit 1 ;;
esac

# under its download name (dpt-linux-amd64) with no command, dpt installs
# itself; the tests run it as plain dpt, the download name is tested last
WORK=$(mktemp -d)
BIN=$WORK/dpt; [ $OS = windows ] && BIN=$WORK/dpt.exe
cp "$DL" "$BIN" && chmod +x "$BIN"

# options as each system writes them
if [ $OS = windows ]; then
	o() { case $1 in c) echo "/c:$2" ;; w) echo "/w:$2" ;; *) echo "/$1" ;; esac; }
	HELP=/? VERSION=/version
else
	o() { case $1 in c) echo "-c $2" ;; w) echo "-w $2" ;; t|d|p|tdp|4) echo "-$1" ;; *) echo "--$1" ;; esac; }
	HELP=--help VERSION=--version
fi

PASS=0 FAIL=0 PRE=
OUT=$(mktemp)
# run <title> <exit codes, a|b> <command...> [-- <must say>...]
run() {
	local title=$1 want=$2 args=() must=()
	shift 2
	while [ $# -gt 0 ] && [ "$1" != -- ]; do args+=("$1"); shift; done
	[ $# -gt 0 ] && shift && must=("$@")
	echo
	echo "=== $title"
	echo "\$ dpt ${args[*]+${args[*]}}"
	$PRE "$BIN" ${args[@]+"${args[@]}"} > "$OUT" 2>&1 < /dev/null
	local got=$? bad=
	cat "$OUT"
	[[ "|$want|" == *"|$got|"* ]] || bad="exit $got, expected $want"
	for m in ${must[@]+"${must[@]}"}; do
		grep -qF -- "$m" "$OUT" || bad="${bad:+$bad; }does not say \"$m\""
	done
	grep -qE '^(panic:|goroutine [0-9]+ \[)' "$OUT" && bad="${bad:+$bad; }crashed"
	if [ -z "$bad" ]; then
		echo "--- PASS (exit $got)"
		PASS=$((PASS + 1))
	else
		echo "--- FAIL: $bad"
		echo "::error title=$OS/$ARCH: $title::$bad"
		FAIL=$((FAIL + 1))
	fi
}

echo "dpt CI test: $OS/$ARCH, $(uname -a)"

# the right program on the right machine, run natively
run "version: this build, this system" 0 $VERSION -- "dpt $VER ($OS/$ARCH)"
run "help" 0 $HELP -- "DPT - Diagnostic Ports Time" "smtp prompt"
run "bad usage" 3 $(o bogus)
run "two targets" 3 1.1.1.1 8.8.8.8
run "a dead address (must FAIL)" 1 192.0.2.1 $(o p) $(o c 2) $(o w 1) -- PING
run "smtp alone (must show how to use it)" 3 smtp -- "smtp prompt"

run "all tests on 1.1.1.1" "0|1" 1.1.1.1 $(o c 3) -- PING DNS TIME
run "ping only, verbose" "0|1" 8.8.8.8 $(o p) $(o c 3) $(o verbose) -- PING
run "DNS only on 1.1.1.1" 0 1.1.1.1 $(o d) $(o c 3) -- DNS OK
run "time only, time.apple.com as the target" "0|1" time.apple.com $(o t) -- TIME
run "a name with every IPv4 address" "0|1" one.one.one.one $(o 4) $(o all) $(o c 2)
run "JSON" "0|1" 1.1.1.1 $(o tdp) $(o c 2) $(o json) -- '"target"'
run "info" "0|1" info -- CLOCK OUTSIDE IPv4 IPv6
run "info as JSON" "0|1" info $(o json) -- '"outside"'
run "smtp: the mail check of mail.smtp2go.com (no login, nothing sent)" "0|1" smtp mail.smtp2go.com -- "PORT 2525" "FROM HERE" VERDICT
run "ports: the common TCP ports and UDP services of 1.1.1.1" "0|1" ports 1.1.1.1 -- TARGET
run "ports: a list, TCP and UDP" "0|1" ports 1.1.1.1 53,443,853,53/udp,123/udp -- TARGET
run "connect: TLS on 443" "0|1" connect 1.1.1.1 443 -- CONNECT TLS
run "trace 8.8.8.8" "0|1" trace 8.8.8.8 -- TARGET
run "outside-ip" 0 outside-ip -- OUTSIDE

echo
echo "=== shell (piped)"
printf 'set type=mx\nietf.org\nset type=a\ngoogle.com 1.1.1.1\nset all\nserver 1.1.1.1\nexit\n' | "$BIN" > "$OUT" 2>&1
SX=$?
cat "$OUT"
if [ $SX = 0 ] && grep -qF "mail exchanger" "$OUT" && grep -qF "fallback =" "$OUT" && grep -qF "dpt [1.1.1.1]>" "$OUT"; then
	echo "--- PASS"; PASS=$((PASS + 1))
else
	echo "--- FAIL: exit $SX, or no MX answer, fallback in set all, or server 1.1.1.1 in the prompt"
	echo "::error title=$OS/$ARCH: shell::exit $SX, or no MX answer, fallback, or server prompt"
	FAIL=$((FAIL + 1))
fi

# dhcp and install need root (Administrator).  The runner's Windows user is
# an Administrator; on Linux and macOS, sudo asks no password there.
if [ $OS = windows ]; then
	run "dhcp (already Administrator: it runs)" "0|1" dhcp $(o w 3) -- DHCP
	run "install" 0 install -- installed
	INST="/c/Program Files/dpt/dpt.exe"
else
	run "dhcp from a script (must not ask; says it needs sudo)" 2 dhcp -- "needs sudo"
	echo; echo "=== sudo dpt dhcp"
	sudo "$BIN" dhcp $(o w 3) > "$OUT" 2>&1 < /dev/null; DX=$?
	cat "$OUT"
	if [[ $DX == [01] ]] && grep -qF DHCP "$OUT" && ! grep -q '^panic:' "$OUT"; then echo "--- PASS (exit $DX)"; PASS=$((PASS + 1))
	else echo "--- FAIL: exit $DX"; echo "::error title=$OS/$ARCH: sudo dhcp::exit $DX"; FAIL=$((FAIL + 1)); fi
	echo; echo "=== sudo dpt install"
	sudo "$BIN" install < /dev/null; IX=$?
	[ $IX = 0 ] || { echo "::error title=$OS/$ARCH: install::exit $IX"; FAIL=$((FAIL + 1)); }
	INST=/usr/local/bin/dpt
fi
GOT=$("$INST" $VERSION 2>/dev/null | awk '{print $2}')
if [ "$GOT" = "$VER" ]; then echo "--- installed $INST is $GOT: PASS"; PASS=$((PASS + 1))
else echo "--- installed $INST is ${GOT:-missing}, want $VER: FAIL"; echo "::error title=$OS/$ARCH: install::$INST is ${GOT:-missing}"; FAIL=$((FAIL + 1)); fi

# the download installs itself: under its download name, with nothing after
# it; the same version is installed now, so it must change nothing
BIN_SAVE=$BIN; BIN=$DL
[ $OS = windows ] || PRE=sudo
run "the download, started with no command (same version installed: nothing changed)" 0 -- "nothing changed"
BIN=$BIN_SAVE PRE=

# upgrade: only for a release version (v1.2.3, v1.2.3-rc1), never a
# between-releases build, which upgrade rightly replaces
if [[ $VER =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-z]+[0-9]*)?$ ]]; then
	run "upgrade (newest or newer installed: up to date, never goes back)" 0 upgrade -- "up to date"
fi

echo
echo "SUMMARY $OS/$ARCH $VER: $PASS passed, $FAIL failed"
[ $FAIL = 0 ]
