# DPT — Diagnostic Ports Time

## ⬇ Download

| System | Download | Tested |
|---|---|---|
| Windows, most PCs (Intel/AMD) | [dpt-windows-amd64.exe](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-windows-amd64.exe) | ✅ every release, on a Windows machine; and by hand |
| Windows on ARM (Snapdragon, Surface Pro X) | [dpt-windows-arm64.exe](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-windows-arm64.exe) | ✅ every release, on a Windows ARM machine |
| Mac, Apple Silicon (M1 and later) | [dpt-darwin-arm64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-darwin-arm64) | ✅ every release, on an Apple Silicon Mac |
| Mac, Intel | [dpt-darwin-amd64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-darwin-amd64) | ✅ every release, on an Intel Mac; and by hand |
| Linux, Intel/AMD | [dpt-linux-amd64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-linux-amd64) | ✅ every release, on Ubuntu; and by hand on Debian |
| Linux, ARM (Raspberry Pi 64-bit, ARM servers) | [dpt-linux-arm64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-linux-arm64) | ✅ every release, on an ARM Linux machine |

Every release is tested before it is published, on a real machine of each
kind ([GitHub's runners](https://github.com/openipv8-org/dpt/actions/workflows/test.yml)):
the unit tests, then every command of the release's own files, checked for
its exit code and what it must say (`scripts/ci-test.sh`). A release is
published only when all six pass.

"By hand" adds what a robot cannot: typing at the shell, the sudo or UAC
prompt, double-clicking the download, and DHCP on a real office network.
Have an Apple Silicon Mac, a Windows ARM PC or an ARM Linux box? Try that
part and tell us in an [issue](https://github.com/openipv8-org/dpt/issues/new):

- **Mac:** `git clone https://github.com/openipv8-org/dpt ~/dpt` (or `git -C ~/dpt pull`), then `bash ~/dpt/scripts/mac-test.sh`; send `~/dpt/mac-test.log` (press Ctrl-C at the copy to our test machine at the end)
- **Windows:** in PowerShell, `irm https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/windows-test.ps1 | iex`; the results are on the clipboard
- **Linux:** install with the line below, then `dpt info; sudo dpt dhcp; dpt` (type `help`, then `exit`) and paste what it says

Linux and Mac, install or update:
`curl -fsSL https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/install.sh | bash`

**v0.3.2 on Windows:** `dpt --help` was taken for a name, and `dpt ports` showed a UDP port it had no request for as "no answer" even when open or closed. Both are fixed in v0.3.4 (`dpt upgrade`).

One tool for a network morning. Is this address working as a network
peer: ping it, use it as a DNS resolver, ask it for the time and compare
that with public NTP servers, and check this machine's own clock against
them (a drifting clock is what makes JWTs fail). Which ports does it
answer on, what does it say when you connect, and which routers are on
the way? Does its mail server take a login and send a message? And what
DHCP servers are on the segment, and what do they hand out?

```
dpt [dhcp|<address>|<dnsname>] [-tdp] [options]     Linux, macOS
dpt [dhcp|<address>|<dnsname>] [/tdp] [options]     Windows
dpt info                                            this machine's lease, DNS, NTP, clock
dpt smtp <host> [test <user> [<pw>]] [to <addr>]    SMTP on 25, 465, 587, 2525, 8025; what mail can do from here
dpt sweep [ports] [<network>]                       live addresses (and their open ports)
dpt ports <host> [<ports>]                          the common TCP and UDP ports of host, or a list
dpt connect <host> <port> [tls|notls]               connect as telnet would, see what it says, type to it
dpt trace <host>                                    the routers on the way, with times and loss
dpt outside-ip                                      the address the internet sees
dpt install | upgrade                               install, or update to the newest
dpt                                                 interactive shell (nslookup and more)
```

Tests are letters written together; with none, all three run:

| | |
|---|---|
| `t` | time: NTP query, compared with time.google.com and time.windows.com, and this machine's clock checked against them (OK ≤ 50 ms, WARN ≤ 1 s, FAIL beyond or unsynchronised) |
| `d` | DNS: lookups with the address as the resolver |
| `p` | ping: ICMP echo |

`dpt dhcp` sends one DHCPDISCOVER and shows every offer (rogue servers
too) without taking a lease; `t` and `d` then test the NTP and DNS
servers the offers name. It probes the Ethernet interface with the
LAN gateway (never a VPN tunnel) unless `--iface` names one.
On Linux and macOS it sends and listens below UDP (packet socket,
/dev/bpf), so the system's DHCP client cannot take the offers first.
When a VPN tunnel is up it says so in red: `A VPN TUNNEL IS UP (utun3):
dhcp might not work on en1`.

It needs sudo (Linux: or CAP_NET_RAW) or an Administrator prompt.
Typed at a terminal, dpt asks for it itself: it runs sudo (the password
is asked in the same window), or on Windows asks UAC and prints the
elevated run's output in the same window. From a script it never asks:
it says `dpt: dhcp needs sudo` and exits 2.

Options: `-c` / `/c:` count (5), `-w` / `/w:` timeout in seconds (2),
`--names`, `--ntp`, `--all`, `--iface`, `--listen`, `--random-mac`,
`-4`, `-6`, `--json`, `--verbose`. `dpt -h` (or `/?`) lists them.

Exit codes: 0 all OK, 1 a test failed, 2 minimum execution level not
met, 3 bad usage.

```
$ dpt 1.1.1.1
TARGET    1.1.1.1
PING      5/5  loss 0%  rtt min/avg/max/sd 21.0/21.3/21.9/0.4 ms        OK
DNS       5/5 answered by 1.1.1.1  avg 22.8 ms  RA AD EDNS0(1232)       OK
TIME      time.google.com            +0.2 ms  s1  delay   27.8 ms  .GOOG.
          time.windows.com           -4.5 ms  s4  delay   58.3 ms  86.77.84.80
          1.1.1.1                no NTP service
          max divergence 4.8 ms                                         OK
          this clock is 2.1 ms behind the reference servers             OK
FEATURES  icmp dns/udp dns/tcp recursion edns0 dnssec dot(853)
```

FEATURES is what the address offers, of what dpt tries: ping, DNS over
UDP and TCP, recursion, EDNS0, DNSSEC validation, DNS over TLS (853),
NTP, whois (43), RDAP (HTTPS, asked under the name when one is given),
LDAP (389: an anonymous bind gets an LDAP answer) and LDAPS (636).

`dpt info` reads what the machine already has, and sends NTP time
requests: to Google, Microsoft, AWS, Apple and NIST (and the machine's
own time server), to show how far off this clock is. It also asks
ifconfig.me, over IPv4 and IPv6 at once, for the addresses the internet
sees, and shows them last (`OUTSIDE  IPv4 ...  IPv6 ...`); it waits for
them no more than 2.5 seconds from the start, and says why one did not
come (`no IPv6 way out from this machine`, `no answer in 2.5 s`). For
each interface: address, gateway, and the DHCP lease it holds (server,
obtained, expires, the DNS and NTP servers in it); then the DNS and NTP
servers the machine uses (resolv.conf; chrony, timesyncd or ntpd; macOS
Date & Time; Windows Time). Then the clock, always: the time and zone,
whether the system sets it itself (NTP, or the domain on Windows) or it
was set by hand, whether it is in sync, when it last was and how far
off, and where the time came from (Windows: "this machine's own clock"
when no server is set). Some Linux DHCP clients keep the lease readable
by root only: `sudo dpt info` shows it.

To test a particular interface, `--select` (`/select` on Windows) lists
every Ethernet interface that is up, with an address or not, and lets
you choose: `dpt dhcp --select`, `dpt info --select`. In the shell,
`interface` does the same (`interface en0` directly, `interface auto`
to let dpt choose); trydhcp and info then use it. From a script
--select never asks: use `--iface`.

## SMTP, sweep, ports, connect, trace, whois, rdap, time, outside-ip

`dpt smtp <host>` tries 25 (STARTTLS), 465 (TLS from the start), 587
(STARTTLS), and 2525 and 8025 (STARTTLS; providers like smtp2go offer them
where 25 and 587 are blocked) at once. For each one it shows the
greeting, the TLS version, the certificate (checked against the name),
and the AUTH methods offered. A port that fails says why in plain words:
`timed out: a firewall is dropping it` (many ISPs and clouds block
outgoing 25), `refused: nothing listening`, `unreachable`, or connected
with no greeting (something holds the port without speaking SMTP). A
firewall inspecting SMTP (Cisco ASA and the like mask the greeting with
`*` and turn STARTTLS into `XXXXXXXA`) is spotted and named, so a missing
STARTTLS is not blamed on the server. A port whose greeting or
certificate belongs to someone else than the server (an ISP or firewall
answering in its place) is flagged. Nothing on 2525 or 8025 is NONE,
not a failure. It ends with what mail can and cannot do from here:

```
FROM HERE possible      25    STARTTLS, trusted; login PLAIN LOGIN
                        2525  STARTTLS, trusted; login PLAIN LOGIN
          not possible  587   timed out: a firewall is dropping it (no answer in 10s)
                        465   refused: nothing listening

VERDICT   mail from here works on 25 or 2525 with STARTTLS
```
 `test <user>` then logs in
(AUTH PLAIN or LOGIN) where the password is safest. A port with TLS and a
trusted certificate is used first. Next comes TLS with an untrusted
certificate. A plain connection is used only when that is all the server
works with, including when its STARTTLS fails. Among equally safe ports
the order is 587, 465, 2525, 8025, then 25. A login that is not over trusted TLS is
WARN, and says who could have read the password. Leave the password out and dpt asks for it
without echoing it. In the shell, it is never written to the history.

Add `to <address>` and, once logged in, dpt sends a test message on the
same connection: MAIL FROM, RCPT TO, DATA, with the subject
"test from dpt at <this machine's address>" and a body saying which
machine, server, port and user sent it. `from <address>` sets the
sender; without it the user is the sender when it is an address. The
server's reply is shown (`250 2.0.0 OK queued as ...`), or where it
refused: at RCPT, `554 Relay access denied` means the server will not
send for this sender. With `from` and `to` and no `test`, it is sent with
no login, for a server that knows this machine by its address (smtp2go's
IP authentication, an office relay) or one taking mail for its own
addresses. It goes on the port that keeps it safest: TLS with a trusted
certificate first, then 587, 465, 2525, 8025, 25.

`dpt smtp prompt` (and the same in the shell) asks a line at a time: the
server, the username (Enter: no login), the password, who the test
message is from (Enter: no message), and who it is to. The answers are
kept in `.dpt` in your home folder (`%APPDATA%\dpt\.dpt` on Windows),
readable by you only, and offered next time: Enter takes what is
offered, `-` takes none. The password is kept too, so keep the file
private. `dpt smtp` with nothing after it shows how to use it.

```
dpt smtp mail.smtp2go.com test jamie@example.com to someone@example.org
dpt smtp smtp.office365.com test user@example.com from shared@example.com to me@example.com
dpt smtp mail.smtp2go.com from me@example.com to someone@example.org      (IP authentication)
```

`dpt sweep` pings every address on this machine's network, 25 at a time
(two echoes each, 1 s wait), and lists the ones that answer with their
names. `sweep ports` then tries the common ports of each live address.
`sweep 10.0.0.0/24` sweeps that network (an address alone: its /24; at
most /22). Addresses that drop pings (Windows' firewall does by default)
are not listed. `dpt outside-ip` asks https://ifconfig.me/ip.

`dpt ports <host>` tries 66 common TCP ports (including whois on 43,
LDAP on 389 and 636, mail on 2525 and 8025, and HTTPS on 1443, 2443 ...
14443) and 11 UDP services: DNS (53), TFTP (69), QUIC (80 and 443), NTP
(123), NetBIOS (137), SNMP (161), RADIUS (1812, and accounting on 1813),
SSDP (1900) and mDNS (5353). A UDP port is open only when it answers,
so each is sent a real, harmless request of its own: a DNS query, an
NTP time request, a QUIC packet of a version no one speaks (a QUIC
server must answer with the versions it does), SNMPv3 discovery (no
community string is guessed), a RADIUS Status-Server (no shared secret
is guessed, so a RADIUS server that checks it stays silent: only a
closed RADIUS port is told apart). Silence is "no answer": open and quiet,
or dropped by a firewall. To try your own ports:
`dpt ports mail.example.com 587,2525,8025`, ranges `8000-8010`, UDP with
`/udp`: `53/udp,123/udp`.

`dpt connect <host> <port>` is what telnet is used for. It connects,
shows how long that took, the TLS and certificate (on 443, 465, 993,
995, 8443 and the like it speaks TLS from the start; `tls` asks for it
on any port, `notls` turns it off), and what the server says first:
`SSH-2.0-OpenSSH_9.6`, a mail server's greeting, a switch's login
prompt. It names what it sees: SSH, SMTP, FTP, POP3, IMAP, VNC, a telnet
login (WARN: the password would go in the clear). Then, at a terminal,
what you type goes to the server a line at a time and its answers are
shown, until Ctrl-D (Windows: Ctrl-Z, Enter) or Ctrl-C. Lines can be
piped in too: `printf 'GET / HTTP/1.0\r\n\r\n' | dpt connect example.com 80`.
A telnet server's option negotiation is answered (every option refused,
so it falls back to plain lines) and kept out of what is shown; so are
escape sequences and other control characters from the server.

`dpt trace <host>` shows the routers on the way, as traceroute and mtr
do: each hop asked 3 times with an ICMP echo whose TTL runs out there,
every hop at once, so a trace takes about 3 seconds however long the
path. Each hop shows its address, name, the three times, and how many
were lost. Loss at a hop in the middle that the hops after it do not
show is a router too busy to answer, not loss; loss at the last hop is
WARN. Some NATs (VirtualBox's) answer echoes on the address's behalf;
then the address answers at hop 1 and dpt says the routers cannot be
seen from here.

`dpt whois <address | network | AS number | domain>` says who holds it,
by whois (port 43), as the whois of Linux and macOS does (Windows has
none): IANA, the server IANA refers to, then one referral from there (an
RIR's, a domain's registrar). It shows a summary read from the
registry's text (holder, network or AS, abuse contact, dates; for a
domain its registrar, status, name servers, DNSSEC), then the text
itself, and says whether RDAP has it too:

```
$ dpt whois 1.1.1.1
WHOIS     1.1.1.1
SOURCE    whois  APNIC  whois.apnic.net  in 1.5 s
          asked whois.iana.org, then whois.apnic.net
HOLDER    APNIC Research and Development
NETWORK   APNIC-LABS  1.1.1.0 - 1.1.1.255  1.1.1.0/24  AU
ABUSE     helpdesk@apnic.net
ALSO      RDAP has it too: rdap.apnic.net   (dpt rdap 1.1.1.1)

TEXT      % [whois.apnic.net]
          ...
```

`dpt rdap <...>` asks RDAP, whois' successor: IANA's lists say which
registry's RDAP server holds it, and the answer is JSON, read the same
way from every registry. A domain's registrar is asked after its
registry; for `www.example.com` it asks for `example.com`. It says
whether whois has it too, and when there is no RDAP server for it
(some country domains: .de, .io, .jp). `dpt whois <...> both` asks both
and shows the two answers one after the other: they do not always agree.
A server after the question asks that one only: `dpt whois example.com
whois.godaddy.com` (as `whois -h` does), `dpt rdap 8.8.8.8
https://rdap.arin.net/registry/`. A private or documentation address is
named as such, and no registry is asked. `--verbose` adds RDAP's every
contact and remark; `--json` gives the summary and RDAP's own answer.

`dpt time` checks this machine's clock against the reference servers,
and `dpt time <host>` that host's NTP time beside them.
`dpt time native` runs the system's own time tools, so what they say can
be set beside dpt's measurement: `w32tm /query /status` and
`w32tm /stripchart` against time.cloudflare.com, time.google.com and
time.windows.com on Windows; `sntp` against the same on macOS; `chronyc
tracking` and `chronyc sources -v` (or `timedatectl`, or `ntpq -p`) on
Linux. Each command is shown (`$ w32tm /query /status`) and runs when
you press Enter; Ctrl-C stops. Last, dpt measures the clock itself:
`dpt now: this clock is 452.1 ms behind (time.cloudflare.com +452.0 ms ...)`.

`time native sync` resyncs now (`w32tm /resync /force`,
`sudo sntp -sS time.apple.com`, `sudo chronyc makestep`), with dpt's
measurement before and after. `time native sync fix` sets the system to
keep its clock in sync: on Windows, Windows Time starts with Windows and
syncs with time.cloudflare.com, time.google.com and time.windows.com
every hour (a PC on no domain syncs once a week otherwise); on macOS,
network time on, from time.apple.com; on Linux, the time service
installed (chrony, systemd-timesyncd) is turned on, and nothing is
changed when one runs. It says first that you should be the system admin
to run it, and how to put things back, and waits for Enter. On a Windows
PC joined to a domain it refuses, and changes nothing: such a PC MUST
get its time from a domain controller, and one that does not can break
the network's logins (Kerberos allows 5 minutes). `time native sync`
there resyncs with the domain controller. The commands that need
Administrator run with sudo on Linux and macOS; on Windows each is shown
and waited for, then UAC is asked once for them, and their output comes
back to the same window. From a script, `fix` never runs.

A certificate that expires in under 30 days is WARN, in smtp and
connect, with the days left.

In the shell, `server <name>` sets the one server, as in nslookup, and the
prompt shows it: `dpt [mail.smtp2go.com]>`. The commands act on it
(`ping`, `ping 3`, `ports`, `connect 25`, `trace`, and `smtp`, which runs
the whole mail check on it); a host given to one of them is for that
command only. `root` makes a root server the server, as in nslookup.
Lookups go to the server first; when it does not answer, they go to
`fallback=` (8.8.8.8 at the start) and say so:
`*** [mail.smtp2go.com] is not working: falling back to [8.8.8.8]`. When
the fallback does not answer either, the lookup fails.
`set fallback=<server>` changes it (`lserver <server>` is the same), and
`set fallback clear` turns it off: lookups go to the server only. `info`
and `set all` show the server, `fallback=`, `ntpd=` and the interface.
`server clear` goes back to the DNS server dpt started with. With a
server chosen, `sweep` pings the /24 around it. `smtp prompt` asks the
mail questions. Tab completes commands, `set` options, DNS types and
interface names.

## Install

Linux and macOS, into `/usr/local/bin/dpt` (the latest release, checked
against its SHA256SUMS; sudo asks for your password):

```
curl -fsSL https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/install.sh | bash
```

Run it again to update.

macOS, the latest release to download:

- [dpt-darwin-arm64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-darwin-arm64) for Apple Silicon (M1 and later)
- [dpt-darwin-amd64](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-darwin-amd64) for Intel Macs

Windows: download the latest release,

- [dpt-windows-amd64.exe](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-windows-amd64.exe) for most PCs
- [dpt-windows-arm64.exe](https://github.com/openipv8-org/dpt/releases/latest/download/dpt-windows-arm64.exe) for ARM (Snapdragon, Surface Pro X)

and run it (double-click it, or `.\dpt-windows-amd64.exe` in PowerShell).

The download installs itself: run under its download name
(`dpt-windows-amd64.exe`, `dpt-darwin-arm64`, `dpt-linux-amd64`, ...)
with nothing after it, it does `dpt install`, asking for UAC or sudo,
and then says to open a new terminal and type `dpt` (on Windows it waits
for Enter, so a double-clicked window does not vanish). When the same or
a newer dpt is already installed, it changes nothing and says so. With a
command after it (`./dpt-linux-amd64 info`) it just runs the command, to
try dpt without installing it.

Until dpt is signed, Windows SmartScreen warns about it ("Windows
protected your PC": More info, then Run anyway), and on a Mac a
downloaded program must be allowed first (`chmod +x dpt-darwin-arm64`,
then right-click it and Open); the curl line above avoids both.

Once dpt is on a machine, it installs and updates itself:

```
dpt install     put this dpt where the system finds it: /usr/local/bin,
                or C:\Program Files\dpt on Windows (added to PATH)
dpt upgrade     download the newest release, check it against SHA256SUMS,
                and replace the installed one (says so if it is up to date)
```

Both ask for sudo (Windows: UAC) when they need it, and only when
typed; from a script they say what they need and exit 2.

## Test on Windows

In PowerShell (a normal one, not "Run as administrator"):

```
irm https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/windows-test.ps1 | iex
```

It downloads the latest release into `%USERPROFILE%\dpt\dpt.exe`, checks
it, runs the tests, asks two questions about the UAC run, and puts the
log on the clipboard.

## Test on a Mac

```
git clone https://github.com/openipv8-org/dpt ~/dpt
bash ~/dpt/scripts/mac-test.sh
```

Downloads the latest release for the Mac into the checkout as `dpt`
(run it as `~/dpt/dpt`), runs the checks and writes `mac-test.log`.

## Build

Go 1.23 or later, no C compiler: `make dist` builds
`dist/dpt-<os>-<arch>[.exe]` for Linux, macOS and Windows on amd64 and
arm64, and `dist/SHA256SUMS`. `make test` runs the tests.

Authors: Jamie Thain and Claude Opus 5.5 (Anthropic). MIT licence.
