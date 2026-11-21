# DPT — Diagnostic Ports Time

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
dpt smtp <host> [test <user> [<pw>]] [to <addr>]    SMTP on 25, 465, 587, a login, a test message
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
it says `MEL: dhcp needs sudo` and exits 2.

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

`dpt info` reads what the machine already has, and sends only NTP time
requests: to Google, Microsoft, AWS, Apple and NIST (and the machine's
own time server), to show how far off this clock is. For
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

## SMTP, sweep, ports, connect, trace, outside-ip

`dpt smtp <host>` tries 25 (STARTTLS), 465 (TLS from the start) and 587
(STARTTLS) at once. For each one it shows the greeting, the TLS version,
the certificate (checked against the name), and the AUTH methods offered.
A port nothing listens on is NONE. A port that never answers is FAIL:
many ISPs and clouds block outgoing 25. `test <user>` then logs in
(AUTH PLAIN or LOGIN) where the password is safest. A port with TLS and a
trusted certificate is used first. Next comes TLS with an untrusted
certificate. A plain connection is used only when that is all the server
works with, including when its STARTTLS fails. Among equally safe ports
the order is 587, 465, then 25. A login that is not over trusted TLS is
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
certificate first, then 587, 465, 25.

`dpt smtp` alone (and `smtp` in the shell) asks a line at a time: the
server, the username (Enter: no login), the password, who the test
message is from (Enter: no message), and who it is to.

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

`dpt ports <host>` tries 65 common TCP ports (including mail on 2525 and
8025, and HTTPS on 1443, 2443 ... 14443) and 9 UDP services: DNS (53),
TFTP (69), QUIC (80 and 443), NTP (123), NetBIOS (137), SNMP (161),
SSDP (1900) and mDNS (5353). A UDP port is open only when it answers,
so each is sent a real, harmless request of its own: a DNS query, an
NTP time request, a QUIC packet of a version no one speaks (a QUIC
server must answer with the versions it does), SNMPv3 discovery (no
community string is guessed). Silence is "no answer": open and quiet,
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

A certificate that expires in under 30 days is WARN, in smtp and
connect, with the days left.

In the shell, `host <name>` sets the host the commands act on, and the
prompt shows it beside the DNS server, which stays as it was:
`dpt host [mail.smtp2go.com] server [8.8.8.8]>`. Giving any command a host
(`ports mail.example.com`, `trace 1.1.1.1`) sets it too; then `ping`,
`ping 3`, `ports`, `connect 25`, `trace` and `smtp` act on it. `host`
alone shows it; `host clear` goes back to the server. With no host set,
the commands act on the current server: `sweep` pings the /24 around it
and `ports` tries its ports. Tab completes commands, `set` options, DNS
types and interface names.

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

then in PowerShell, in the folder it downloaded to:

```
.\dpt-windows-amd64.exe install
```

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
