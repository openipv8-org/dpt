# dpt — DNS Ping Time

Is this address working as a network peer? One command answers it: ping
it, use it as a DNS resolver, ask it for the time and compare that with
public NTP servers, and check this machine's own clock against them (a
drifting clock is what makes JWTs fail). Or look at every DHCP server on
the segment and what it hands out.

```
dpt [dhcp|<address>|<dnsname>] [-tdp] [options]     Linux, macOS
dpt [dhcp|<address>|<dnsname>] [/tdp] [options]     Windows
dpt info                                            this machine's lease, DNS, NTP
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

`dpt info` sends nothing: it reads what the machine already has. For
each interface: address, gateway, and the DHCP lease it holds (server,
obtained, expires, the DNS and NTP servers in it); then the DNS and NTP
servers the machine uses (resolv.conf; chrony, timesyncd or ntpd; macOS
Date & Time; Windows Time). Some Linux DHCP clients keep the lease
readable by root only: `sudo dpt info` shows it.

To test a particular interface, `--select` (`/select` on Windows) lists
every Ethernet interface that is up, with an address or not, and lets
you choose: `dpt dhcp --select`, `dpt info --select`. In the shell,
`interface` does the same (`interface en0` directly, `interface auto`
to let dpt choose); trydhcp and info then use it. From a script
--select never asks: use `--iface`.

## Install

Linux and macOS, into `/usr/local/bin/dpt` (the latest release, checked
against its SHA256SUMS; sudo asks for your password):

```
curl -fsSL https://raw.githubusercontent.com/openipv8-org/dpt/main/scripts/install.sh | bash
```

Run it again to update. Windows: `dpt-windows-amd64.exe` (or `-arm64`)
from the release page.

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
