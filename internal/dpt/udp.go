// SPDX-License-Identifier: MIT

package dpt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// UDP ports.  A UDP port has no handshake: an open one answers only a
// request its service understands, so each common one is sent a real
// request, harmless and asking for nothing private.  It is open when
// something answers, closed when the host says no one is there (ICMP
// port unreachable), and no answer otherwise: open and silent, or
// dropped by a firewall, which UDP cannot tell apart.

// DPTUDPPorts are the UDP services tried, each with its request.
var DPTUDPPorts = []DPTPortName{
	{53, "dns", "udp"}, {69, "tftp", "udp"}, {80, "quic", "udp"}, {123, "ntp", "udp"},
	{137, "netbios-ns", "udp"}, {161, "snmp", "udp"}, {443, "quic", "udp"}, {1900, "ssdp", "udp"},
	{1812, "radius", "udp"}, {1813, "radius-acct", "udp"}, {5353, "mdns", "udp"},
}

// radiusStatusServer is a RADIUS Status-Server (RFC 5997): code 12, with
// the Message-Authenticator it must carry.  dpt knows no shared secret,
// so a server that checks it drops the request: an open port is "no
// answer" and only a closed one says so; a server that does answer is
// open.
func radiusStatusServer() []byte {
	b := []byte{12, 0x44, 0, 38}
	b = append(b, "dpt-radius-probe"...) // the Request Authenticator: 16 octets
	b = append(b, 80, 18)                // Message-Authenticator
	return append(b, make([]byte, 16)...)
}

// quicProbe is a QUIC Initial of a version no one speaks, padded to the
// 1200 octets QUIC asks for: a QUIC server must answer it with the
// versions it does speak (RFC 9000 6.1), and nothing more is said.
func quicProbe() []byte {
	b := make([]byte, 1200)
	copy(b, []byte{0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8, 'd', 'p', 't', 'p', 'r', 'o', 'b', 'e', 0})
	return b
}

// udpProbes are the requests: what an ordinary client of the service
// sends first.
var udpProbes = map[int][]byte{
	80:  quicProbe(),
	443: quicProbe(),
	// DNS: a query for the root's name servers
	53: {0x44, 0x50, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1},
	// TFTP: read a file no one has; a server answers with an error
	69: append(append([]byte{0, 1}, "dpt-probe\x00"...), "octet\x00"...),
	// NTP: a client request (version 4, mode 3)
	123: append([]byte{0x23}, make([]byte, 47)...),
	// NetBIOS: node status of "*", as "nbtstat -A" asks
	137: {0x44, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20,
		'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 0, 0, 0x21, 0, 1},
	// SNMP: version 3 engine discovery, which needs and guesses no
	// community or password (a v1/v2c-only agent may stay silent)
	161: {0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02, 0x02, 0x4a, 0x69, 0x02, 0x03, 0x00, 0xff, 0xe3,
		0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c,
		0x02, 0x02, 0x37, 0xf0, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00},
	// SSDP (UPnP): search for anything
	1900: []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"),
	// RADIUS: Status-Server, which authenticates no one
	1812: radiusStatusServer(),
	1813: radiusStatusServer(),
	// mDNS: the services it offers, asked by unicast
	5353: {0x44, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 7, '_', 'd', 'n', 's', '-', 's', 'd',
		4, '_', 'u', 'd', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0, 0, 12, 0x80, 1},
}

// udpState is what one UDP port did.
type udpState int

const (
	udpNoAnswer udpState = iota
	udpOpen
	udpClosed
)

// udpAnyProbe goes to a port with no request of its own: two empty lines.
// Not an empty datagram: Windows sends none (a zero-length write never
// leaves the machine), and some stacks and firewalls drop them; a line
// service (echo, daytime, chargen, quote) answers it, and a closed port
// is closed either way.
var udpAnyProbe = []byte("\r\n\r\n")

// probeUDP sends port's request (udpAnyProbe for a port with none),
// twice if the first gets nothing, and waits for an answer.
func probeUDP(ctx context.Context, ip string, port int, timeout time.Duration) (udpState, time.Duration) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return udpNoAnswer, 0
	}
	defer c.Close()
	udpReportUnreachable(c)
	req := udpProbes[port]
	if len(req) == 0 {
		req = udpAnyProbe
	}
	buf := make([]byte, 1500)
	wait := max(timeout/2, 200*time.Millisecond)
	for try := 0; try < 2 && ctx.Err() == nil; try++ {
		start := time.Now()
		if _, err := c.Write(req); err != nil {
			if refused(err) {
				return udpClosed, 0
			}
			return udpNoAnswer, 0
		}
		c.SetReadDeadline(time.Now().Add(wait))
		_, err := c.Read(buf)
		switch {
		case err == nil: // any datagram back, even an empty one
			return udpOpen, time.Since(start)
		case err != nil && refused(err):
			return udpClosed, 0
		}
	}
	return udpNoAnswer, 0
}

// refused: the host said the port is closed (ICMP port unreachable,
// reported on the connected socket: ECONNREFUSED on Linux and macOS,
// WSAECONNRESET, 10054, on Windows).
func refused(err error) bool {
	var e syscall.Errno
	if errors.As(err, &e) && (e == syscall.ECONNREFUSED || uintptr(e) == wsaeconnreset) {
		return true
	}
	return strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "forcibly closed")
}

// wsaeconnreset is Windows' WSAECONNRESET: on a UDP socket, the port
// unreachable that came back for what was sent.  No Linux or macOS
// errno is this large.
const wsaeconnreset = 10054

// ParsePortList reads "587,2525,8025", "8000-8010", "53/udp" and mixes
// of them; a port is TCP unless it says /udp.  Known ports get their
// service's name.
func ParsePortList(s string) ([]DPTPortName, error) {
	names := map[string]string{}
	for _, p := range DPTTopPorts {
		names[p.key()] = p.Service
	}
	for _, p := range DPTUDPPorts {
		names[p.key()] = p.Service
	}
	var out []DPTPortName
	seen := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		proto := "tcp"
		if r, p, ok := strings.Cut(item, "/"); ok {
			if p != "tcp" && p != "udp" {
				return nil, fmt.Errorf("port %q: /tcp or /udp", item)
			}
			item, proto = r, p
		}
		lo, hi, isRange := strings.Cut(item, "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || b < a {
			return nil, fmt.Errorf("port %q: a number from 1 to 65535, or a range like 8000-8010", item)
		}
		for n := a; n <= b; n++ {
			p := DPTPortName{Port: n, Proto: proto}
			if seen[p.key()] {
				continue
			}
			seen[p.key()] = true
			p.Service = names[p.key()]
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no ports in the list")
	}
	return out, nil
}

// IsPortList: s is a port list, not a host's name.
func IsPortList(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' || net.ParseIP(s) != nil {
		return false
	}
	_, err := ParsePortList(s)
	return err == nil
}

func (p DPTPortName) key() string { return strconv.Itoa(p.Port) + "/" + p.Proto }
