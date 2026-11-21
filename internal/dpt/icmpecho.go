// SPDX-License-Identifier: MIT
package dpt

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"strconv"
	"sync"
	"time"
)

// ICMP echo from the program itself, not the system's ping program: a
// tool (dpt) needs each reply's round trip and TTL.  Linux and macOS use
// the unprivileged ICMP datagram socket (Linux: when the group is in
// net.ipv4.ping_group_range) and fall back to a raw socket as root;
// Windows uses IcmpSendEcho, which needs no Administrator.

// EchoReply is one echo's answer.
type EchoReply struct {
	Seq  int
	From string
	RTT  time.Duration
	TTL  int // -1: not known (Windows IPv6)
	Size int // ICMP octets received
	// Hop: From is a router on the way that said the echo's TTL ran
	// out (trace), not the address echoed.  Unreachable: From said the
	// address cannot be reached.
	Hop, Unreachable bool
	// Code is the unreachable's ICMP code (IPv4's numbering; IPv6's is
	// turned into it): 1 host, 3 port, 13 administratively prohibited...
	Code int
}

// UnreachWhy says what an unreachable's code means (IPv4 numbering).
func UnreachWhy(code int) string {
	switch code {
	case 0:
		return "network unreachable"
	case 1:
		return "host unreachable"
	case 2:
		return "protocol unreachable"
	case 3:
		return "port unreachable"
	case 4:
		return "fragmentation needed"
	case 9, 10, 13:
		return "administratively prohibited"
	}
	return "unreachable (code " + strconv.Itoa(code) + ")"
}

// unreachCode6 turns an ICMPv6 destination unreachable code into IPv4's.
func unreachCode6(c int) int {
	switch c {
	case 0:
		return 0 // no route
	case 1, 5, 6:
		return 13 // prohibited, failed policy, reject route
	case 3:
		return 1 // address unreachable
	case 4:
		return 3 // port
	}
	return 100 + c
}

// ErrEchoTimeout is an echo that got no answer in time.
var ErrEchoTimeout = errors.New("no reply")

// ICMPConn sends echoes to one address.
type ICMPConn struct {
	ip      net.IP
	v6      bool
	id      uint16
	payload []byte
	sys     icmpSys
}

// OpenICMP opens what echoes to ip need.  An error is the minimum
// execution level not being met: no ICMP socket for this user.
func OpenICMP(ip net.IP) (*ICMPConn, error) {
	c := &ICMPConn{ip: ip, v6: ip.To4() == nil, payload: make([]byte, 56)}
	if !c.v6 {
		c.ip = ip.To4()
	}
	var b [2]byte
	rand.Read(b[:])
	c.id = binary.BigEndian.Uint16(b[:])
	rand.Read(c.payload)
	copy(c.payload, "dpt-echo-probe-1")
	if err := c.open(); err != nil {
		return nil, err
	}
	return c, nil
}

// Close frees the socket or handle.
func (c *ICMPConn) Close() error { return c.close() }

// Echo sends one echo request with sequence seq and waits up to timeout
// for its reply.
func (c *ICMPConn) Echo(seq int, timeout time.Duration) (EchoReply, error) {
	return c.echo(seq, 0, timeout)
}

// EchoTTL sends an echo that may cross only ttl routers: the router
// where it runs out answers (Hop), or the address does.
func (c *ICMPConn) EchoTTL(seq, ttl int, timeout time.Duration) (EchoReply, error) {
	return c.echo(seq, ttl, timeout)
}

// EchoTTLs sends the probes, each with its TTL, and gives what each got,
// in the same order: all of them on one socket where the system allows,
// so that a NAT on the way sees one ping and not one per hop.
func (c *ICMPConn) EchoTTLs(probes []TraceProbe, timeout time.Duration) []TraceResult {
	return c.echoTTLs(probes, timeout)
}

// echoTTLsEach does the probes at once, each its own blocking echo (on
// Windows the system gives every echo the same id already).
func (c *ICMPConn) echoTTLsEach(probes []TraceProbe, timeout time.Duration) []TraceResult {
	res := make([]TraceResult, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.echo(p.Seq, p.TTL, timeout)
			res[i] = TraceResult{EchoReply: r, Err: err}
		}()
	}
	wg.Wait()
	return res
}

// ICMP error kinds a trace hears.
const (
	icmpNotOurs = iota
	icmpExceeded
	icmpUnreach
)

// icmpTraceMatch reads b (ICMP, any IP header removed): time exceeded or
// unreachable about our echo request seq.
func icmpTraceMatch(v6 bool, b []byte, seq int) int {
	kind, got := icmpTraceSeq(v6, b)
	if kind == icmpNotOurs || got != seq&0xffff {
		return icmpNotOurs
	}
	return kind
}

// icmpTraceSeq reads b (ICMP, any IP header removed): time exceeded or
// unreachable about an echo request, and that request's sequence number.
// The error carries the start of the packet it is about: its IP header,
// then the echo's 8 octets.
func icmpTraceSeq(v6 bool, b []byte) (int, int) {
	if len(b) < 8 {
		return icmpNotOurs, 0
	}
	kind := icmpNotOurs
	switch {
	case !v6 && b[0] == 11, v6 && b[0] == 3:
		kind = icmpExceeded
	case !v6 && b[0] == 3, v6 && b[0] == 1:
		kind = icmpUnreach
	default:
		return icmpNotOurs, 0
	}
	in := b[8:]
	req := byte(8)
	if v6 {
		if len(in) < 40+8 || in[0]>>4 != 6 || in[6] != 58 {
			return icmpNotOurs, 0
		}
		in, req = in[40:], 128
	} else {
		if len(in) < 20 || in[0]>>4 != 4 || in[9] != 1 {
			return icmpNotOurs, 0
		}
		hl := int(in[0]&0x0f) * 4
		if hl < 20 || len(in) < hl+8 {
			return icmpNotOurs, 0
		}
		in = in[hl:]
	}
	if in[0] != req {
		return icmpNotOurs, 0
	}
	return kind, int(binary.BigEndian.Uint16(in[6:]))
}

// icmpReplySeq: b (ICMP, any IP header removed) is an echo reply
// carrying our payload; its sequence number.
func icmpReplySeq(v6 bool, b []byte, payload []byte) (int, bool) {
	want := byte(0)
	if v6 {
		want = 129
	}
	if len(b) < 8+len(payload) || b[0] != want || b[1] != 0 || string(b[8:8+len(payload)]) != string(payload) {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(b[6:])), true
}

// TraceProbe is one echo of a trace: its sequence number and TTL.
type TraceProbe struct{ Seq, TTL int }

// TraceResult is what one probe got: Err is ErrEchoTimeout when nothing.
type TraceResult struct {
	EchoReply
	Err error
}

// icmpEchoRequest is an echo request: type 8 (IPv4) or 128 (IPv6).  The
// checksum is filled for IPv4; the kernel fills IPv6's.
func icmpEchoRequest(v6 bool, id uint16, seq int, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = 8
	if v6 {
		b[0] = 128
	}
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], uint16(seq))
	copy(b[8:], payload)
	if !v6 {
		binary.BigEndian.PutUint16(b[2:], inetChecksum(b))
	}
	return b
}

func inetChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// icmpMatchReply checks that b (ICMP, any IP header removed) is the echo
// reply to seq carrying our payload.  The id is not checked: a Linux
// datagram socket replaces it with its own.
func icmpMatchReply(v6 bool, b []byte, seq int, payload []byte) bool {
	want := byte(0)
	if v6 {
		want = 129
	}
	if len(b) < 8+len(payload) || b[0] != want || b[1] != 0 {
		return false
	}
	if int(binary.BigEndian.Uint16(b[6:])) != seq&0xffff {
		return false
	}
	return string(b[8:8+len(payload)]) == string(payload)
}

// PingStats sums up a run of echoes.
type PingStats struct {
	Sent, Received        int
	Loss                  float64 // percent
	Min, Avg, Max, StdDev time.Duration
}

// PingSummary works out a run's statistics from its replies.
func PingSummary(sent int, replies []EchoReply) PingStats {
	s := PingStats{Sent: sent, Received: len(replies)}
	if sent > 0 {
		s.Loss = 100 * float64(sent-len(replies)) / float64(sent)
	}
	if len(replies) == 0 {
		return s
	}
	var sum, sq float64
	s.Min = replies[0].RTT
	for _, r := range replies {
		if r.RTT < s.Min {
			s.Min = r.RTT
		}
		if r.RTT > s.Max {
			s.Max = r.RTT
		}
		sum += float64(r.RTT)
	}
	mean := sum / float64(len(replies))
	for _, r := range replies {
		d := float64(r.RTT) - mean
		sq += d * d
	}
	s.Avg = time.Duration(mean)
	s.StdDev = time.Duration(math.Sqrt(sq / float64(len(replies))))
	return s
}
