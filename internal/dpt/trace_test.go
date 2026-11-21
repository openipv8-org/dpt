// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePath is a network: hops[ttl-1] answers an echo with that TTL ("" is
// silent, "lossy" loses the first round); the target is at len(hops).
type fakePath struct {
	hops   []string
	target string
	mu     sync.Mutex
	seen   map[int]int
	shared bool // a VirtualBox NAT: only the first socket hears, and only when it is the one echo out
	first  *fakeEcho
	out    int
}

type fakeEcho struct{ p *fakePath }

func (p *fakePath) open(net.IP) (TraceEchoer, error) {
	e := &fakeEcho{p}
	if p.first == nil {
		p.first = e
	}
	return e, nil
}

func (e *fakeEcho) Close() error { return nil }

func (e *fakeEcho) EchoTTLs(probes []TraceProbe, timeout time.Duration) []TraceResult {
	res := make([]TraceResult, len(probes))
	for i, p := range probes {
		if e.p.shared && len(probes) > 1 {
			res[i] = TraceResult{Err: ErrEchoTimeout} // many at once: the NAT loses them
			continue
		}
		r, err := e.EchoTTL(p.Seq, p.TTL, timeout)
		res[i] = TraceResult{EchoReply: r, Err: err}
	}
	return res
}

func (e *fakeEcho) EchoTTL(seq, ttl int, timeout time.Duration) (EchoReply, error) {
	p := e.p
	p.mu.Lock()
	if p.seen == nil {
		p.seen = map[int]int{}
	}
	p.seen[ttl]++
	n := p.seen[ttl]
	p.mu.Unlock()
	if p.shared {
		// the NAT answers as the address at once
		return EchoReply{From: p.target, RTT: 20 * time.Millisecond}, nil
	}
	if ttl > len(p.hops) {
		return EchoReply{From: p.target, RTT: 30 * time.Millisecond}, nil
	}
	switch h := p.hops[ttl-1]; {
	case h == "":
		return EchoReply{}, ErrEchoTimeout
	case strings.HasPrefix(h, "lossy ") && n == 1:
		return EchoReply{}, ErrEchoTimeout
	case strings.HasPrefix(h, "refuse "):
		return EchoReply{From: strings.TrimPrefix(h, "refuse "), RTT: 5 * time.Millisecond, Unreachable: true, Code: 13}, nil
	default:
		return EchoReply{From: strings.TrimPrefix(h, "lossy "), RTT: time.Duration(ttl) * time.Millisecond, Hop: true}, nil
	}
}

func TestTrace(t *testing.T) {
	names := func(_ context.Context, ip string) string {
		if ip == "192.168.178.1" {
			return "fritz.box"
		}
		return ""
	}
	p := &fakePath{hops: []string{"192.168.178.1", "", "lossy 62.155.243.81"}, target: "203.0.113.9"}
	r, err := RunTrace(context.Background(), "203.0.113.9", TraceOptions{Open: p.open, Names: names, MaxHops: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Reached || len(r.Hops) != 4 || r.Status != DPTOK || r.Hops[0].Name != "fritz.box" || len(r.Hops[1].From) != 0 ||
		r.Hops[2].Lost != 1 || len(r.Hops[3].RTTs) != 3 || !r.Hops[3].Reached {
		t.Fatalf("%+v", r)
	}
	var b bytes.Buffer
	RenderTrace(&b, r, false)
	out := b.String()
	for _, w := range []string{"TRACE      1  192.168.178.1  fritz.box", " 2  *   no answer", "1/3 lost", " 4  203.0.113.9", "TRACE OK   4 hops"} {
		if !strings.Contains(out, w) {
			t.Errorf("lacks %q:\n%s", w, out)
		}
	}

	// Transact's carrier NAT (hop 4) refuses the echo with TTL 11; TTL 12
	// reaches 8.8.8.8: reached at 12, hop 11 marked as hop 4 refusing
	hops := []string{"192.168.178.254", "100.66.0.1", "209.240.35.67", "100.100.100.7", "209.240.45.206",
		"172.22.126.254", "209.240.45.218", "172.31.13.13", "142.250.63.91", "216.239.43.155", "refuse 100.100.100.7"}
	p = &fakePath{hops: hops, target: "8.8.8.8"}
	r, _ = RunTrace(context.Background(), "8.8.8.8", TraceOptions{Open: p.open, Names: names})
	if !r.Reached || len(r.Hops) != 12 || r.Hops[10].SameAs != 4 || r.Hops[10].Why != "administratively prohibited" || !r.Hops[11].Reached {
		t.Fatalf("carrier NAT: %d hops %+v", len(r.Hops), r.Hops[10])
	}
	b.Reset()
	RenderTrace(&b, r, false)
	if !strings.Contains(b.String(), "administratively prohibited: hop 4's router refused this echo") || !strings.Contains(b.String(), "12  8.8.8.8") {
		t.Errorf("%s", b.String())
	}

	// an unreachable with nothing after it ends the trace
	p = &fakePath{hops: append([]string{"192.168.178.1", "refuse 10.0.0.1"}, make([]string, 28)...), target: ""}
	r, _ = RunTrace(context.Background(), "203.0.113.9", TraceOptions{Open: p.open, Names: names})
	if r.Reached || len(r.Hops) != 2 || !r.Hops[1].Unreach || r.Status != DPTFail {
		t.Errorf("unreachable end: %+v", r)
	}

	// nothing beyond hop 2: one line, and not reached
	p = &fakePath{hops: []string{"192.168.178.1", "10.0.0.1"}, target: ""}
	p.hops = append(p.hops, make([]string, 28)...)
	r, _ = RunTrace(context.Background(), "203.0.113.9", TraceOptions{Open: p.open, Names: names})
	if r.Reached || len(r.Hops) != 3 || r.Status != DPTFail || !strings.Contains(r.Note, "from hop 3 to 30") {
		t.Errorf("not reached: %d hops %+v", len(r.Hops), r)
	}

	// VirtualBox's NAT: all at once hears nothing; one at a time on one
	// socket hears the address at hop 1
	p = &fakePath{target: "203.0.113.9", shared: true}
	r, _ = RunTrace(context.Background(), "203.0.113.9", TraceOptions{Open: p.open, Names: names, MaxHops: 5})
	if !r.OneAtATime || !r.Reached || len(r.Hops) != 1 || r.Status != DPTWarn || !strings.Contains(r.Note, "NAT") {
		t.Errorf("NAT: %+v", r)
	}
}

func TestICMPTraceMatch(t *testing.T) {
	// time exceeded (IPv4): its header, then the packet it is about: an
	// IP header and our echo request's first 8 octets
	inner := make([]byte, 20+8)
	inner[0], inner[9] = 0x45, 1
	inner[20] = 8
	binary.BigEndian.PutUint16(inner[26:], 42)
	te := append([]byte{11, 0, 0, 0, 0, 0, 0, 0}, inner...)
	if icmpTraceMatch(false, te, 42) != icmpExceeded || icmpTraceMatch(false, te, 43) != icmpNotOurs {
		t.Error("v4 exceeded")
	}
	un := append([]byte{3, 1, 0, 0, 0, 0, 0, 0}, inner...)
	if icmpTraceMatch(false, un, 42) != icmpUnreach {
		t.Error("v4 unreachable")
	}
	// someone else's echo, or not an echo: not ours
	inner[20] = 0
	te = append([]byte{11, 0, 0, 0, 0, 0, 0, 0}, inner...)
	if icmpTraceMatch(false, te, 42) != icmpNotOurs {
		t.Error("not an echo request")
	}
	// IPv6: 40-octet header, next header 58
	in6 := make([]byte, 40+8)
	in6[0], in6[6] = 0x60, 58
	in6[40] = 128
	binary.BigEndian.PutUint16(in6[46:], 7)
	te6 := append([]byte{3, 0, 0, 0, 0, 0, 0, 0}, in6...)
	if icmpTraceMatch(true, te6, 7) != icmpExceeded || icmpTraceMatch(true, te6[:20], 7) != icmpNotOurs {
		t.Error("v6 exceeded")
	}
}
