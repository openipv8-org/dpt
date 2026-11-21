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
		// the NAT answers as the address at once, to the first socket
		// only, and loses the answers when several echoes are out
		p.mu.Lock()
		p.out++
		p.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		p.mu.Lock()
		crowded := p.out > 1
		p.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		p.mu.Lock()
		p.out--
		p.mu.Unlock()
		if e != p.first || crowded {
			return EchoReply{}, ErrEchoTimeout
		}
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
