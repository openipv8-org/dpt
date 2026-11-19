// SPDX-License-Identifier: MIT
package dpt

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------ SNTP query

// fakeNTP answers on loopback; reply shapes each answer from the request.
func fakeNTP(t *testing.T, reply func(req ntpPacket, now time.Time) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := parseNTP(buf[:n])
			if err != nil {
				continue
			}
			if b := reply(q, time.Now()); b != nil {
				pc.WriteTo(b, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// ntpServerAhead answers as a server whose clock is off by offset.
func ntpServerAhead(offset time.Duration, stratum uint8, li uint8) func(ntpPacket, time.Time) []byte {
	return func(q ntpPacket, now time.Time) []byte {
		t := now.Add(offset)
		r := ntpPacket{LI: li, VN: 4, Mode: ntpModeServer, Stratum: stratum, Precision: -20,
			RefID: [4]byte{'G', 'P', 'S', 0}, Ref: ntpStamp(t.Add(-time.Second)), Orig: q.Xmit,
			Recv: ntpStamp(t), Xmit: ntpStamp(t)}
		return r.marshal()
	}
}

func TestNTPQuery(t *testing.T) {
	ctx := context.Background()
	addr := fakeNTP(t, ntpServerAhead(300*time.Millisecond, 1, 0))
	r, err := NTPQuery(ctx, addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d := r.Offset - 300*time.Millisecond; d < -20*time.Millisecond || d > 20*time.Millisecond {
		t.Errorf("offset %v, want about 300ms", r.Offset)
	}
	if r.Stratum != 1 || r.RefID != ".GPS." || r.Unsynchronised() || r.Addr != "127.0.0.1" {
		t.Errorf("%+v", r)
	}

	// leap indicator 3 is an answer, flagged
	r, err = NTPQuery(ctx, fakeNTP(t, ntpServerAhead(0, 3, 3)), time.Second)
	if err != nil || !r.Unsynchronised() {
		t.Errorf("unsynchronised: %v %+v", err, r)
	}

	// Kiss-o'-Death
	kod := func(q ntpPacket, now time.Time) []byte {
		return ntpPacket{VN: 4, Mode: ntpModeServer, RefID: [4]byte{'D', 'E', 'N', 'Y'}, Orig: q.Xmit, Recv: 1, Xmit: 1}.marshal()
	}
	if _, err := NTPQuery(ctx, fakeNTP(t, kod), time.Second); err == nil || !strings.Contains(err.Error(), "DENY") {
		t.Errorf("kiss-o'-death: %v", err)
	}

	// a spoofed answer (wrong origin) first, then the real one
	spoof := func(q ntpPacket, now time.Time) []byte {
		bad := ntpServerAhead(time.Hour, 2, 0)(ntpPacket{Xmit: q.Xmit + 2}, now)
		good := ntpServerAhead(0, 2, 0)(q, now)
		return append(bad[:0:0], good...) // the fake sends one datagram: the good one
	}
	if r, err := NTPQuery(ctx, fakeNTP(t, spoof), time.Second); err != nil || r.Offset > time.Minute {
		t.Errorf("spoof: %v %+v", err, r)
	}

	// silence
	silent := fakeNTP(t, func(ntpPacket, time.Time) []byte { return nil })
	if _, err := NTPQuery(ctx, silent, 200*time.Millisecond); err == nil || err.Error() != "no answer" {
		t.Errorf("silence: %v", err)
	}
}

func TestCheckNTPReplySpoof(t *testing.T) {
	now := time.Now()
	b := ntpServerAhead(0, 2, 0)(ntpPacket{Xmit: 42}, now)
	if _, err := checkNTPReply(b, 43, now, now); err != errSpoof {
		t.Errorf("wrong origin: %v", err)
	}
	if _, err := checkNTPReply(b[:20], 42, now, now); err != errNTPShort {
		t.Errorf("short: %v", err)
	}
}

// ------------------------------------------------------------ DNS client

// fakeDNS answers A questions on loopback UDP and TCP.  Over UDP it says
// TC when truncate is set; over TCP it answers in full.
func fakeDNS(t *testing.T, flags uint16, rcode int, truncate bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", itoaT(port)))
	if err != nil {
		t.Skip("tcp port taken:", err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	answer := func(b []byte, tcp bool) []byte {
		q, err := parseDNS(b)
		if err != nil {
			return nil
		}
		m := &dnsMsg{ID: q.ID, Flags: dnsFlagQR | flags | q.Flags&dnsFlagRD, Question: q.Question}
		m.setRcode(rcode)
		if rcode == 0 {
			m.Answer = []DNSRecord{{Name: q.Question[0].Name, Type: DNSTypeA, Class: 1, TTL: 60, Data: []byte{192, 0, 2, 7}}}
		}
		if truncate && !tcp {
			m.Flags |= dnsFlagTC
			m.Answer = nil
		}
		m.Additional = []DNSRecord{dnsOPT(4096, 0)}
		out, _ := m.marshal()
		return out
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(answer(buf[:n], false), from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, err := dnsReadTCP(c)
				if err != nil {
					return
				}
				a := answer(b, true)
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
			}()
		}
	}()
	return pc.LocalAddr().String()
}

func itoaT(n int) string { return strconv.Itoa(n) }

func TestDNSAsk(t *testing.T) {
	ctx := context.Background()
	srv := fakeDNS(t, dnsFlagRA|dnsFlagAD, 0, false)
	a, err := DNSAsk(ctx, srv, "example.test", DNSAskOptions{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !a.RA || !a.AD || !a.RD || a.AA || !a.EDNS || a.EDNSSize != 4096 || a.Network != "udp" || a.RcodeName() != "NOERROR" {
		t.Errorf("%+v", a)
	}
	if len(a.Answer) != 1 || DNSFormatRData(a.Answer[0].Type, a.Answer[0].Data) != "192.0.2.7" {
		t.Errorf("answer %+v", a.Answer)
	}
	if a.Flags() != "qr rd ra ad" {
		t.Errorf("flags %q", a.Flags())
	}
	// no recursion asked: RD clear in the answer (the fake copies it)
	if a, err := DNSAsk(ctx, srv, "example.test", DNSAskOptions{NoRecurse: true}, time.Second); err != nil || a.RD {
		t.Errorf("norecurse: %v %+v", err, a)
	}
	// truncated over UDP: asked again over TCP
	tc := fakeDNS(t, dnsFlagRA, 0, true)
	if a, err := DNSAsk(ctx, tc, "example.test", DNSAskOptions{}, time.Second); err != nil || a.Network != "tcp" || !a.TruncatedRetry || len(a.Answer) != 1 {
		t.Errorf("truncated: %v %+v", err, a)
	}
	// always TCP (set vc)
	if a, err := DNSAsk(ctx, srv, "example.test", DNSAskOptions{TCP: true}, time.Second); err != nil || a.Network != "tcp" {
		t.Errorf("vc: %v %+v", err, a)
	}
	// REFUSED is an answer, not an error
	ref := fakeDNS(t, 0, dnsRefused, false)
	if a, err := DNSAsk(ctx, ref, "example.test", DNSAskOptions{}, time.Second); err != nil || a.RcodeName() != "REFUSED" {
		t.Errorf("refused: %v %+v", err, a)
	}
}

func TestDNSTypesAndRData(t *testing.T) {
	for _, n := range []string{"a", "AAAA", "mx", "caa", "dnskey", "ds", "TYPE65280"} {
		if _, ok := DNSTypeByName(n); !ok {
			t.Errorf("type %s", n)
		}
	}
	if _, ok := DNSTypeByName("nonsense"); ok {
		t.Error("nonsense type taken")
	}
	if c, ok := DNSClassByName("ch"); !ok || c != DNSClassCH || DNSClassString(c) != "CH" {
		t.Error("class CH")
	}
	mx, _ := dnsWireName("mx.example.test")
	soaM, _ := dnsWireName("ns.example.test")
	soaR, _ := dnsWireName("hostmaster.example.test")
	soa := append(append(append([]byte{}, soaM...), soaR...), make([]byte, 20)...)
	binary.BigEndian.PutUint32(soa[len(soa)-20:], 2026111901)
	for _, c := range []struct {
		t    uint16
		d    []byte
		want string
	}{
		{DNSTypeA, []byte{192, 0, 2, 1}, "192.0.2.1"},
		{DNSTypeMX, append([]byte{0, 10}, mx...), "10 mx.example.test."},
		{DNSTypeTXT, []byte("\x05hello\x03you"), `"hello" "you"`},
		{DNSTypeSOA, soa, "ns.example.test. hostmaster.example.test. 2026111901 0 0 0 0"},
		{DNSTypeCAA, []byte("\x00\x05issueletsencrypt.org"), `0 issue "letsencrypt.org"`},
		{DNSTypeDS, []byte{0x12, 0x34, 13, 2, 0xab, 0xcd}, "4660 13 2 ABCD"},
		{999, []byte{1, 2}, `\# 2 0102`},
		{DNSTypeA, []byte{1, 2, 3}, `\# 3 010203`},
	} {
		if got := DNSFormatRData(c.t, c.d); got != c.want {
			t.Errorf("type %d: %q, want %q", c.t, got, c.want)
		}
	}
	if DNSReverseName(net.ParseIP("192.0.2.10")) != "10.2.0.192.in-addr.arpa" {
		t.Error("v4 reverse")
	}
	if r := DNSReverseName(net.ParseIP("2001:db8::1")); !strings.HasPrefix(r, "1.0.0.0.") || !strings.HasSuffix(r, ".8.b.d.0.1.0.0.2.ip6.arpa") {
		t.Errorf("v6 reverse %s", r)
	}
}

// ------------------------------------------------------------ DHCP probe

func TestDHCPDiscoverAndOffer(t *testing.T) {
	mac := DHCPRandomMAC()
	if mac[0]&1 != 0 || mac[0]&2 == 0 {
		t.Errorf("random MAC %s is not unicast, locally administered", mac)
	}
	d, err := ParseDHCP(dhcpDiscover(0x1234, mac))
	if err != nil {
		t.Fatal(err)
	}
	if d.Type() != DHCPDiscover || d.Flags != 0x8000 || net.HardwareAddr(d.CHAddr[:6]).String() != mac.String() {
		t.Errorf("discover %+v", d)
	}
	if string(d.Get(55)) != string(DHCPProbeRequested) || binary.BigEndian.Uint16(d.Get(57)) != 1500 {
		t.Error("discover options 55/57")
	}
	if d.Get(dhcpOptRequested) != nil {
		t.Error("the probe asks for no address")
	}

	// an offer: NTP, TZ, search list (compressed), classless routes, an
	// unknown option, and the boot file in the BOOTP field
	o := &DHCPMessage{Op: 2, HType: 1, HLen: 6, XID: 0x1234, YIAddr: net.IPv4(10, 0, 0, 57).To4(), SIAddr: net.IPv4(10, 0, 0, 9).To4()}
	o.Set(dhcpOptType, []byte{DHCPOffer})
	o.Set(dhcpOptServerID, []byte{10, 0, 0, 1})
	o.Set(42, []byte{10, 0, 0, 5, 192, 0, 2, 123})
	o.Set(101, []byte("Europe/London"))
	o.Set(119, []byte("\x07example\x04test\x00\x03lab\xc0\x00"))
	o.Set(121, []byte{24, 192, 168, 7, 10, 0, 0, 1, 0, 10, 0, 0, 1})
	o.Set(224, []byte{0xde, 0xad})
	b := o.Marshal()
	copy(b[108:], "pxelinux.0")
	seen := dhcpOfferFor(b, 0x1234)
	if seen == nil {
		t.Fatal("offer not read")
	}
	if dhcpOfferFor(b, 0x9999) != nil {
		t.Error("another transaction's offer taken")
	}
	if seen.File != "pxelinux.0" {
		t.Errorf("file %q", seen.File)
	}
	s := dptDHCPServer(*seen)
	if strings.Join(s.NTP, " ") != "10.0.0.5 192.0.2.123" || s.TZName != `"Europe/London"` || s.ServerID != "10.0.0.1" || s.NextSrv != "10.0.0.9" {
		t.Errorf("%+v", s)
	}
	if s.Search != "example.test lab.example.test" {
		t.Errorf("search %q", s.Search)
	}
	if s.Routes != "192.168.7.0/24 via 10.0.0.1, 0.0.0.0/0 via 10.0.0.1" {
		t.Errorf("routes %q", s.Routes)
	}
	if s.Other["224"] != "dead" {
		t.Errorf("other %v", s.Other)
	}
	var buf bytes.Buffer
	RenderDPTDHCP(&buf, &DPTDHCPReport{Iface: "eth0", Servers: []DPTDHCPServer{s, s}, Multiple: true}, false)
	if !strings.Contains(buf.String(), "WARNING: multiple DHCP servers on eth0") || !strings.Contains(buf.String(), "TZ name (101)") {
		t.Errorf("render:\n%s", buf.String())
	}
}

// ------------------------------------------------------------ arguments

func TestParseDPTArgs(t *testing.T) {
	all := DPTTests{Time: true, DNS: true, Ping: true}
	for _, c := range []struct {
		st    DPTArgStyle
		args  string
		tests DPTTests
	}{
		{DPTStyleWindows, "10.10.10.10 /tdp /c:3 /w:1 /names:a.test,b.test /ntp:ntp.test /json", all},
		{DPTStyleWindows, "10.10.10.10 /t/p /c:3 /w:1 /names:a.test,b.test /ntp:ntp.test /json", DPTTests{Time: true, Ping: true}},
		{DPTStyleUnix, "10.10.10.10 -tdp -c 3 -w 1 --names a.test,b.test --ntp=ntp.test --json", all},
		{DPTStyleUnix, "10.10.10.10 --dp --count 3 --timeout=1 --names a.test,b.test --ntp ntp.test --json", DPTTests{DNS: true, Ping: true}},
		{DPTStyleUnix, "-p -c 3 -w 1000ms --names a.test,b.test --ntp ntp.test --json 10.10.10.10", DPTTests{Ping: true}},
	} {
		cmd, err := ParseDPTArgs(strings.Fields(c.args), c.st)
		if err != nil {
			t.Errorf("%q: %v", c.args, err)
			continue
		}
		o := cmd.Opts
		if cmd.Mode != "dpt" || cmd.Target != "10.10.10.10" || o.Count != 3 || o.Timeout != time.Second ||
			strings.Join(o.Names, ",") != "a.test,b.test" || strings.Join(o.NTP, ",") != "ntp.test" || !cmd.JSON || o.Tests != c.tests {
			t.Errorf("%q: %+v", c.args, cmd)
		}
	}
	// no test letters: all three run
	if c, err := ParseDPTArgs([]string{"google.com"}, DPTStyleUnix); err != nil || c.Opts.Tests.Any() || c.Opts.Tests.Effective() != all {
		t.Errorf("no letters: %v %+v", err, c)
	}
	for _, c := range []struct {
		st   DPTArgStyle
		args string
	}{
		{DPTStyleWindows, "dhcp /td /iface:eth1 /listen:5 /random-mac"},
		{DPTStyleUnix, "dhcp -td --iface eth1 --listen 5s --random-mac"},
		{DPTStyleUnix, "DHCP --td --iface=eth1 --listen=5 --random-mac"},
	} {
		cmd, err := ParseDPTArgs(strings.Fields(c.args), c.st)
		if err != nil || cmd.Mode != "dhcp" || cmd.Opts.Iface != "eth1" || cmd.Opts.Listen != 5*time.Second || !cmd.Opts.RandomMAC ||
			cmd.Opts.Tests != (DPTTests{Time: true, DNS: true}) {
			t.Errorf("%q: %v %+v", c.args, err, cmd)
		}
	}
	if c, _ := ParseDPTArgs(nil, DPTStyleUnix); c.Mode != "shell" {
		t.Error("no arguments is the shell")
	}
	if c, _ := ParseDPTArgs([]string{"/?"}, DPTStyleWindows); c.Mode != "help" {
		t.Error("/? is help")
	}
	for _, c := range []struct {
		st   DPTArgStyle
		args string
	}{
		{DPTStyleUnix, "-c"},
		{DPTStyleUnix, "-c 0 x"},
		{DPTStyleUnix, "--bogus x"},
		{DPTStyleUnix, "-tdx x"},
		{DPTStyleUnix, "-count 3 x"}, // a long option takes two dashes here
		{DPTStyleUnix, "a b"},
		{DPTStyleUnix, "dhcp 10.0.0.1"},
		{DPTStyleUnix, "dhcp -p"},
		{DPTStyleUnix, "--json=yes x"},
		{DPTStyleUnix, "--names bad..name x"},
		{DPTStyleUnix, "-w soon x"},
		{DPTStyleUnix, "-tdp"},
		{DPTStyleWindows, "/c 3 x"}, // Windows writes /c:3
		{DPTStyleWindows, "/tdp:1 x"},
	} {
		if _, err := ParseDPTArgs(strings.Fields(c.args), c.st); err == nil {
			t.Errorf("%q taken", c.args)
		}
	}
	for _, st := range []DPTArgStyle{DPTStyleWindows, DPTStyleUnix} {
		u := DPTUsage(st, "dpt")
		want := map[DPTArgStyle]string{DPTStyleWindows: "/c:<v>, /count:<v>", DPTStyleUnix: "-c <v>, --count <v>"}[st]
		if !strings.Contains(u, want) || !strings.Contains(u, "dhcp|<address>|<dnsname>") || !strings.Contains(u, "Authors: Jamie Thain and Claude Opus 5.5 (Anthropic)") {
			t.Errorf("usage %d lacks %q:\n%s", st, want, u)
		}
	}
}

// ------------------------------------------------------------ time compare

func TestDPTTimeRun(t *testing.T) {
	ctx := context.Background()
	ref := fakeNTP(t, ntpServerAhead(0, 1, 0))
	for _, c := range []struct {
		off    time.Duration
		li     uint8
		status string
	}{
		{10 * time.Millisecond, 0, DPTOK},
		{200 * time.Millisecond, 0, DPTWarn},
		{3 * time.Second, 0, DPTFail},
		{0, 3, DPTFail},
	} {
		target := fakeNTP(t, ntpServerAhead(c.off, 2, c.li))
		tm := DPTTimeRun(ctx, []DPTTimeAsk{{Server: target, Role: "target"}}, DPTOptions{NTP: []string{ref}, Timeout: time.Second})
		if tm.Status != c.status {
			t.Errorf("offset %v li %d: %s (%s), want %s", c.off, c.li, tm.Status, tm.Reason, c.status)
		}
		if tm.Reference != ref {
			t.Errorf("reference %q", tm.Reference)
		}
	}
	// a target with no NTP: reported, not a failure
	silent := fakeNTP(t, func(ntpPacket, time.Time) []byte { return nil })
	tm := DPTTimeRun(ctx, []DPTTimeAsk{{Server: silent, Role: "target"}}, DPTOptions{NTP: []string{ref}, Timeout: 200 * time.Millisecond})
	if tm.Status != DPTOK || !tm.Rows[1].NoService {
		t.Errorf("silent target: %+v", tm)
	}
	var buf bytes.Buffer
	RenderDPTTime(&buf, tm, false)
	if !strings.Contains(buf.String(), "no NTP service") {
		t.Errorf("render:\n%s", buf.String())
	}
}

// this machine's clock against the references: a drifting clock is the
// point, even when the servers agree with each other
func TestDPTTimeLocalClock(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		ahead  time.Duration // the servers ahead of us
		status string
		words  string
	}{
		{0, DPTOK, "ms behind the reference servers"},
		{200 * time.Millisecond, DPTWarn, "200."},
		{-200 * time.Millisecond, DPTWarn, "ms ahead of the reference servers"},
		{3 * time.Second, DPTFail, "behind"},
	} {
		a := fakeNTP(t, ntpServerAhead(c.ahead, 1, 0))
		b := fakeNTP(t, ntpServerAhead(c.ahead, 2, 0))
		tm := DPTTimeRun(ctx, nil, DPTOptions{NTP: []string{a, b}, Timeout: time.Second})
		if tm.DivStatus != DPTOK || tm.LocalStatus != c.status || tm.Status != c.status {
			t.Errorf("servers %v ahead: div %s local %s status %s (%s)", c.ahead, tm.DivStatus, tm.LocalStatus, tm.Status, tm.Reason)
		}
		var buf bytes.Buffer
		RenderDPTTime(&buf, tm, false)
		if !strings.Contains(buf.String(), "this clock is") || !strings.Contains(buf.String(), c.words) {
			t.Errorf("servers %v ahead, render lacks %q:\n%s", c.ahead, c.words, buf.String())
		}
	}
	// an unsynchronised reference does not count towards our clock
	a := fakeNTP(t, ntpServerAhead(0, 1, 0))
	b := fakeNTP(t, ntpServerAhead(5*time.Second, 16, 3))
	tm := DPTTimeRun(ctx, nil, DPTOptions{NTP: []string{a, b}, Timeout: time.Second})
	if tm.LocalStatus != DPTOK || tm.Status != DPTFail {
		t.Errorf("unsynchronised reference: local %s status %s", tm.LocalStatus, tm.Status)
	}
}

// ------------------------------------------------------------ the whole run

func TestRunDPTLoopback(t *testing.T) {
	// 127.0.0.1 has no DNS or NTP here (the fakes are on other ports):
	// ping only where an ICMP socket opens
	if c, err := OpenICMP(net.ParseIP("127.0.0.1")); err != nil {
		t.Skip("no ICMP socket:", err)
	} else {
		c.Close()
	}
	ref := fakeNTP(t, ntpServerAhead(0, 1, 0))
	r, err := RunDPT(context.Background(), "127.0.0.1", DPTOptions{Count: 2, Interval: 10 * time.Millisecond, Timeout: 300 * time.Millisecond, NTP: []string{ref}})
	if err != nil {
		t.Fatal(err)
	}
	a := r.Results[0]
	if a.Ping == nil || a.DNS == nil || a.Time == nil || a.Features == nil {
		t.Fatalf("all three tests and the features: %+v", a)
	}
	if a.Ping.Received != 2 || a.Ping.Status != DPTOK || !a.Features.ICMP {
		t.Errorf("ping %+v", a.Ping)
	}
	if a.DNS.Status == DPTFail || r.Failed() {
		t.Errorf("no service is not a failure: dns %+v time %+v", a.DNS, a.Time)
	}
	var buf bytes.Buffer
	RenderDPT(&buf, r, false, true)
	for _, w := range []string{"TARGET    127.0.0.1", "PING      2/2", "FEATURES  icmp", "seq 1"} {
		if !strings.Contains(buf.String(), w) {
			t.Errorf("render lacks %q:\n%s", w, buf.String())
		}
	}
	buf.Reset()
	if err := DPTJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || back["results"] == nil {
		t.Errorf("json: %v\n%s", err, buf.String())
	}
}

func TestPingSummary(t *testing.T) {
	s := PingSummary(4, []EchoReply{{RTT: 10 * time.Millisecond}, {RTT: 20 * time.Millisecond}, {RTT: 30 * time.Millisecond}})
	if s.Received != 3 || s.Loss != 25 || s.Min != 10*time.Millisecond || s.Max != 30*time.Millisecond || s.Avg != 20*time.Millisecond {
		t.Errorf("%+v", s)
	}
	if s := PingSummary(3, nil); s.Loss != 100 || s.Received != 0 {
		t.Errorf("%+v", s)
	}
}

func TestICMPEchoRequest(t *testing.T) {
	p := []byte("payload!")
	b := icmpEchoRequest(false, 7, 3, p)
	if b[0] != 8 || inetChecksum(b) != 0 {
		t.Errorf("v4 request % x", b)
	}
	reply := append([]byte{0, 0, 0, 0, 0, 9, 0, 3}, p...)
	if !icmpMatchReply(false, reply, 3, p) || icmpMatchReply(false, reply, 4, p) || icmpMatchReply(true, reply, 3, p) {
		t.Error("reply matching")
	}
}

// only the tests asked run, and the features need all three
func TestRunDPTSelected(t *testing.T) {
	ref := fakeNTP(t, ntpServerAhead(0, 1, 0))
	r, err := RunDPT(context.Background(), "127.0.0.1", DPTOptions{Tests: DPTTests{Time: true}, Timeout: 200 * time.Millisecond, NTP: []string{ref}})
	if err != nil {
		t.Fatal(err)
	}
	a := r.Results[0]
	if a.Ping != nil || a.DNS != nil || a.Features != nil || a.Time == nil {
		t.Errorf("t only: %+v", a)
	}
	var buf bytes.Buffer
	RenderDPT(&buf, r, false, false)
	if strings.Contains(buf.String(), "PING") || strings.Contains(buf.String(), "FEATURES") || !strings.Contains(buf.String(), "TIME") {
		t.Errorf("render:\n%s", buf.String())
	}
}

// the interface the probe picks has a real IPv4 address, and is the one
// with the gateway when there is one
func TestDPTDefaultIface(t *testing.T) {
	name, err := DPTDefaultIface()
	if err != nil {
		t.Skip("no interface here:", err)
	}
	i, err := net.InterfaceByName(name)
	if err != nil || !dptProbeable(*i) {
		t.Fatalf("%s is not probeable", name)
	}
	if gw := gatewayIfaces(); len(gw) > 0 {
		any := false
		ifs, _ := net.Interfaces()
		for _, c := range ifs {
			any = any || gw[c.Index] && dptProbeable(c)
		}
		if any && !gw[i.Index] {
			t.Errorf("%s chosen, not the gateway's interface %v", name, gw)
		}
	}
	t.Logf("chose %s", name)
}
