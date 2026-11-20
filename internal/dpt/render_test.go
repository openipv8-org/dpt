// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func sampleReport() *DPTReport {
	return &DPTReport{
		Target: DPTTarget{Input: "8.8.8.8", Addresses: []string{"8.8.8.8"}, Tested: []string{"8.8.8.8"}},
		Results: []DPTAddrReport{{
			Address: "8.8.8.8",
			Ping:    &DPTPing{Sent: 5, Received: 5, Min: 32.5, Avg: 33.2, Max: 34, StdDev: 0.6, Status: DPTOK},
			DNS:     &DPTDNS{Server: "8.8.8.8", Rows: make([]DPTDNSRow, 5), Answered: 5, Avg: 35.6, Recursion: true, Status: DPTOK},
			Time: &DPTTime{Rows: []DPTTimeRow{
				{Server: "time.google.com", Role: "reference", OK: true, Offset: -3.9, Delay: 60.4, Stratum: 1, RefID: ".GOOG."},
				{Server: "8.8.8.8", Role: "target", NoService: true, Error: "no answer"},
			}, Reference: "time.google.com", MaxDivergence: 2.3, DivStatus: DPTOK, LocalOffset: 5, LocalStatus: DPTOK, Status: DPTWarn},
		}},
	}
}

// the summary: a rule, then the tests on one line
func TestRenderDPTSummary(t *testing.T) {
	var b bytes.Buffer
	RenderDPT(&b, sampleReport(), false, false)
	out := b.String()
	if !strings.Contains(out, "\n"+DPTRule+"\nPING OK   DNS OK   TIME WARN\n") {
		t.Errorf("summary:\n%s", out)
	}
	// the DNS test asks the target: it is never "answered by" anyone else
	if strings.Contains(out, "answered by") {
		t.Errorf("answered by:\n%s", out)
	}
	// a blank line between sections
	if !strings.Contains(out, "TARGET    8.8.8.8\n\nPING ") || !strings.Contains(out, "\n\nDNS ") || !strings.Contains(out, "\n\nTIME ") {
		t.Errorf("sections:\n%s", out)
	}
}

// PING and DNS share columns; TIME's numbers and messages line up
func TestRenderDPTAligned(t *testing.T) {
	var b bytes.Buffer
	RenderDPT(&b, sampleReport(), false, false)
	lines := strings.Split(b.String(), "\n")
	find := func(prefix string) string {
		for _, l := range lines {
			if strings.HasPrefix(l, prefix) {
				return l
			}
		}
		t.Fatalf("no %q line:\n%s", prefix, b.String())
		return ""
	}
	if p, d := find("PING "), find("DNS "); strings.Index(p, "rtt") != strings.Index(d, "avg") {
		t.Errorf("rtt/avg columns:\n%s\n%s", p, d)
	}
	g, n := find("TIME "), find("          8.8.8.8 ")
	if strings.Index(g, "-3.9") != strings.Index(n, "no NTP service") {
		t.Errorf("number/message columns:\n%s\n%s", g, n)
	}
	div, clk := find("          max divergence"), find("          this clock")
	if strings.Index(div, ".3 ms") != strings.Index(clk, ".0 ms") || strings.Index(g, ".9 ms") != strings.Index(div, ".3 ms") {
		t.Errorf("decimal points:\n%s\n%s\n%s", g, div, clk)
	}
}

func TestRenderDPTColour(t *testing.T) {
	var b bytes.Buffer
	r := sampleReport()
	r.Results[0].Ping.Status = DPTFail
	RenderDPT(&b, r, true, false)
	for _, w := range []string{"\x1b[1;36mPING      \x1b[0m", "\x1b[1;31mFAIL\x1b[0m", "\x1b[1;32mOK\x1b[0m", "\x1b[1;33mWARN\x1b[0m", "\x1b[33mno NTP service\x1b[0m"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("lacks %q:\n%q", w, b.String())
		}
	}
}

func TestRenderDPTDHCPSummary(t *testing.T) {
	var b bytes.Buffer
	RenderDPTDHCP(&b, &DPTDHCPReport{Iface: "eth0", Status: DPTWarn, DNSState: DPTFail,
		DNS:  []DPTDHCPCheck{{Server: "192.0.2.53", Error: "no answer"}},
		Time: &DPTTime{Status: DPTOK}}, false)
	if !strings.HasSuffix(b.String(), DPTRule+"\nDHCP WARN   DNS FAIL   TIME OK\n") {
		t.Errorf("summary:\n%s", b.String())
	}
}

// the sections come as each is done, in their order, after the target
func TestRunDPTStreams(t *testing.T) {
	if c, err := OpenICMP(net.ParseIP("127.0.0.1")); err != nil {
		t.Skip("no ICMP socket:", err)
	} else {
		c.Close()
	}
	ref := fakeNTP(t, ntpServerAhead(0, 1, 0))
	var got []string
	o := DPTOptions{Count: 2, Interval: 10 * time.Millisecond, Timeout: 300 * time.Millisecond, NTP: []string{ref}}
	o.OnTarget = func(DPTTarget) { got = append(got, "TARGET") }
	o.OnSection = func(a *DPTAddrReport, s string) {
		got = append(got, s)
		if s == "PING" && a.Ping == nil || s == "TIME" && a.Time == nil {
			t.Errorf("%s before its result", s)
		}
	}
	var live bytes.Buffer
	o.Live = NewLive(&live, 80)
	if _, err := RunDPT(context.Background(), "127.0.0.1", o); err != nil {
		t.Fatal(err)
	}
	o.Live.Stop()
	if w := "TARGET ADDRESS PING DNS TIME FEATURES"; strings.Join(got, " ") != w {
		t.Errorf("sections %v, want %s", got, w)
	}
	if !strings.Contains(live.String(), "ping 2/2") || !strings.Contains(live.String(), "time ") {
		t.Errorf("status line %q", live.String())
	}
}

func TestLive(t *testing.T) {
	var nl *Live // off: no-ops, Out still prints
	nl.Set("a", "x")
	ran := false
	nl.Out(func() { ran = true })
	nl.Stop()
	if !ran {
		t.Error("nil Live: Out did not print")
	}

	var b bytes.Buffer
	l := NewLive(&b, 40)
	l.Set("ping", "ping 1/5")
	l.Set("dns", "dns 2/5")
	l.Set("ping", "ping 2/5")
	if !strings.HasSuffix(b.String(), "\r| ping 2/5   dns 2/5") {
		t.Errorf("line %q", b.String())
	}
	l.Out(func() { b.WriteString("RESULT\n") })
	if !strings.Contains(b.String(), "\r"+strings.Repeat(" ", 20)+"\rRESULT\n") {
		t.Errorf("not cleared before the result: %q", b.String())
	}
	l.Set("x", strings.Repeat("y", 50)) // never wider than the terminal
	l.Stop()
	l.Stop()
	s := b.String()
	if !strings.HasSuffix(s, "\r") {
		t.Errorf("not cleared at the end: %q", s)
	}
	for _, seg := range strings.Split(s, "\r") {
		if len(seg) > 39 && !strings.Contains(seg, "RESULT") {
			t.Errorf("wider than 39: %q", seg)
		}
	}
}
