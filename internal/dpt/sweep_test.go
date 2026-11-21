// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTopPorts(t *testing.T) {
	if len(DPTTopPorts) != 65 {
		t.Errorf("%d ports", len(DPTTopPorts))
	}
	seen := map[int]bool{}
	for _, p := range DPTTopPorts {
		if seen[p.Port] {
			t.Errorf("%d twice", p.Port)
		}
		seen[p.Port] = true
	}
	for _, p := range []int{21, 22, 23, 25, 53, 80, 81, 443, 2525, 8025, 1443, 14443, 3389} {
		if !seen[p] {
			t.Errorf("%d missing", p)
		}
	}
}

func TestParseSweepNetwork(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.0/24": "192.168.1.0/24",
		"10.1.2.3":       "10.1.2.0/24", // an address: its /24
		"10.0.0.0/22":    "10.0.0.0/22",
	} {
		n, err := ParseSweepNetwork(in)
		if err != nil || n.String() != want {
			t.Errorf("%s: %v %v", in, n, err)
		}
	}
	for _, in := range []string{"10.0.0.0/16", "fe80::/64", "nonsense"} {
		if _, err := ParseSweepNetwork(in); err == nil {
			t.Errorf("%s taken", in)
		}
	}
	n, _ := ParseSweepNetwork("10.0.0.0/24")
	a := sweepAddrs(n)
	if len(a) != 254 || u2ip4(a[0]).String() != "10.0.0.1" || u2ip4(a[253]).String() != "10.0.0.254" {
		t.Errorf("%d addresses", len(a))
	}
}

// 25 at a time, in address order, the live ones only
func TestSweep(t *testing.T) {
	n, _ := ParseSweepNetwork("10.9.8.0/24")
	var mu sync.Mutex
	inFlight, most := 0, 0
	live := map[string]bool{"10.9.8.1": true, "10.9.8.30": true, "10.9.8.200": true}
	var order []string
	r, err := RunSweep(context.Background(), SweepOptions{
		Network: n,
		Timeout: 10 * time.Millisecond,
		Ping: func(ip net.IP, timeout time.Duration) (EchoReply, error) {
			mu.Lock()
			inFlight++
			most = max(most, inFlight)
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			if live[ip.String()] {
				return EchoReply{RTT: 1500 * time.Microsecond, TTL: 64}, nil
			}
			return EchoReply{}, ErrEchoTimeout
		},
		Names:  func(context.Context, string) string { return "" },
		OnHost: func(h *SweepHost) { order = append(order, h.Address) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if most > 25 {
		t.Errorf("%d pings at once", most)
	}
	if strings.Join(order, " ") != "10.9.8.1 10.9.8.30 10.9.8.200" || len(r.Hosts) != 3 || r.Tried != 254 {
		t.Errorf("%v %+v", order, r)
	}
	var b bytes.Buffer
	RenderSweep(&b, r, false)
	if !strings.Contains(b.String(), "LIVE      10.9.8.1            1.5 ms  ttl 64") || !strings.Contains(b.String(), "3 of 254 addresses answered a ping") {
		t.Errorf("%s", b.String())
	}
}

func TestScanPorts(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	open := l.Addr().(*net.TCPAddr).Port
	ports := []DPTPortName{{open, "test", "tcp"}, {closedPort(t), "closed", "tcp"}}
	o, closed, filtered := ScanPorts(context.Background(), "127.0.0.1", ports, time.Second, make(chan struct{}, 4), nil)
	if len(o) != 1 || o[0].Port != open || closed != 1 || filtered != 0 {
		t.Errorf("%v %d %d", o, closed, filtered)
	}
	var b bytes.Buffer
	RenderPorts(&b, &PortsReport{Target: DPTTarget{Input: "h", Tested: []string{"127.0.0.1"}}, Open: o, Closed: 1, Tried: 2}, false)
	if !strings.Contains(b.String(), fmt.Sprintf("OPEN      %-9s test", fmt.Sprint(open)+"/tcp")) || !strings.Contains(b.String(), "1 of 2 ports open, 1 closed, 0 no answer") {
		t.Errorf("%s", b.String())
	}
}

func TestOutsideIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "203.0.113.7")
	}))
	defer srv.Close()
	old := OutsideIPURL
	OutsideIPURL = srv.URL
	defer func() { OutsideIPURL = old }()
	r, err := RunOutsideIP(context.Background(), 0, 2*time.Second)
	if err != nil || r.Address != "203.0.113.7" {
		t.Fatalf("%+v %v", r, err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>") }))
	defer bad.Close()
	OutsideIPURL = bad.URL
	if _, err := RunOutsideIP(context.Background(), 0, 2*time.Second); err == nil {
		t.Error("html taken as an address")
	}
}

func TestParseNetArgs(t *testing.T) {
	for _, c := range []struct {
		args               string
		mode, target, user string
		pass               string
		ports              bool
		network            string
	}{
		{"smtp mail.test", "smtp", "mail.test", "", "", false, ""},
		{"smtp mail.test test u", "smtp", "mail.test", "u", "", false, ""},
		{"smtp mail.test test u secret -w 5", "smtp", "mail.test", "u", "secret", false, ""},
		{"sweep", "sweep", "", "", "", false, ""},
		{"sweep ports", "sweep", "", "", "", true, ""},
		{"sweep 10.0.0.0/24 ports", "sweep", "", "", "", true, "10.0.0.0/24"},
		{"ports 10.0.0.1", "ports", "10.0.0.1", "", "", false, ""},
		{"outside-ip", "outside-ip", "", "", "", false, ""},
	} {
		cmd, err := ParseDPTArgs(strings.Fields(c.args), DPTStyleUnix)
		if err != nil || cmd.Mode != c.mode || cmd.Target != c.target || cmd.SMTPUser != c.user || cmd.SMTPPassword != c.pass ||
			cmd.SweepPorts != c.ports || cmd.SweepNetwork != c.network {
			t.Errorf("%q: %v %+v", c.args, err, cmd)
		}
	}
	// smtp alone: asked for at the terminal
	if c, err := ParseDPTArgs([]string{"smtp"}, DPTStyleUnix); err != nil || c.Mode != "smtp" || c.Target != "" {
		t.Errorf("smtp alone: %v %+v", err, c)
	}
	for _, a := range []string{"smtp h test", "smtp h login u", "smtp h test u p x", "sweep 10.0.0.0/8",
		"sweep a b", "ports", "ports a b", "outside-ip x", "smtp h -t", "ports h --iface en0", "sweep 10.0.0.1 --iface en0"} {
		if _, err := ParseDPTArgs(strings.Fields(a), DPTStyleUnix); err == nil {
			t.Errorf("%q taken", a)
		}
	}
}

func TestSweepHostPortsRight(t *testing.T) {
	var b bytes.Buffer
	p := NewSweepPrinter(&b, false)
	p.Network(&SweepReport{Network: "192.168.178.0/24", Tried: 254, Ports: true})
	p.Host(&SweepHost{Address: "192.168.178.194", RTT: 5.2, TTL: 64, Scanned: true, Open: []DPTOpenPort{{Port: 22, Service: "ssh", Proto: "tcp"}}})
	p.Host(&SweepHost{Address: "192.168.178.196", RTT: 5.8, TTL: 60, Scanned: true, Name: "nas.lan", Open: []DPTOpenPort{
		{Port: 23, Service: "telnet", Proto: "tcp"}, {Port: 53, Service: "dns", Proto: "udp"}, {Port: 80, Service: "http", Proto: "tcp"},
		{Port: 443, Service: "https", Proto: "tcp"}, {Port: 445, Service: "smb", Proto: "tcp"}, {Port: 5353, Service: "mdns", Proto: "udp"},
		{Port: 8080, Service: "http-proxy", Proto: "tcp"}, {Port: 9100, Service: "jetdirect", Proto: "tcp"}}})
	out := b.String()
	if !strings.Contains(out, "LIVE      192.168.178.194     5.2 ms  ttl 64    22 ssh\n") {
		t.Errorf("one port on the address's line:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) > 80 {
			t.Errorf("over 80: %q", l)
		}
	}
	if !strings.Contains(out, "23 telnet  53/udp dns") || !strings.Contains(out, "   nas.lan\n") {
		t.Errorf("ports, wrapped, then the name:\n%s", out)
	}
	for _, c := range []struct {
		p    DPTOpenPort
		kind string
	}{{DPTOpenPort{Port: 23}, "risky"}, {DPTOpenPort{Port: 3389}, "remote"}, {DPTOpenPort{Port: 587}, "mail"},
		{DPTOpenPort{Port: 53, Proto: "udp"}, "names"}, {DPTOpenPort{Port: 2443, Service: "https-alt"}, "web"},
		{DPTOpenPort{Port: 443, Service: "quic", Proto: "udp"}, "web"}, {DPTOpenPort{Port: 3306, Service: "mysql"}, ""}} {
		if k := PortKind(c.p); k != c.kind {
			t.Errorf("%d: %q, want %q", c.p.Port, k, c.kind)
		}
	}
}
