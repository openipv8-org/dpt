// SPDX-License-Identifier: MIT

package dpt

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParsePortList(t *testing.T) {
	l, err := ParsePortList("587,2525, 8000-8002,53/udp,587")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range l {
		got = append(got, p.key()+" "+p.Service)
	}
	want := "587/tcp submission,2525/tcp smtp-alt,8000/tcp http-alt,8001/tcp ,8002/tcp ,53/udp dns"
	if strings.Join(got, ",") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, ","), want)
	}
	for _, bad := range []string{"0", "70000", "10-5", "53/sctp", "x", ""} {
		if _, err := ParsePortList(bad); err == nil {
			t.Errorf("%q took", bad)
		}
	}
	if !IsPortList("587,2525") || IsPortList("mail.example.com") || IsPortList("10.0.0.1") {
		t.Error("IsPortList")
	}
	for _, p := range []string{"53/udp", "123/udp", "443/udp", "80/udp"} {
		found := false
		for _, x := range DPTDefaultPorts {
			found = found || x.key() == p
		}
		if !found {
			t.Errorf("%s not tried by default", p)
		}
	}
}

func TestQUICProbe(t *testing.T) {
	q := quicProbe()
	// long header, an unknown version, 1200 octets: a QUIC server must
	// answer with version negotiation
	if len(q) != 1200 || q[0]&0xc0 != 0xc0 || q[1]&0x0f != 0x0a || q[5] != 8 {
		t.Errorf("% x", q[:16])
	}
}

// a port with no request of its own is sent udpAnyProbe, never an empty
// datagram (Windows sends none): a server that answers only what has
// something in it must be found open
func TestProbeUDPAnyPort(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			if n > 0 {
				c.WriteTo([]byte("ok"), a)
			}
		}
	}()
	port := c.LocalAddr().(*net.UDPAddr).Port
	if udpProbes[port] != nil {
		t.Skip("the port drawn has a request of its own")
	}
	if st, _ := probeUDP(context.Background(), "127.0.0.1", port, time.Second); st != udpOpen {
		t.Errorf("port %d answering anything not empty: %v", port, st)
	}
	for p, req := range udpProbes {
		if len(req) == 0 {
			t.Errorf("port %d: empty request", p)
		}
	}
}

func TestRefused(t *testing.T) {
	for _, e := range []error{syscall.ECONNREFUSED, syscall.Errno(wsaeconnreset),
		&net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("wsarecv", syscall.Errno(wsaeconnreset))},
		&net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("read", syscall.ECONNREFUSED)}} {
		if !refused(e) {
			t.Errorf("%v: not taken for closed", e)
		}
	}
	if refused(os.ErrDeadlineExceeded) {
		t.Error("a timeout taken for closed")
	}
}

func TestProbeUDP(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			c.WriteTo(b[:n], a)
		}
	}()
	port := c.LocalAddr().(*net.UDPAddr).Port
	ctx := context.Background()
	if st, _ := probeUDP(ctx, "127.0.0.1", port, time.Second); st != udpOpen {
		t.Errorf("answering port: %v", st)
	}
	// a port no one has: the host says so (ICMP port unreachable)
	d, _ := net.ListenPacket("udp", "127.0.0.1:0")
	gone := d.LocalAddr().(*net.UDPAddr).Port
	d.Close()
	// loopback always says so, but macOS limits how many such answers it
	// sends a second, so there silence is allowed
	if st, _ := probeUDP(ctx, "127.0.0.1", gone, 500*time.Millisecond); st != udpClosed && !(runtime.GOOS == "darwin" && st == udpNoAnswer) {
		t.Errorf("closed port: %v", st)
	}
	o, _, _ := ScanPorts(ctx, "127.0.0.1", []DPTPortName{{port, "echo", "udp"}}, time.Second, make(chan struct{}, 2), nil)
	if len(o) != 1 || o[0].Proto != "udp" {
		t.Errorf("scan: %+v", o)
	}
}
