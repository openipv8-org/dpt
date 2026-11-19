// SPDX-License-Identifier: MIT

//go:build linux

package dpt

import (
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The macOS probe's frame and filter, run on Linux's packet socket in its
// whole-frame form (SOCK_RAW): the same frame goes out, the same program
// picks the offers, the same code reads them.  Needs root and a DHCP
// server on the default interface.
func TestDHCPEtherOnTheWire(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	name, err := DPTDefaultIface()
	if err != nil {
		t.Skip(err)
	}
	ifi, _ := net.InterfaceByName(name)
	proto := htons(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var f []unix.SockFilter
	for _, i := range dhcpEtherFilter {
		f = append(f, unix.SockFilter{Code: uint16(i[0]), Jt: uint8(i[1]), Jf: uint8(i[2]), K: i[3]})
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		t.Fatal(err)
	}
	xid := uint32(0x5eed1234)
	disc := dhcpDiscover(xid, ifi.HardwareAddr)
	frame := dhcpEtherFrame(ifi.HardwareAddr, dhcpIPv4UDP(disc))
	to := &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index, Halen: 6}
	copy(to.Addr[:], frame[0:6])
	if err := unix.Sendto(fd, frame, 0, to); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if k, _ := unix.Poll(pfd, 200); k == 0 {
			continue
		}
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if err != nil {
			continue
		}
		mac, ip, ok := dhcpEtherOffer(buf[:n])
		if !ok {
			t.Errorf("the filter passed a frame that is not IPv4: % x", buf[:min(n, 20)])
			continue
		}
		_, body, ok := dhcpUDP(ip)
		if !ok {
			t.Errorf("the filter passed a packet that is not UDP to 68")
			continue
		}
		if o := dhcpOfferFor(body, xid); o != nil {
			t.Logf("offer %v from %s", o.Msg.YIAddr, mac)
			return
		}
	}
	t.Fatal("no offer through the frame filter")
}
