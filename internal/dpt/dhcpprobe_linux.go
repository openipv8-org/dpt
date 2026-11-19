// SPDX-License-Identifier: MIT

//go:build linux

package dpt

import (
	"context"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// Linux: the DISCOVER goes out and the offers come in on one packet
// socket (CAP_NET_RAW), as dhcpcd and nclient4 do: the interface may have
// no address, and UDP port 68 may belong to the system's DHCP client.
// The socket sees each offer's source MAC.

func dhcpProbe(ctx context.Context, ifi *net.Interface, xid uint32, discover []byte, listen time.Duration) ([]DHCPOfferSeen, error) {
	proto := htons(unix.ETH_P_IP)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			return nil, errDHCPProbePriv
		}
		return nil, err
	}
	defer unix.Close(fd)
	prog := unix.SockFprog{Len: uint16(len(dhcpBPF)), Filter: &dhcpBPF[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		return nil, err
	}
	pkt := dhcpIPv4UDP(discover)
	to := &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index, Halen: 6}
	copy(to.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	start := time.Now()
	if err := unix.Sendto(fd, pkt, 0, to); err != nil {
		return nil, err
	}
	deadline := start.Add(listen)
	var out []DHCPOfferSeen
	buf := make([]byte, 2048)
	for {
		if ctx.Err() != nil {
			return out, nil
		}
		left := time.Until(deadline)
		if left <= 0 {
			return out, nil
		}
		ms := int(left / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		if ms > 200 {
			ms = 200 // look at ctx now and then
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if k, err := unix.Poll(pfd, ms); err != nil || k == 0 {
			continue
		}
		n, from, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if err != nil {
			continue
		}
		src, body, ok := dhcpUDP(buf[:n])
		if !ok {
			continue
		}
		o := dhcpOfferFor(body, xid)
		if o == nil {
			continue
		}
		o.SrcIP, o.After = src.IP, time.Since(start)
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Halen == 6 {
			o.SrcMAC = append(net.HardwareAddr(nil), ll.Addr[:6]...)
		}
		out = append(out, *o)
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// dhcpBPF accepts IPv4 UDP to port 68, not fragmented (the data starts
// at the IP header: a SOCK_DGRAM packet socket).
var dhcpBPF = []unix.SockFilter{
	{Code: 0x30, K: 9},                    // ldb [9]: protocol
	{Code: 0x15, Jt: 0, Jf: 6, K: 17},     // jeq udp
	{Code: 0x28, K: 6},                    // ldh [6]: flags and fragment offset
	{Code: 0x45, Jt: 4, Jf: 0, K: 0x1fff}, // jset fragment offset: drop
	{Code: 0xb1, K: 0},                    // ldxb 4*([0]&0xf): header length
	{Code: 0x48, K: 2},                    // ldh [x+2]: destination port
	{Code: 0x15, Jt: 0, Jf: 1, K: 68},     // jeq 68
	{Code: 0x06, K: 0xffff},               // accept
	{Code: 0x06, K: 0},                    // drop
}
