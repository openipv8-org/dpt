// SPDX-License-Identifier: MIT

//go:build linux

package dpt

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

func sockCloexec() int { return unix.SOCK_CLOEXEC }

// icmpRecvErr asks for the ICMP errors about what the socket sent: a
// Linux ping socket gets a router's "time exceeded" only on its error
// queue.
func icmpRecvErr(fd int, v6 bool) {
	if v6 {
		unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
	} else {
		unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	}
}

// icmpErrQueue reads one error from the queue: the router that sent it
// and what it said, when it is about our echo seq.
func icmpErrQueue(fd int, v6 bool, seq int) (string, int, bool) {
	buf := make([]byte, 1600)
	oob := make([]byte, 512)
	n, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil || n < 8 {
		return "", 0, false
	}
	// what the error is about: our echo request as sent
	if req := byte(8); v6 && buf[0] != 128 || !v6 && buf[0] != req || int(binary.BigEndian.Uint16(buf[6:])) != seq&0xffff {
		return "", 0, false
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return "", 0, false
	}
	for _, m := range msgs {
		v4err := m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_RECVERR
		v6err := m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_RECVERR
		if !v4err && !v6err || len(m.Data) < 16 {
			continue
		}
		// struct sock_extended_err: errno(4) origin(1) type(1) code(1)
		// pad(1) info(4) data(4), then the offender's sockaddr
		origin, typ := m.Data[4], m.Data[5]
		kind := 0
		switch {
		case origin == 2 && typ == 11, origin == 3 && typ == 3:
			kind = icmpExceeded
		case origin == 2 && typ == 3, origin == 3 && typ == 1:
			kind = icmpUnreach
		default:
			continue
		}
		sa := m.Data[16:]
		switch {
		case !v6 && len(sa) >= 8:
			return net.IP(sa[4:8]).String(), kind, true
		case v6 && len(sa) >= 24:
			return net.IP(sa[8:24]).String(), kind, true
		}
	}
	return "", 0, false
}
