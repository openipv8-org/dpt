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

// icmpErrQueue reads one error from the queue: the sequence number of
// the echo it is about, the router that sent it, what it said and its
// code.
func icmpErrQueue(fd int, v6 bool) (int, string, int, int, bool) {
	buf := make([]byte, 1600)
	oob := make([]byte, 512)
	n, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil || n < 8 {
		return 0, "", 0, 0, false
	}
	// what the error is about: our echo request as sent
	if v6 && buf[0] != 128 || !v6 && buf[0] != 8 {
		return 0, "", 0, 0, false
	}
	seq := int(binary.BigEndian.Uint16(buf[6:]))
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, "", 0, 0, false
	}
	for _, m := range msgs {
		v4err := m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_RECVERR
		v6err := m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_RECVERR
		if !v4err && !v6err || len(m.Data) < 16 {
			continue
		}
		// struct sock_extended_err: errno(4) origin(1) type(1) code(1)
		// pad(1) info(4) data(4), then the offender's sockaddr
		origin, typ, code := m.Data[4], m.Data[5], int(m.Data[6])
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
			return seq, net.IP(sa[4:8]).String(), kind, code, true
		case v6 && len(sa) >= 24:
			return seq, net.IP(sa[8:24]).String(), kind, code, true
		}
	}
	return 0, "", 0, 0, false
}
