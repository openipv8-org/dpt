// SPDX-License-Identifier: MIT

//go:build linux || darwin

package dpt

import (
	"errors"
	"net"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

type icmpSys struct {
	fd  int
	raw bool
	ttl int // set for a trace; 0: the system's
}

func (c *ICMPConn) open() error {
	family, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if c.v6 {
		family, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|sockCloexec(), proto)
	raw := false
	if err != nil {
		var rerr error
		fd, rerr = unix.Socket(family, unix.SOCK_RAW|sockCloexec(), proto)
		if rerr != nil {
			if runtime.GOOS == "linux" {
				return errors.New("cannot open ICMP socket: needs sudo, or set net.ipv4.ping_group_range")
			}
			return errors.New("cannot open ICMP socket: " + err.Error())
		}
		raw = true
	}
	if c.v6 {
		unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
	} else {
		unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTTL, 1)
	}
	c.sys = icmpSys{fd: fd, raw: raw}
	return nil
}

func (c *ICMPConn) close() error { return unix.Close(c.sys.fd) }

func (c *ICMPConn) sockaddr() unix.Sockaddr {
	if c.v6 {
		sa := &unix.SockaddrInet6{}
		copy(sa.Addr[:], c.ip.To16())
		return sa
	}
	sa := &unix.SockaddrInet4{}
	copy(sa.Addr[:], c.ip.To4())
	return sa
}

func (c *ICMPConn) echo(seq, ttl int, timeout time.Duration) (EchoReply, error) {
	req := icmpEchoRequest(c.v6, c.id, seq, c.payload)
	if ttl > 0 && ttl != c.sys.ttl {
		var err error
		if c.v6 {
			err = unix.SetsockoptInt(c.sys.fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		} else {
			err = unix.SetsockoptInt(c.sys.fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
		}
		if err != nil {
			return EchoReply{Seq: seq}, err
		}
		if c.sys.ttl == 0 && !c.sys.raw {
			icmpRecvErr(c.sys.fd, c.v6) // Linux: the routers' errors, on the error queue
		}
		c.sys.ttl = ttl
	}
	start := time.Now()
	if err := unix.Sendto(c.sys.fd, req, 0, c.sockaddr()); err != nil {
		return EchoReply{Seq: seq}, err
	}
	deadline := start.Add(timeout)
	buf := make([]byte, 1600)
	oob := make([]byte, 128)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return EchoReply{Seq: seq}, ErrEchoTimeout
		}
		// poll, not SO_RCVTIMEO: a timeout that rounds to zero there
		// waits for ever
		ms := int(left / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		pfd := []unix.PollFd{{Fd: int32(c.sys.fd), Events: unix.POLLIN}}
		if k, err := unix.Poll(pfd, ms); err != nil || k == 0 {
			continue
		}
		if pfd[0].Revents&unix.POLLERR != 0 {
			if from, kind, ok := icmpErrQueue(c.sys.fd, c.v6, seq); ok {
				return EchoReply{Seq: seq, From: from, RTT: time.Since(start), TTL: -1, Hop: kind == icmpExceeded, Unreachable: kind == icmpUnreach}, nil
			}
			if pfd[0].Revents&unix.POLLIN == 0 {
				continue
			}
		}
		n, oobn, _, from, err := unix.Recvmsg(c.sys.fd, buf, oob, unix.MSG_DONTWAIT)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return EchoReply{Seq: seq}, err
		}
		rtt := time.Since(start)
		b := buf[:n]
		ttl := -1
		// an IPv4 packet with its header (raw sockets, and macOS's
		// datagram sockets): the TTL is in it
		if !c.v6 && len(b) >= 20 && b[0]>>4 == 4 {
			hl := int(b[0]&0x0f) * 4
			if hl < 20 || hl > len(b) {
				continue
			}
			ttl = int(b[8])
			b = b[hl:]
		}
		if ttl > 0 {
			// a router's word about our echo (raw sockets, macOS)
			if kind := icmpTraceMatch(c.v6, b, seq); kind != icmpNotOurs {
				return EchoReply{Seq: seq, From: sockaddrIP(from), RTT: rtt, TTL: ttl, Size: len(b),
					Hop: kind == icmpExceeded, Unreachable: kind == icmpUnreach}, nil
			}
		}
		if !icmpMatchReply(c.v6, b, seq, c.payload) {
			continue
		}
		if !icmpFromTarget(from, c.ip) {
			continue
		}
		if ttl < 0 {
			ttl = icmpCmsgTTL(oob[:oobn], c.v6)
		}
		return EchoReply{Seq: seq, From: c.ip.String(), RTT: rtt, TTL: ttl, Size: len(b)}, nil
	}
}

func sockaddrIP(from unix.Sockaddr) string {
	switch a := from.(type) {
	case *unix.SockaddrInet4:
		return net.IP(a.Addr[:]).String()
	case *unix.SockaddrInet6:
		return net.IP(a.Addr[:]).String()
	}
	return ""
}

func icmpFromTarget(from unix.Sockaddr, ip net.IP) bool {
	switch a := from.(type) {
	case *unix.SockaddrInet4:
		return net.IP(a.Addr[:]).Equal(ip)
	case *unix.SockaddrInet6:
		return net.IP(a.Addr[:]).Equal(ip)
	}
	return true
}

// icmpCmsgTTL reads IP_TTL / IPV6_HOPLIMIT from the control messages.
func icmpCmsgTTL(oob []byte, v6 bool) int {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return -1
	}
	for _, m := range msgs {
		if len(m.Data) == 0 {
			continue
		}
		if !v6 && m.Header.Level == unix.IPPROTO_IP && (m.Header.Type == unix.IP_TTL || m.Header.Type == unix.IP_RECVTTL) {
			if len(m.Data) >= 4 && runtime.GOOS == "linux" {
				return int(nativeInt32(m.Data))
			}
			return int(m.Data[0]) // macOS: one octet
		}
		if v6 && m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_HOPLIMIT && len(m.Data) >= 4 {
			return int(nativeInt32(m.Data))
		}
	}
	return -1
}

func nativeInt32(b []byte) int32 {
	// little-endian on every platform dpt is built for (amd64, arm64)
	return int32(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
}
