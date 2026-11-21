// SPDX-License-Identifier: MIT

//go:build windows

package dpt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows: IcmpSendEcho / Icmp6SendEcho2 from iphlpapi.dll, which need no
// Administrator.  The round trip is timed here (the API's own is whole
// milliseconds).  IPv6 replies carry no hop limit through this API.

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile = iphlpapi.NewProc("IcmpCreateFile")
	procIcmp6Create    = iphlpapi.NewProc("Icmp6CreateFile")
	procIcmpClose      = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho   = iphlpapi.NewProc("IcmpSendEcho")
	procIcmp6SendEcho2 = iphlpapi.NewProc("Icmp6SendEcho2")
)

const (
	ipSuccess       = 0
	ipDestNetUnr    = 11002
	ipDestHostUnr   = 11003
	ipDestProtUnr   = 11004
	ipDestPortUnr   = 11005
	ipReqTimedOut   = 11010
	ipTTLExpTransit = 11013
	ipTTLExpReasm   = 11014
	icmpReplyExtra  = 64
)

// icmpStatusKind: what a status from a router (not the address) says.
func icmpStatusKind(st uint32) int {
	switch st {
	case ipTTLExpTransit, ipTTLExpReasm:
		return icmpExceeded
	case ipDestNetUnr, ipDestHostUnr, ipDestProtUnr, ipDestPortUnr:
		return icmpUnreach
	}
	return icmpNotOurs
}

type icmpSys struct{ h uintptr }

func (c *ICMPConn) open() error {
	if err := iphlpapi.Load(); err != nil {
		return errors.New("cannot open ICMP: iphlpapi.dll: " + err.Error())
	}
	p := procIcmpCreateFile
	if c.v6 {
		p = procIcmp6Create
	}
	h, _, err := p.Call()
	if h == uintptr(windows.InvalidHandle) || h == 0 {
		return errors.New("cannot open ICMP handle: " + err.Error())
	}
	c.sys.h = h
	return nil
}

func (c *ICMPConn) close() error {
	procIcmpClose.Call(c.sys.h)
	return nil
}

// ipOptionInformation is IP_OPTION_INFORMATION.
type ipOptionInformation struct {
	TTL, TOS, Flags, OptionsSize uint8
	OptionsData                  uintptr
}

// icmpEchoReply is ICMP_ECHO_REPLY (the native one, 32 or 64 bit).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// sockaddrIn6 is struct sockaddr_in6.
type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

func (c *ICMPConn) echo(seq, ttl int, timeout time.Duration) (EchoReply, error) {
	// the API makes its own echo header; seq is ours only
	data := append([]byte(nil), c.payload...)
	binary.BigEndian.PutUint16(data[len(data)-2:], uint16(seq))
	ms := uintptr(timeout / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(data)+8+icmpReplyExtra)
	opts := ipOptionInformation{TTL: 128}
	if ttl > 0 {
		opts.TTL = uint8(min(ttl, 255))
	}
	start := time.Now()
	var n uintptr
	var callErr error
	if c.v6 {
		src := sockaddrIn6{Family: windows.AF_INET6}
		dst := sockaddrIn6{Family: windows.AF_INET6}
		copy(dst.Addr[:], c.ip.To16())
		n, _, callErr = procIcmp6SendEcho2.Call(c.sys.h, 0, 0, 0,
			uintptr(unsafe.Pointer(&src)), uintptr(unsafe.Pointer(&dst)),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), ms)
	} else {
		ip := c.ip.To4()
		addr := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
		n, _, callErr = procIcmpSendEcho.Call(c.sys.h, uintptr(addr),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), ms)
	}
	rtt := time.Since(start)
	if n == 0 {
		if en, ok := callErr.(windows.Errno); ok && en == ipReqTimedOut {
			return EchoReply{Seq: seq}, ErrEchoTimeout
		}
		if rtt >= timeout {
			return EchoReply{Seq: seq}, ErrEchoTimeout
		}
		return EchoReply{Seq: seq}, fmt.Errorf("echo failed: %v", callErr)
	}
	if c.v6 {
		// ICMPV6_ECHO_REPLY: a packed 26-octet IPV6_ADDRESS_EX, then
		// Status at 28
		if st := binary.LittleEndian.Uint32(reply[28:]); st != ipSuccess {
			if k := icmpStatusKind(st); k != icmpNotOurs && ttl > 0 {
				// IPV6_ADDRESS_EX: port(2) flowinfo(4) address(16)
				return EchoReply{Seq: seq, From: net.IP(append([]byte(nil), reply[6:22]...)).String(), RTT: rtt, TTL: -1,
					Hop: k == icmpExceeded, Unreachable: k == icmpUnreach}, nil
			}
			if st == ipReqTimedOut {
				return EchoReply{Seq: seq}, ErrEchoTimeout
			}
			return EchoReply{Seq: seq}, fmt.Errorf("echo status %d", st)
		}
		return EchoReply{Seq: seq, From: c.ip.String(), RTT: rtt, TTL: -1, Size: 8 + len(data)}, nil
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	if r.Status == ipReqTimedOut {
		return EchoReply{Seq: seq}, ErrEchoTimeout
	}
	if r.Status != ipSuccess {
		if k := icmpStatusKind(r.Status); k != icmpNotOurs && ttl > 0 {
			a := r.Address // in network order as stored
			from := net.IPv4(byte(a), byte(a>>8), byte(a>>16), byte(a>>24)).String()
			return EchoReply{Seq: seq, From: from, RTT: rtt, TTL: int(r.Options.TTL),
				Hop: k == icmpExceeded, Unreachable: k == icmpUnreach}, nil
		}
		return EchoReply{Seq: seq}, fmt.Errorf("echo status %d", r.Status)
	}
	return EchoReply{Seq: seq, From: c.ip.String(), RTT: rtt, TTL: int(r.Options.TTL), Size: 8 + int(r.DataSize)}, nil
}
