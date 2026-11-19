// SPDX-License-Identifier: MIT

// Package mel checks dpt's Minimum Execution Level: what the chosen mode
// needs before it runs.  A failure is one clear line and exit code 2.
package mel

import (
	"errors"
	"net"

	"openipv8.org/concomm"
)

// Error is a MEL failure; its text follows "MEL: ".
type Error struct{ Msg string }

func (e *Error) Error() string { return "MEL: " + e.Msg }

func fail(m string) error { return &Error{Msg: m} }

// Is tells a MEL failure from other errors.
func Is(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

// Interface needs an interface that is up with an address (withAddr) or
// just up.
func Interface(withAddr bool) error {
	ifs, err := net.Interfaces()
	if err != nil {
		return fail("no active network interface")
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !withAddr {
			return nil
		}
		if a, _ := i.Addrs(); len(a) > 0 {
			return nil
		}
	}
	return fail("no active network interface")
}

// UDP needs a UDP socket.
func UDP() error {
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fail("cannot open UDP socket")
	}
	c.Close()
	return nil
}

// ICMP needs an ICMP socket (or handle) towards ip.
func ICMP(ip net.IP) error {
	c, err := concomm.OpenICMP(ip)
	if err != nil {
		return fail("cannot open ICMP socket — run as root or set net.ipv4.ping_group_range")
	}
	c.Close()
	return nil
}

// DHCP needs the privilege the probe takes and an interface that is up.
func DHCP(iface string) error {
	if iface != "" {
		i, err := net.InterfaceByName(iface)
		if err != nil || i.Flags&net.FlagUp == 0 {
			return fail("interface " + iface + " not found or down")
		}
	}
	if !dhcpPrivileged() {
		return fail("dhcp requires root/Administrator")
	}
	return nil
}
