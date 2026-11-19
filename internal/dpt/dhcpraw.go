// SPDX-License-Identifier: MIT

//go:build linux || darwin

package dpt

import (
	"encoding/binary"
	"net"
)

// Linux and macOS send the DISCOVER and hear the offers below UDP (a
// packet socket, /dev/bpf): the system's DHCP client and a VPN's rules
// cannot take the offers first.

// DHCPProbeNote is empty here: the probe hears every offer on the wire.
const DHCPProbeNote = ""

// dhcpIPv4UDP wraps a DHCP message in UDP 68 -> 67 and IPv4 0.0.0.0 ->
// 255.255.255.255.
func dhcpIPv4UDP(payload []byte) []byte {
	ul := 8 + len(payload)
	b := make([]byte, 20+ul)
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(b[10:], inetChecksum(b[:20]))
	u := b[20:]
	binary.BigEndian.PutUint16(u[0:], 68)
	binary.BigEndian.PutUint16(u[2:], 67)
	binary.BigEndian.PutUint16(u[4:], uint16(ul))
	copy(u[8:], payload)
	// the UDP checksum over the pseudo-header
	ph := make([]byte, 0, 12+ul)
	ph = append(ph, b[12:20]...)
	ph = append(ph, 0, 17)
	ph = binary.BigEndian.AppendUint16(ph, uint16(ul))
	ph = append(ph, u...)
	cs := inetChecksum(ph)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], cs)
	return b
}

// dhcpUDP is an IPv4 packet's UDP payload to port 68, and its source.
func dhcpUDP(p []byte) (*net.UDPAddr, []byte, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return nil, nil, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl+8 || p[9] != 17 {
		return nil, nil, false
	}
	u := p[ihl:]
	if binary.BigEndian.Uint16(u[2:4]) != 68 {
		return nil, nil, false
	}
	ul := int(binary.BigEndian.Uint16(u[4:6]))
	if ul < 8 || ul > len(u) {
		return nil, nil, false
	}
	src := &net.UDPAddr{IP: net.IP(append([]byte(nil), p[12:16]...)), Port: int(binary.BigEndian.Uint16(u[0:2]))}
	return src, u[8:ul], true
}
