// SPDX-License-Identifier: MIT
package dpt

import (
	"encoding/binary"
	"errors"
	"net"
)

// DHCP message types (option 53).
const (
	DHCPDiscover byte = 1
	DHCPOffer    byte = 2
	DHCPRequest  byte = 3
	DHCPDecline  byte = 4
	DHCPAck      byte = 5
	DHCPNak      byte = 6
	DHCPRelease  byte = 7
	DHCPInform   byte = 8
)

// DHCP options the server reads or writes.
const (
	dhcpOptMask      byte = 1
	dhcpOptRouter    byte = 3
	dhcpOptDNS       byte = 6
	dhcpOptHostname  byte = 12
	dhcpOptDomain    byte = 15
	dhcpOptRequested byte = 50
	dhcpOptLease     byte = 51
	dhcpOptOverload  byte = 52
	dhcpOptType      byte = 53
	dhcpOptServerID  byte = 54
	dhcpOptT1        byte = 58
	dhcpOptT2        byte = 59
	dhcpOptClientID  byte = 61
	dhcpOptRelay     byte = 82
)

// Limits of the packet format.
const (
	dhcpFixed    = 236 // the BOOTP part, before the magic cookie
	dhcpMinReply = 300 // BOOTP's minimum; some relays drop shorter
	dhcpMaxMsg   = 4096
)

var dhcpCookie = []byte{99, 130, 83, 99}

// DHCPOption is one option, its data whole (RFC 3396: repeated codes
// are joined when read, split when written).
type DHCPOption struct {
	Code byte
	Data []byte
}

// DHCPMessage is a BOOTP/DHCP message.  sname and file are not carried:
// the server neither reads nor sends them (option 52, which would put
// options there, is ignored).
type DHCPMessage struct {
	Op, HType, HLen, Hops byte
	XID                   uint32
	Secs, Flags           uint16
	CIAddr, YIAddr        net.IP // 4 bytes each
	SIAddr, GIAddr        net.IP
	CHAddr                [16]byte
	Options               []DHCPOption
}

var errDHCPPacket = errors.New("malformed DHCP packet")

// ParseDHCP decodes a packet.  It never keeps a reference to b.
func ParseDHCP(b []byte) (*DHCPMessage, error) {
	if len(b) < dhcpFixed+4 || len(b) > dhcpMaxMsg {
		return nil, errDHCPPacket
	}
	if string(b[dhcpFixed:dhcpFixed+4]) != string(dhcpCookie) {
		return nil, errDHCPPacket
	}
	m := &DHCPMessage{
		Op: b[0], HType: b[1], HLen: b[2], Hops: b[3],
		XID:  binary.BigEndian.Uint32(b[4:]),
		Secs: binary.BigEndian.Uint16(b[8:]), Flags: binary.BigEndian.Uint16(b[10:]),
		CIAddr: ip4(b[12:16]), YIAddr: ip4(b[16:20]), SIAddr: ip4(b[20:24]), GIAddr: ip4(b[24:28]),
	}
	copy(m.CHAddr[:], b[28:44])
	opts := b[dhcpFixed+4:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 0 {
			i++
			continue
		}
		if code == 255 {
			break
		}
		if i+1 >= len(opts) {
			return nil, errDHCPPacket
		}
		n := int(opts[i+1])
		if i+2+n > len(opts) {
			return nil, errDHCPPacket
		}
		data := opts[i+2 : i+2+n]
		if o := m.opt(code); o != nil {
			o.Data = append(o.Data, data...)
		} else {
			m.Options = append(m.Options, DHCPOption{Code: code, Data: append([]byte{}, data...)})
		}
		i += 2 + n
	}
	return m, nil
}

func ip4(b []byte) net.IP { return net.IPv4(b[0], b[1], b[2], b[3]).To4() }

func (m *DHCPMessage) opt(code byte) *DHCPOption {
	for i := range m.Options {
		if m.Options[i].Code == code {
			return &m.Options[i]
		}
	}
	return nil
}

// Get is an option's data (nil when absent).
func (m *DHCPMessage) Get(code byte) []byte {
	if o := m.opt(code); o != nil {
		return o.Data
	}
	return nil
}

// Set sets an option, replacing any before.
func (m *DHCPMessage) Set(code byte, data []byte) {
	if o := m.opt(code); o != nil {
		o.Data = append([]byte{}, data...)
		return
	}
	m.Options = append(m.Options, DHCPOption{Code: code, Data: append([]byte{}, data...)})
}

// Type is the message type (option 53), 0 for plain BOOTP.
func (m *DHCPMessage) Type() byte {
	if t := m.Get(dhcpOptType); len(t) == 1 {
		return t[0]
	}
	return 0
}

// Marshal encodes the message, padded to the BOOTP minimum.
func (m *DHCPMessage) Marshal() []byte {
	b := make([]byte, dhcpFixed, 576)
	b[0], b[1], b[2], b[3] = m.Op, m.HType, m.HLen, m.Hops
	binary.BigEndian.PutUint32(b[4:], m.XID)
	binary.BigEndian.PutUint16(b[8:], m.Secs)
	binary.BigEndian.PutUint16(b[10:], m.Flags)
	for i, a := range []net.IP{m.CIAddr, m.YIAddr, m.SIAddr, m.GIAddr} {
		if v := a.To4(); v != nil {
			copy(b[12+4*i:], v)
		}
	}
	copy(b[28:44], m.CHAddr[:])
	b = append(b, dhcpCookie...)
	for _, o := range m.Options {
		if o.Code == 0 || o.Code == 255 {
			continue
		}
		d := o.Data
		for {
			n := min(len(d), 255)
			b = append(append(b, o.Code, byte(n)), d[:n]...)
			d = d[n:]
			if len(d) == 0 {
				break
			}
		}
	}
	b = append(b, 255)
	for len(b) < dhcpMinReply {
		b = append(b, 0)
	}
	return b
}
