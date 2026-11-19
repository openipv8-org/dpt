// SPDX-License-Identifier: MIT
package dpt

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// The DHCP probe: one DHCPDISCOVER, broadcast, and every DHCPOFFER that
// comes back in the listening time.  No DHCPREQUEST is ever sent, so no
// lease is taken and nothing needs releasing.  It shows every server on
// a segment (rogue ones too) and what each would hand out, time options
// first among them.

// DHCPProbeRequested is option 55 of the probe: every option dpt shows.
var DHCPProbeRequested = []byte{1, 2, 3, 4, 6, 12, 15, 26, 28, 33, 42, 43, 44, 51, 54, 58, 59, 66, 67, 100, 101, 119, 121, 150, 252}

// DHCPProbeOptions is how DHCPProbe asks.
type DHCPProbeOptions struct {
	Iface  string           // the interface to send on (required)
	MAC    net.HardwareAddr // chaddr; nil: the interface's own
	Listen time.Duration    // how long to collect offers; 0: 5 s
}

// DHCPOfferSeen is one offer, as it arrived.
type DHCPOfferSeen struct {
	SrcIP   net.IP
	SrcMAC  net.HardwareAddr // nil where the platform cannot see it
	After   time.Duration    // since the DISCOVER
	Msg     *DHCPMessage
	SName   string       // BOOTP server name field
	File    string       // BOOTP boot file field
	Options []DHCPOption // in the order received, overloaded ones joined
}

// DHCPRandomMAC is a random unicast, locally administered MAC.
func DHCPRandomMAC() net.HardwareAddr {
	m := make(net.HardwareAddr, 6)
	rand.Read(m)
	m[0] = m[0]&^1 | 2
	return m
}

// dhcpDiscover is the probe's DHCPDISCOVER.
func dhcpDiscover(xid uint32, mac net.HardwareAddr) []byte {
	m := &DHCPMessage{Op: 1, HType: 1, HLen: 6, XID: xid, Flags: 0x8000}
	copy(m.CHAddr[:], mac)
	m.Set(dhcpOptType, []byte{DHCPDiscover})
	m.Set(57, []byte{0x05, 0xdc}) // maximum message size 1500: offers are not trimmed to 576
	m.Set(55, DHCPProbeRequested)
	m.Set(dhcpOptClientID, append([]byte{1}, mac...))
	return m.Marshal()
}

// dhcpOfferFor reads b as an offer to xid; nil if it is not one.
func dhcpOfferFor(b []byte, xid uint32) *DHCPOfferSeen {
	m, err := ParseDHCP(b)
	if err != nil || m.Op != 2 || m.XID != xid || m.Type() != DHCPOffer {
		return nil
	}
	o := &DHCPOfferSeen{Msg: m, Options: m.Options}
	cstr := func(b []byte) string {
		if i := strings.IndexByte(string(b), 0); i >= 0 {
			b = b[:i]
		}
		return Safe(string(b))
	}
	ov := m.Get(dhcpOptOverload)
	if len(ov) == 1 && len(b) >= dhcpFixed {
		// option 52: sname (2) and/or file (1) hold more options
		extra := &DHCPMessage{}
		for _, f := range []struct {
			bit      byte
			from, to int
		}{{1, 108, 236}, {2, 44, 108}} {
			if ov[0]&f.bit != 0 {
				dhcpReadOptions(extra, b[f.from:f.to])
			}
		}
		for _, x := range extra.Options {
			if p := m.opt(x.Code); p != nil {
				p.Data = append(p.Data, x.Data...)
			} else {
				m.Options = append(m.Options, x)
			}
		}
		o.Options = m.Options
	} else if len(b) >= dhcpFixed {
		o.SName, o.File = cstr(b[44:108]), cstr(b[108:236])
	}
	return o
}

func dhcpReadOptions(m *DHCPMessage, opts []byte) {
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 0 {
			i++
			continue
		}
		if code == 255 || i+1 >= len(opts) {
			return
		}
		n := int(opts[i+1])
		if i+2+n > len(opts) {
			return
		}
		m.Options = append(m.Options, DHCPOption{Code: code, Data: append([]byte{}, opts[i+2:i+2+n]...)})
		i += 2 + n
	}
}

// DHCPProbe sends one DISCOVER from o.Iface and gives every offer heard
// within o.Listen, in the order they came.
func DHCPProbe(ctx context.Context, o DHCPProbeOptions) ([]DHCPOfferSeen, error) {
	ifi, err := net.InterfaceByName(o.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found or down", o.Iface)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %s not found or down", o.Iface)
	}
	mac := o.MAC
	if mac == nil {
		mac = ifi.HardwareAddr
	}
	if len(mac) != 6 {
		return nil, fmt.Errorf("interface %s has no Ethernet address: use a random MAC", o.Iface)
	}
	if o.Listen <= 0 {
		o.Listen = 5 * time.Second
	}
	var xb [4]byte
	rand.Read(xb[:])
	xid := binary.BigEndian.Uint32(xb[:])
	return dhcpProbe(ctx, ifi, xid, dhcpDiscover(xid, mac), o.Listen)
}

// errDHCPProbePriv is the probe without the privilege it needs.
// DHCPNeeds is what the probe needs, in the system's words.
var DHCPNeeds = map[bool]string{true: "an Administrator prompt", false: "sudo"}[runtime.GOOS == "windows"]

var errDHCPProbePriv = errors.New("dhcp needs " + DHCPNeeds)

// DHCPOptionValue writes an option's data the way an operator reads it;
// options it does not know are hex.
func DHCPOptionValue(code byte, d []byte) string {
	ips := func() string {
		if len(d) == 0 || len(d)%4 != 0 {
			return hex.EncodeToString(d)
		}
		var s []string
		for i := 0; i < len(d); i += 4 {
			s = append(s, net.IP(d[i:i+4]).String())
		}
		return strings.Join(s, " ")
	}
	secs := func() string {
		if len(d) != 4 {
			return hex.EncodeToString(d)
		}
		v := binary.BigEndian.Uint32(d)
		if v == 0xffffffff {
			return "infinite"
		}
		return (time.Duration(v) * time.Second).String()
	}
	switch code {
	case 1, 3, 4, 6, 28, 42, 44, 54, 150:
		return ips()
	case 2:
		if len(d) == 4 {
			return (time.Duration(int32(binary.BigEndian.Uint32(d))) * time.Second).String()
		}
	case 12, 15, 66, 67, 100, 101, 252:
		return strconv.Quote(string(d))
	case 26:
		if len(d) == 2 {
			return strconv.Itoa(int(binary.BigEndian.Uint16(d)))
		}
	case 51, 58, 59:
		return secs()
	case 53:
		if len(d) == 1 {
			return strconv.Itoa(int(d[0]))
		}
	case 33:
		if len(d)%8 == 0 && len(d) > 0 {
			var s []string
			for i := 0; i < len(d); i += 8 {
				s = append(s, net.IP(d[i:i+4]).String()+" via "+net.IP(d[i+4:i+8]).String())
			}
			return strings.Join(s, ", ")
		}
	case 119:
		if names, ok := dhcpSearchList(d); ok {
			return strings.Join(names, " ")
		}
	case 121:
		if r, ok := dhcpClasslessRoutes(d); ok {
			return strings.Join(r, ", ")
		}
	}
	return hex.EncodeToString(d)
}

// dhcpClasslessRoutes reads option 121 (RFC 3442).
func dhcpClasslessRoutes(d []byte) ([]string, bool) {
	var out []string
	for i := 0; i < len(d); {
		w := int(d[i])
		if w > 32 {
			return nil, false
		}
		n := (w + 7) / 8
		if i+1+n+4 > len(d) {
			return nil, false
		}
		var dst [4]byte
		copy(dst[:], d[i+1:i+1+n])
		gw := net.IP(d[i+1+n : i+1+n+4])
		out = append(out, fmt.Sprintf("%s/%d via %s", net.IP(dst[:]), w, gw))
		i += 1 + n + 4
	}
	return out, true
}

// dhcpSearchList reads option 119 (RFC 3397): DNS names, compressed
// against the option itself.
func dhcpSearchList(d []byte) ([]string, bool) {
	var out []string
	for off := 0; off < len(d); {
		n, next, err := dnsName(d, off)
		if err != nil || next <= off {
			return nil, false
		}
		out = append(out, n)
		off = next
	}
	return out, true
}
