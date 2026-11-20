// SPDX-License-Identifier: MIT
package dpt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The DNS client as a tool sees it: every header bit and the EDNS size
// the server sent, the time it took, the raw message, and the choices
// nslookup has (class, recursion, TCP).

// More header flags.
const (
	dnsFlagAD = 1 << 5
	dnsFlagCD = 1 << 4
)

// Record types a client asks for that the server side never names.
const (
	DNSTypeHINFO uint16 = 13
	DNSTypeTLSA  uint16 = 52
	DNSTypeSVCB  uint16 = 64
	DNSTypeHTTPS uint16 = 65
	DNSTypeCAA   uint16 = 257
)

// DNS classes.
const (
	DNSClassIN uint16 = 1
	DNSClassCH uint16 = 3
	DNSClassHS uint16 = 4
)

var dnsClientTypes = map[string]uint16{
	"A": DNSTypeA, "NS": DNSTypeNS, "CNAME": DNSTypeCNAME, "SOA": DNSTypeSOA, "PTR": DNSTypePTR,
	"HINFO": DNSTypeHINFO, "MX": DNSTypeMX, "TXT": DNSTypeTXT, "AAAA": DNSTypeAAAA, "SRV": DNSTypeSRV,
	"DS": DNSTypeDS, "RRSIG": DNSTypeRRSIG, "NSEC": DNSTypeNSEC, "DNSKEY": DNSTypeDNSKEY,
	"NSEC3": DNSTypeNSEC3, "TLSA": DNSTypeTLSA, "SVCB": DNSTypeSVCB, "HTTPS": DNSTypeHTTPS,
	"CAA": DNSTypeCAA, "AXFR": DNSTypeAXFR, "IXFR": DNSTypeIXFR, "ANY": DNSTypeANY,
}

// DNSTypeByName reads a type mnemonic (any case) or TYPEn.
func DNSTypeByName(s string) (uint16, bool) {
	u := strings.ToUpper(s)
	if t, ok := dnsClientTypes[u]; ok {
		return t, true
	}
	if n, err := strconv.ParseUint(strings.TrimPrefix(u, "TYPE"), 10, 16); err == nil && strings.HasPrefix(u, "TYPE") {
		return uint16(n), true
	}
	return 0, false
}

// DNSTypeString is a type's mnemonic, or TYPEn.
func DNSTypeString(t uint16) string {
	for n, v := range dnsClientTypes {
		if v == t {
			return n
		}
	}
	return dnsTypeName(t)
}

// DNSClassByName reads IN, CH, HS (any case) or CLASSn.
func DNSClassByName(s string) (uint16, bool) {
	switch u := strings.ToUpper(s); u {
	case "IN":
		return DNSClassIN, true
	case "CH", "CHAOS":
		return DNSClassCH, true
	case "HS", "HESIOD":
		return DNSClassHS, true
	default:
		if n, err := strconv.ParseUint(strings.TrimPrefix(u, "CLASS"), 10, 16); err == nil && strings.HasPrefix(u, "CLASS") {
			return uint16(n), true
		}
	}
	return 0, false
}

// DNSClassString is IN, CH, HS or CLASSn.
func DNSClassString(c uint16) string {
	switch c {
	case 0, DNSClassIN:
		return "IN"
	case DNSClassCH:
		return "CH"
	case DNSClassHS:
		return "HS"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// DNSAskOptions is how DNSAsk asks.  The zero value asks for an A record
// in class IN over UDP, recursion desired, with EDNS (1232 octets).
type DNSAskOptions struct {
	Type      uint16 // 0: A
	Class     uint16 // 0: IN
	NoRecurse bool   // clear RD
	TCP       bool   // always TCP (nslookup's set vc)
	NoEDNS    bool   // no OPT record
	UDPSize   uint16 // the EDNS size we offer; 0: 1232
	DO        bool   // DNSSEC OK: ask for signatures
	CD        bool   // checking disabled
}

// DNSAnswer is everything a server sent back to DNSAsk.
type DNSAnswer struct {
	Server   string // host:port asked
	Network  string // "udp" or "tcp": how the answer came
	Question DNSQuestion
	ID       uint16
	Rcode    int // with the EDNS extended bits
	// header bits
	AA, TC, RD, RA, AD, CD bool
	EDNS                   bool   // the server sent an OPT record
	EDNSSize               uint16 // the UDP size it advertised
	EDNSVersion            int
	DOBit                  bool
	Answer                 []DNSRecord
	Authority              []DNSRecord
	Additional             []DNSRecord // without the OPT record
	Time                   time.Duration
	Size                   int    // octets of the answer
	Query, Raw             []byte // the query sent, the answer received
	TruncatedRetry         bool   // a truncated UDP answer was asked again over TCP
}

// RcodeName is the answer's rcode as a word.
func (a *DNSAnswer) RcodeName() string { return dnsRcodeName(a.Rcode) }

// Flags is the header bits that are set, as dig writes them: "qr aa rd ra".
func (a *DNSAnswer) Flags() string {
	f := []string{"qr"}
	for _, x := range []struct {
		on bool
		n  string
	}{{a.AA, "aa"}, {a.TC, "tc"}, {a.RD, "rd"}, {a.RA, "ra"}, {a.AD, "ad"}, {a.CD, "cd"}} {
		if x.on {
			f = append(f, x.n)
		}
	}
	return strings.Join(f, " ")
}

// DNSServerAddr is server with port 53 (or port) added when it has none.
func DNSServerAddr(server string, port int) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if port == 0 {
		port = 53
	}
	return net.JoinHostPort(strings.Trim(server, "[]"), strconv.Itoa(port))
}

// DNSAsk asks server (host:port) one question.  A truncated UDP answer
// is asked again over TCP.  It gives an error only when no answer came;
// a REFUSED or SERVFAIL is an answer.
func DNSAsk(ctx context.Context, server, name string, o DNSAskOptions, timeout time.Duration) (*DNSAnswer, error) {
	if o.Type == 0 {
		o.Type = DNSTypeA
	}
	if o.Class == 0 {
		o.Class = DNSClassIN
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	q := &dnsMsg{ID: binary.BigEndian.Uint16(idb[:]), Question: []DNSQuestion{{Name: name, Type: o.Type, Class: o.Class}}}
	if !o.NoRecurse {
		q.Flags |= dnsFlagRD
	}
	if o.CD {
		q.Flags |= dnsFlagCD
	}
	if !o.NoEDNS {
		size := o.UDPSize
		if size == 0 {
			size = 1232
		}
		opt := dnsOPT(size, 0)
		if o.DO {
			opt.TTL |= dnsFlagDO
		}
		q.Additional = []DNSRecord{opt}
	}
	b, err := q.marshal()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := "udp"
	if o.TCP {
		network = "tcp"
	}
	start := time.Now()
	m, raw, err := dnsClientTrip(ctx, network, server, b, q)
	retry := false
	if err == nil && network == "udp" && m.Flags&dnsFlagTC != 0 {
		if m2, raw2, err2 := dnsClientTrip(ctx, "tcp", server, b, q); err2 == nil {
			m, raw, network, retry = m2, raw2, "tcp", true
		}
	}
	if err != nil {
		return nil, err
	}
	a := &DNSAnswer{Server: server, Network: network, Question: q.Question[0], ID: m.ID, Rcode: m.rcode(),
		AA: m.Flags&dnsFlagAA != 0, TC: m.Flags&dnsFlagTC != 0, RD: m.Flags&dnsFlagRD != 0,
		RA: m.Flags&dnsFlagRA != 0, AD: m.Flags&dnsFlagAD != 0, CD: m.Flags&dnsFlagCD != 0,
		Answer: m.Answer, Authority: m.Authority, Time: time.Since(start), Size: len(raw),
		Query: b, Raw: raw, TruncatedRetry: retry}
	for _, r := range m.Additional {
		if r.Type == DNSTypeOPT {
			a.EDNS = true
			a.EDNSSize = r.Class
			a.Rcode |= int(r.TTL>>24) << 4
			a.EDNSVersion = int(r.TTL>>16) & 0xff
			a.DOBit = r.TTL&dnsFlagDO != 0
			continue
		}
		a.Additional = append(a.Additional, r)
	}
	return a, nil
}

// dnsClientTrip sends b and waits for the answer to q, giving the
// message and its octets.
func dnsClientTrip(ctx context.Context, network, server string, b []byte, q *dnsMsg) (*dnsMsg, []byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	dl, _ := ctx.Deadline()
	conn.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	if network == "tcp" {
		if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)); err != nil {
			return nil, nil, err
		}
		for {
			buf, err := dnsReadTCP(conn)
			if err != nil {
				return nil, nil, err
			}
			m, err := parseDNS(buf)
			if err != nil {
				return nil, nil, err
			}
			if m.ID == q.ID && m.Flags&dnsFlagQR != 0 {
				return m, buf, nil
			}
		}
	}
	if _, err := conn.Write(b); err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, nil, errors.New("no answer")
			}
			return nil, nil, err
		}
		m, err := parseDNS(buf[:n])
		if err != nil || m.ID != q.ID || m.Flags&dnsFlagQR == 0 {
			continue
		}
		return m, append([]byte(nil), buf[:n]...), nil
	}
}

func dnsReadTCP(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// DNSZoneTransfer asks server for zone over TCP (AXFR) and gives every
// record, the closing SOA left out.
func DNSZoneTransfer(ctx context.Context, server, zone string, timeout time.Duration) ([]DNSRecord, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	q := &dnsMsg{ID: binary.BigEndian.Uint16(idb[:]), Question: []DNSQuestion{{Name: zone, Type: DNSTypeAXFR, Class: DNSClassIN}}}
	b, err := q.marshal()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)); err != nil {
		return nil, err
	}
	var out []DNSRecord
	soas := 0
	for {
		buf, err := dnsReadTCP(conn)
		if err != nil {
			if len(out) > 0 {
				return out, fmt.Errorf("transfer ended early: %v", err)
			}
			return nil, err
		}
		m, err := parseDNS(buf)
		if err != nil {
			return out, err
		}
		if m.ID != q.ID {
			continue
		}
		if r := m.rcode(); r != dnsNoError {
			return out, errors.New("transfer refused: " + dnsRcodeName(r))
		}
		if len(m.Answer) == 0 {
			return out, errors.New("transfer gave no records")
		}
		for _, r := range m.Answer {
			if r.Type == DNSTypeSOA {
				soas++
				if soas == 2 {
					return out, nil
				}
			}
			out = append(out, r)
		}
	}
}

// DNSReverseName is the PTR name of an IPv4 or IPv6 address.
func DNSReverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	var b strings.Builder
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&b, "%x.%x.", v6[i]&0xf, v6[i]>>4)
	}
	return b.String() + "ip6.arpa"
}

// DNSFormatRData writes a record's data in zone-file form; types it does
// not know are written as RFC 3597's \# <length> <hex>.
func DNSFormatRData(t uint16, b []byte) string {
	name := func(b []byte) (string, []byte, bool) {
		n, k, err := dnsNameFromWire(b)
		if err != nil {
			return "", nil, false
		}
		if n == "" {
			n = "."
		} else {
			n += "."
		}
		return n, b[k:], true
	}
	unknown := func() string { return `\# ` + strconv.Itoa(len(b)) + " " + hex.EncodeToString(b) }
	u16 := func(b []byte) int { return int(binary.BigEndian.Uint16(b)) }
	switch t {
	case DNSTypeA:
		if len(b) == 4 {
			return net.IP(b).String()
		}
	case DNSTypeAAAA:
		if len(b) == 16 {
			return net.IP(b).String()
		}
	case DNSTypeCNAME, DNSTypeNS, DNSTypePTR:
		if n, _, ok := name(b); ok {
			return n
		}
	case DNSTypeMX:
		if len(b) >= 3 {
			if n, _, ok := name(b[2:]); ok {
				return strconv.Itoa(u16(b)) + " " + n
			}
		}
	case DNSTypeSRV:
		if len(b) >= 7 {
			if n, _, ok := name(b[6:]); ok {
				return fmt.Sprintf("%d %d %d %s", u16(b), u16(b[2:]), u16(b[4:]), n)
			}
		}
	case DNSTypeTXT, DNSTypeHINFO:
		var parts []string
		for len(b) > 0 {
			n := int(b[0])
			if 1+n > len(b) {
				return unknown()
			}
			parts = append(parts, strconv.Quote(string(b[1:1+n])))
			b = b[1+n:]
		}
		return strings.Join(parts, " ")
	case DNSTypeSOA:
		m, rest, ok1 := name(b)
		r, rest, ok2 := name(rest)
		if ok1 && ok2 && len(rest) == 20 {
			v := func(i int) uint32 { return binary.BigEndian.Uint32(rest[4*i:]) }
			return fmt.Sprintf("%s %s %d %d %d %d %d", m, r, v(0), v(1), v(2), v(3), v(4))
		}
	case DNSTypeCAA:
		if len(b) >= 2 && 2+int(b[1]) <= len(b) {
			return fmt.Sprintf("%d %s %q", b[0], b[2:2+int(b[1])], b[2+int(b[1]):])
		}
	case DNSTypeDS:
		if len(b) >= 4 {
			return fmt.Sprintf("%d %d %d %s", u16(b), b[2], b[3], strings.ToUpper(hex.EncodeToString(b[4:])))
		}
	case DNSTypeDNSKEY:
		if len(b) >= 4 {
			return fmt.Sprintf("%d %d %d %s ; key id %d", u16(b), b[2], b[3], base64.StdEncoding.EncodeToString(b[4:]), DNSKeyTag(b))
		}
	case DNSTypeRRSIG:
		if len(b) >= 18 {
			if n, sig, ok := name(b[18:]); ok {
				tm := func(v uint32) string { return time.Unix(int64(v), 0).UTC().Format("20060102150405") }
				return fmt.Sprintf("%s %d %d %d %s %s %d %s %s", DNSTypeString(uint16(u16(b))), b[2], b[3],
					binary.BigEndian.Uint32(b[4:]), tm(binary.BigEndian.Uint32(b[8:])), tm(binary.BigEndian.Uint32(b[12:])),
					u16(b[16:]), n, base64.StdEncoding.EncodeToString(sig))
			}
		}
	default:
		return unknown()
	}
	return unknown()
}

// DNSTypeNames are the type mnemonics DNSTypeByName knows, sorted.
func DNSTypeNames() []string {
	out := make([]string, 0, len(dnsClientTypes))
	for n := range dnsClientTypes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
