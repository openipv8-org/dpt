// SPDX-License-Identifier: MIT
package dpt

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// DNS record types and classes the server knows by name.
const (
	DNSTypeA     uint16 = 1
	DNSTypeNS    uint16 = 2
	DNSTypeCNAME uint16 = 5
	DNSTypeSOA   uint16 = 6
	DNSTypePTR   uint16 = 12
	DNSTypeMX    uint16 = 15
	DNSTypeTXT   uint16 = 16
	DNSTypeAAAA  uint16 = 28
	DNSTypeSRV   uint16 = 33
	DNSTypeOPT   uint16 = 41
	DNSTypeIXFR  uint16 = 251
	DNSTypeAXFR  uint16 = 252
	DNSTypeANY   uint16 = 255

	dnsClassIN uint16 = 1
)

// Response codes.
const (
	dnsNoError  = 0
	dnsFormErr  = 1
	dnsServFail = 2
	dnsNXDomain = 3
	dnsNotImp   = 4
	dnsRefused  = 5
	dnsBadVers  = 16 // extended: needs an OPT record
)

// Header flag bits.
const (
	dnsFlagQR = 1 << 15
	dnsFlagAA = 1 << 10
	dnsFlagTC = 1 << 9
	dnsFlagRD = 1 << 8
	dnsFlagRA = 1 << 7
)

// Limits of the wire format.
const (
	dnsMaxName    = 255 // octets of a name on the wire
	dnsMaxLabel   = 63
	dnsMaxPointer = 64 // compression pointers followed in one name
	dnsMaxRRs     = 512
)

var dnsTypeNames = map[uint16]string{
	DNSTypeA: "A", DNSTypeNS: "NS", DNSTypeCNAME: "CNAME", DNSTypeSOA: "SOA", DNSTypePTR: "PTR",
	DNSTypeMX: "MX", DNSTypeTXT: "TXT", DNSTypeAAAA: "AAAA", DNSTypeSRV: "SRV", DNSTypeOPT: "OPT",
	DNSTypeIXFR: "IXFR", DNSTypeAXFR: "AXFR", DNSTypeANY: "ANY",
}

var dnsRcodeNames = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

func dnsRcodeName(r int) string {
	if r >= 0 && r < len(dnsRcodeNames) {
		return dnsRcodeNames[r]
	}
	if r == dnsBadVers {
		return "BADVERS"
	}
	return "RCODE" + strconv.Itoa(r)
}

// DNSQuestion is one question: a name in presentation form (dots
// between labels, \. and \DDD escapes), its type and class.
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNSRecord is a resource record.  Data is the RDATA in wire form with
// every name in it uncompressed, so it can be copied into any message.
type DNSRecord struct {
	Name  string
	Type  uint16
	Class uint16 // 0 is IN
	TTL   uint32
	Data  []byte
}

// dnsMsg is a whole message.
type dnsMsg struct {
	ID         uint16
	Flags      uint16
	Question   []DNSQuestion
	Answer     []DNSRecord
	Authority  []DNSRecord
	Additional []DNSRecord
}

func (m *dnsMsg) rcode() int { return int(m.Flags & 0xf) }

func (m *dnsMsg) setRcode(r int) { m.Flags = m.Flags&^0xf | uint16(r&0xf) }

var (
	errDNSShort   = errors.New("dns: message too short")
	errDNSName    = errors.New("dns: bad name")
	errDNSPointer = errors.New("dns: bad compression pointer")
	errDNSRecord  = errors.New("dns: bad record")
	errDNSCount   = errors.New("dns: too many records")
)

// parseDNS decodes a message.  It refuses anything it would not send:
// names over 255 octets, labels over 63, pointers that do not point
// strictly backwards (which is what makes a pointer loop impossible),
// extended label types, and bytes left over at the end.  It never keeps
// a reference to b.
func parseDNS(b []byte) (*dnsMsg, error) {
	if len(b) < 12 {
		return nil, errDNSShort
	}
	m := &dnsMsg{ID: binary.BigEndian.Uint16(b), Flags: binary.BigEndian.Uint16(b[2:])}
	counts := [4]int{}
	total := 0
	for i := range counts {
		counts[i] = int(binary.BigEndian.Uint16(b[4+2*i:]))
		total += counts[i]
	}
	if total > dnsMaxRRs {
		return nil, errDNSCount
	}
	off := 12
	for i := 0; i < counts[0]; i++ {
		name, n, err := dnsName(b, off)
		if err != nil {
			return nil, err
		}
		if n+4 > len(b) {
			return nil, errDNSShort
		}
		m.Question = append(m.Question, DNSQuestion{Name: name, Type: binary.BigEndian.Uint16(b[n:]), Class: binary.BigEndian.Uint16(b[n+2:])})
		off = n + 4
	}
	for s, dst := range []*[]DNSRecord{&m.Answer, &m.Authority, &m.Additional} {
		for i := 0; i < counts[s+1]; i++ {
			rr, n, err := dnsParseRR(b, off)
			if err != nil {
				return nil, err
			}
			*dst = append(*dst, rr)
			off = n
		}
	}
	if off != len(b) {
		return nil, errDNSRecord
	}
	return m, nil
}

// dnsName reads the name at off and gives the offset after it (after
// the first pointer, if any).
func dnsName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	wire := 0 // octets of the name as it would be uncompressed
	next := -1
	ptrs := 0
	limit := off // a pointer must point before the label that holds it
	for {
		if off >= len(b) {
			return "", 0, errDNSShort
		}
		l := int(b[off])
		switch {
		case l == 0:
			wire++
			if wire > dnsMaxName {
				return "", 0, errDNSName
			}
			if next < 0 {
				next = off + 1
			}
			if sb.Len() == 0 {
				return ".", next, nil
			}
			return sb.String(), next, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", 0, errDNSShort
			}
			p := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if p >= limit || ptrs >= dnsMaxPointer {
				return "", 0, errDNSPointer
			}
			ptrs++
			if next < 0 {
				next = off + 2
			}
			off, limit = p, p
		case l&0xc0 != 0:
			return "", 0, errDNSName // 0x40 and 0x80: no such label types
		default:
			if off+1+l > len(b) {
				return "", 0, errDNSShort
			}
			wire += 1 + l
			if wire > dnsMaxName {
				return "", 0, errDNSName
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			dnsEscapeLabel(&sb, b[off+1:off+1+l])
			if next < 0 {
				limit = off
			}
			off += 1 + l
		}
	}
}

// dnsEscapeLabel writes a label in presentation form: letters, digits,
// '-', '_' and '*' as they are; '.', '\' as \. and \\; anything else
// as \DDD.  A name read off the wire can then never be mistaken for one
// with other labels.
func dnsEscapeLabel(sb *strings.Builder, l []byte) {
	for _, c := range l {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '*':
			sb.WriteByte(c)
		case c == '.' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			sb.WriteByte('\\')
			sb.WriteByte('0' + c/100)
			sb.WriteByte('0' + c/10%10)
			sb.WriteByte('0' + c%10)
		}
	}
}

// dnsLabels splits a presentation-form name into wire labels.  "." and
// "" are the root.
func dnsLabels(name string) ([][]byte, error) {
	if name == "." || name == "" {
		return nil, nil
	}
	name = strings.TrimSuffix(name, ".")
	var out [][]byte
	var cur []byte
	total := 1
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '\\':
			if i+1 >= len(name) {
				return nil, errDNSName
			}
			if d := name[i+1]; d >= '0' && d <= '9' {
				if i+4 > len(name) {
					return nil, errDNSName
				}
				v, err := strconv.Atoi(name[i+1 : i+4])
				if err != nil || v < 0 || v > 255 || strings.ContainsAny(name[i+1:i+4], "+-") {
					return nil, errDNSName
				}
				cur = append(cur, byte(v))
				i += 3
			} else {
				cur = append(cur, d)
				i++
			}
		case c == '.':
			if len(cur) == 0 || len(cur) > dnsMaxLabel {
				return nil, errDNSName
			}
			out = append(out, cur)
			total += 1 + len(cur)
			cur = nil
		default:
			cur = append(cur, c)
		}
	}
	if len(cur) == 0 || len(cur) > dnsMaxLabel {
		return nil, errDNSName
	}
	out = append(out, cur)
	total += 1 + len(cur)
	if total > dnsMaxName {
		return nil, errDNSName
	}
	return out, nil
}

// dnsWireName is a name uncompressed, for RDATA.
func dnsWireName(name string) ([]byte, error) {
	ls, err := dnsLabels(name)
	if err != nil {
		return nil, err
	}
	var b []byte
	for _, l := range ls {
		b = append(append(b, byte(len(l))), l...)
	}
	return append(b, 0), nil
}

// dnsParseRR reads one record; names inside RDATA are decompressed.
func dnsParseRR(b []byte, off int) (DNSRecord, int, error) {
	name, n, err := dnsName(b, off)
	if err != nil {
		return DNSRecord{}, 0, err
	}
	if n+10 > len(b) {
		return DNSRecord{}, 0, errDNSShort
	}
	rr := DNSRecord{Name: name, Type: binary.BigEndian.Uint16(b[n:]), Class: binary.BigEndian.Uint16(b[n+2:]), TTL: binary.BigEndian.Uint32(b[n+4:])}
	rdlen := int(binary.BigEndian.Uint16(b[n+8:]))
	start := n + 10
	end := start + rdlen
	if end > len(b) {
		return DNSRecord{}, 0, errDNSShort
	}
	// the names a record type carries, after how many fixed octets
	var fixed []int // positions: -1 a name, k>0 k fixed octets
	switch rr.Type {
	case DNSTypeCNAME, DNSTypeNS, DNSTypePTR:
		fixed = []int{-1}
	case DNSTypeMX:
		fixed = []int{2, -1}
	case DNSTypeSRV:
		fixed = []int{6, -1}
	case DNSTypeSOA:
		fixed = []int{-1, -1, 20}
	}
	if fixed == nil {
		rr.Data = append([]byte{}, b[start:end]...)
		return rr, end, nil
	}
	p := start
	var data []byte
	for _, f := range fixed {
		if f < 0 {
			nm, q, err := dnsName(b, p)
			if err != nil || q > end {
				return DNSRecord{}, 0, errDNSRecord
			}
			w, err := dnsWireName(nm)
			if err != nil {
				return DNSRecord{}, 0, errDNSRecord
			}
			data = append(data, w...)
			p = q
			continue
		}
		if p+f > end {
			return DNSRecord{}, 0, errDNSRecord
		}
		data = append(data, b[p:p+f]...)
		p += f
	}
	if p != end {
		return DNSRecord{}, 0, errDNSRecord
	}
	rr.Data = data
	return rr, end, nil
}

// dnsBuilder writes a message with name compression.
type dnsBuilder struct {
	b    []byte
	comp map[string]int // lower-case name suffix -> offset
}

func (w *dnsBuilder) name(name string) error {
	ls, err := dnsLabels(name)
	if err != nil {
		return err
	}
	for i := range ls {
		var key strings.Builder
		for _, l := range ls[i:] {
			key.WriteString(strings.ToLower(string(l)))
			key.WriteByte(0)
		}
		k := key.String()
		if off, ok := w.comp[k]; ok {
			w.b = binary.BigEndian.AppendUint16(w.b, 0xc000|uint16(off))
			return nil
		}
		if len(w.b) < 0x3fff {
			w.comp[k] = len(w.b)
		}
		w.b = append(append(w.b, byte(len(ls[i]))), ls[i]...)
	}
	w.b = append(w.b, 0)
	return nil
}

func (w *dnsBuilder) rr(r DNSRecord) error {
	if err := w.name(r.Name); err != nil {
		return err
	}
	class := r.Class
	if class == 0 {
		class = dnsClassIN
	}
	if len(r.Data) > 0xffff {
		return errDNSRecord
	}
	w.b = binary.BigEndian.AppendUint16(w.b, r.Type)
	w.b = binary.BigEndian.AppendUint16(w.b, class)
	w.b = binary.BigEndian.AppendUint32(w.b, r.TTL)
	w.b = binary.BigEndian.AppendUint16(w.b, uint16(len(r.Data)))
	w.b = append(w.b, r.Data...)
	return nil
}

// marshal encodes the message.
func (m *dnsMsg) marshal() ([]byte, error) {
	w := &dnsBuilder{b: make([]byte, 12, 512), comp: map[string]int{}}
	binary.BigEndian.PutUint16(w.b, m.ID)
	binary.BigEndian.PutUint16(w.b[2:], m.Flags)
	secs := [][]DNSRecord{m.Answer, m.Authority, m.Additional}
	if len(m.Question) > 0xffff {
		return nil, errDNSCount
	}
	binary.BigEndian.PutUint16(w.b[4:], uint16(len(m.Question)))
	for i, s := range secs {
		if len(s) > 0xffff {
			return nil, errDNSCount
		}
		binary.BigEndian.PutUint16(w.b[6+2*i:], uint16(len(s)))
	}
	for _, q := range m.Question {
		if err := w.name(q.Name); err != nil {
			return nil, err
		}
		w.b = binary.BigEndian.AppendUint16(w.b, q.Type)
		w.b = binary.BigEndian.AppendUint16(w.b, q.Class)
	}
	for _, s := range secs {
		for _, r := range s {
			if err := w.rr(r); err != nil {
				return nil, err
			}
		}
	}
	if len(w.b) > 0xffff {
		return nil, errDNSRecord
	}
	return w.b, nil
}

// opt is the message's OPT record, if any.
func (m *dnsMsg) opt() (DNSRecord, int, bool) {
	n := 0
	var o DNSRecord
	for _, r := range m.Additional {
		if r.Type == DNSTypeOPT {
			o = r
			n++
		}
	}
	return o, n, n > 0
}

// dnsTypeName is a type's mnemonic, or TYPEn (RFC 3597).
func dnsTypeName(t uint16) string {
	if n, ok := dnsTypeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// DNSWireName is name in wire form, uncompressed (an add-on's record
// types that carry a name as MX does).
func DNSWireName(name string) ([]byte, error) { return dnsWireName(name) }
