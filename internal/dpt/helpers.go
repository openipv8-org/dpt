// SPDX-License-Identifier: MIT
package dpt

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// The few general helpers the probes need.

// ntpEpoch is 1900-01-01 in Unix seconds.
const ntpEpoch = -2208988800

// DNSSEC record types.
const (
	DNSTypeDS     uint16 = 43
	DNSTypeRRSIG  uint16 = 46
	DNSTypeNSEC   uint16 = 47
	DNSTypeDNSKEY uint16 = 48
	DNSTypeNSEC3  uint16 = 50
)

// dnsFlagDO is the DO bit of the OPT record's TTL field.
const dnsFlagDO = 1 << 15

// dnsOPT is an OPT record (RFC 6891) offering size octets.
func dnsOPT(size uint16, rcode int) DNSRecord {
	return DNSRecord{Name: ".", Type: DNSTypeOPT, Class: size, TTL: uint32(rcode>>4) << 24}
}

// dnsNameFromWire reads an uncompressed name at the start of b.
func dnsNameFromWire(b []byte) (string, int, error) {
	// a name inside RDATA has no pointers: give dnsName nothing to
	// point back at
	return dnsName(b, 0)
}

// DNSKeyTag is a DNSKEY's key tag (RFC 4034 appendix B).
func DNSKeyTag(rdata []byte) uint16 {
	var ac uint32
	for i, b := range rdata {
		if i&1 == 1 {
			ac += uint32(b)
		} else {
			ac += uint32(b) << 8
		}
	}
	ac += ac >> 16 & 0xffff
	return uint16(ac & 0xffff)
}

// Safe removes control characters (terminal escapes) from text that
// came from the network.
func Safe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// Printable replaces control characters and bytes that are not UTF-8
// with '?', for text typed by the user and shown back.
func Printable(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || (r == utf8.RuneError && size == 1):
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ValidName says whether s is a host name: labels of letters, digits and
// hyphens, 63 characters at most, 253 in all.
func ValidName(s string, record bool) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if record {
			label = strings.TrimPrefix(label, "_")
		}
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range strings.ToLower(label) {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// NewResolver asks the given name servers (IP literals, port 53) in turn
// instead of the system's resolver.
func NewResolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	list := append([]string(nil), servers...)
	var next atomic.Uint64
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		server := list[int(next.Add(1)-1)%len(list)]
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
	}}
}
