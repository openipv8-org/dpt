// SPDX-License-Identifier: MIT
package dpt

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// The SNTP query (RFC 4330 / RFC 5905 client mode): one request, one
// answer, nothing kept.  It reads the local clock and never sets it, so
// it needs no privilege and runs the same on every platform.

// NTP modes.
const (
	ntpModeClient = 3
	ntpModeServer = 4
)

// ntpPacket is the 48-octet NTP header (RFC 5905 7.3); extension fields
// and MACs after it are ignored.
type ntpPacket struct {
	LI, VN, Mode uint8
	Stratum      uint8
	Poll         int8
	Precision    int8
	RootDelay    uint32 // 16.16 seconds
	RootDisp     uint32 // 16.16 seconds
	RefID        [4]byte
	Ref, Orig    uint64
	Recv, Xmit   uint64
}

var errNTPShort = errors.New("short NTP packet")

func parseNTP(b []byte) (ntpPacket, error) {
	var p ntpPacket
	if len(b) < 48 {
		return p, errNTPShort
	}
	p.LI, p.VN, p.Mode = b[0]>>6, b[0]>>3&7, b[0]&7
	p.Stratum, p.Poll, p.Precision = b[1], int8(b[2]), int8(b[3])
	p.RootDelay = binary.BigEndian.Uint32(b[4:])
	p.RootDisp = binary.BigEndian.Uint32(b[8:])
	copy(p.RefID[:], b[12:16])
	p.Ref = binary.BigEndian.Uint64(b[16:])
	p.Orig = binary.BigEndian.Uint64(b[24:])
	p.Recv = binary.BigEndian.Uint64(b[32:])
	p.Xmit = binary.BigEndian.Uint64(b[40:])
	return p, nil
}

func (p ntpPacket) marshal() []byte {
	b := make([]byte, 48)
	b[0] = p.LI<<6 | p.VN&7<<3 | p.Mode&7
	b[1], b[2], b[3] = p.Stratum, byte(p.Poll), byte(p.Precision)
	binary.BigEndian.PutUint32(b[4:], p.RootDelay)
	binary.BigEndian.PutUint32(b[8:], p.RootDisp)
	copy(b[12:16], p.RefID[:])
	binary.BigEndian.PutUint64(b[16:], p.Ref)
	binary.BigEndian.PutUint64(b[24:], p.Orig)
	binary.BigEndian.PutUint64(b[32:], p.Recv)
	binary.BigEndian.PutUint64(b[40:], p.Xmit)
	return b
}

// ntpTime reads a timestamp.  Seconds with the top bit clear are taken
// to be in era 1 (2036-2104), as RFC 4330 3 suggests.
func ntpTime(ts uint64) time.Time {
	sec := int64(ts >> 32)
	if sec&0x80000000 == 0 {
		sec += 1 << 32
	}
	nsec := int64((ts & 0xffffffff) * 1e9 >> 32)
	return time.Unix(sec+ntpEpoch, nsec)
}

// ntpStamp writes a timestamp (the era is dropped).
func ntpStamp(t time.Time) uint64 {
	sec := uint64(t.Unix()-ntpEpoch) & 0xffffffff
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return sec<<32 | frac
}

// short16 is a 16.16 duration.
func short16(v uint32) time.Duration {
	return time.Duration(int64(v) * int64(time.Second) >> 16)
}

// KissError is a Kiss-o'-Death answer (stratum 0): RATE, DENY, RSTR, ...
type KissError struct{ Code string }

func (k KissError) Error() string { return "kiss-o'-death " + k.Code }

// NTPResult is one server's answer to an SNTP query.  An unsynchronised
// server (leap indicator 3, stratum 16) is an answer, not an error: the
// caller decides what it is worth.
type NTPResult struct {
	Server    string        // as asked
	Addr      string        // the address that answered
	Stratum   int           // 1-16
	Version   int           // 3 or 4
	Leap      int           // 0 none, 1 +1 s, 2 -1 s, 3 not synchronised
	RefID     string        // .GPS. for stratum 1, else an IPv4 address (or a hash for IPv6)
	Offset    time.Duration // the server's clock minus ours
	Delay     time.Duration // round trip, less the server's own time
	Precision time.Duration // the server's clock precision
	RootDelay time.Duration
	RootDisp  time.Duration
	RefTime   time.Time // when the server's clock was last set
}

// Unsynchronised is true when the server says its clock is not to be
// trusted.
func (r *NTPResult) Unsynchronised() bool { return r.Leap == 3 || r.Stratum >= 16 }

var errSpoof = errors.New("origin timestamp does not match (spoofed or stale)")

// checkNTPReply validates a server's answer to the request whose transmit
// timestamp was nonce, sent at t1 and received at t4.  A wrong origin is
// errSpoof: the caller keeps waiting for the real answer.
func checkNTPReply(b []byte, nonce uint64, t1, t4 time.Time) (NTPResult, error) {
	p, err := parseNTP(b)
	if err != nil {
		return NTPResult{}, err
	}
	if p.Orig != nonce {
		return NTPResult{}, errSpoof
	}
	if p.Mode != ntpModeServer {
		return NTPResult{}, fmt.Errorf("mode %d is not a server answer", p.Mode)
	}
	if p.VN < 3 || p.VN > 4 {
		return NTPResult{}, fmt.Errorf("version %d", p.VN)
	}
	if p.Stratum == 0 {
		return NTPResult{}, KissError{Code: kissCode(p.RefID)}
	}
	if p.Xmit == 0 || p.Recv == 0 {
		return NTPResult{}, errors.New("zero timestamp")
	}
	t2, t3 := ntpTime(p.Recv), ntpTime(p.Xmit)
	if t3.Before(t2) {
		return NTPResult{}, errors.New("server sent before it received")
	}
	rtt := t4.Sub(t1)
	if rtt < 0 {
		return NTPResult{}, errors.New("our clock went backwards")
	}
	delay := rtt - t3.Sub(t2)
	if delay < 0 {
		delay = 0
	}
	r := NTPResult{Stratum: int(p.Stratum), Version: int(p.VN), Leap: int(p.LI), RefID: ntpRefID(p),
		Offset: t2.Sub(t1)/2 + t3.Sub(t4)/2, Delay: delay,
		RootDelay: short16(p.RootDelay), RootDisp: short16(p.RootDisp)}
	if r.Stratum > 16 {
		r.Stratum = 16
	}
	if p.Precision > -40 && p.Precision < 8 {
		if p.Precision < 0 {
			r.Precision = time.Second >> uint(-p.Precision)
		} else {
			r.Precision = time.Second << uint(p.Precision)
		}
	}
	if p.Ref != 0 {
		r.RefTime = ntpTime(p.Ref)
	}
	return r, nil
}

func kissCode(r [4]byte) string {
	var b strings.Builder
	for _, c := range r {
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "?"
	}
	return b.String()
}

// ntpRefID is the reference: .CODE. for stratum 1, an address otherwise.
func ntpRefID(p ntpPacket) string {
	if p.Stratum <= 1 {
		return "." + kissCode(p.RefID) + "."
	}
	if p.Stratum >= 16 {
		return "." + kissCode(p.RefID) + "." // INIT, STEP: what it is waiting for
	}
	return net.IP(p.RefID[:]).String()
}

// NTPQuery asks server (a name or an address, port 123 unless given as
// host:port) for the time, once.
func NTPQuery(ctx context.Context, server string, timeout time.Duration) (*NTPResult, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(strings.Trim(server, "[]"), "123")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dl, _ := ctx.Deadline()
	conn.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	// the transmit timestamp is a random nonce: it tells nobody our
	// clock, and an answer must echo it
	var nb [8]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return nil, err
	}
	nonce := binary.BigEndian.Uint64(nb[:]) | 1
	req := ntpPacket{VN: 4, Mode: ntpModeClient, Xmit: nonce}
	t1 := time.Now()
	if _, err := conn.Write(req.marshal()); err != nil {
		return nil, err
	}
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, errors.New("no answer")
			}
			return nil, err
		}
		t4 := time.Now()
		r, err := checkNTPReply(buf[:n], nonce, t1, t4)
		if err == errSpoof || err == errNTPShort {
			continue
		}
		if err != nil {
			return nil, err
		}
		r.Server = server
		if ua, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			r.Addr = ua.IP.String()
		}
		return &r, nil
	}
}
