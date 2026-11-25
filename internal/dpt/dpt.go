// SPDX-License-Identifier: MIT
package dpt

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DPT — Diagnostic Ports Time.  "Is this address working as a network peer", in
// one go: ping it, use it as a DNS resolver, ask it for the time and set
// that against public NTP references; or (DHCP mode) see every DHCP
// server on a segment and what it hands out, then test the DNS and NTP
// servers it names.

// DPT statuses.
const (
	DPTOK   = "OK"
	DPTWarn = "WARN"
	DPTFail = "FAIL"
	DPTNone = "NONE" // the service is not there: reported, not a failure
)

// DPTDefaultNames are the names the DNS test resolves, in order.
var DPTDefaultNames = []string{"google.com", "microsoft.com", "cloudflare.com", "ietf.org", "github.com"}

// DPTDefaultNTP are the reference time servers.
var DPTDefaultNTP = []string{"time.google.com", "time.windows.com"}

// DPTTests is which tests run: none set means all of them.
type DPTTests struct {
	Time, DNS, Ping bool
}

// Or is both sets of tests.
func (t DPTTests) Or(u DPTTests) DPTTests {
	return DPTTests{Time: t.Time || u.Time, DNS: t.DNS || u.DNS, Ping: t.Ping || u.Ping}
}

// Any is true when a test was chosen.
func (t DPTTests) Any() bool { return t.Time || t.DNS || t.Ping }

// Effective is the tests to run: all when none was chosen.
func (t DPTTests) Effective() DPTTests {
	if !t.Any() {
		return DPTTests{Time: true, DNS: true, Ping: true}
	}
	return t
}

// DPTOptions is one run.
type DPTOptions struct {
	Tests   DPTTests      // t, d, p; none: all
	Count   int           // pings and DNS lookups; 0: 5
	Timeout time.Duration // per operation; 0: 2 s
	Names   []string      // nil: DPTDefaultNames
	NTP     []string      // nil: DPTDefaultNTP
	Family  int           // 4, 6 or 0 for both
	All     bool          // test every address a name gives, not the first
	// Interval between pings; 0: 1 s
	Interval time.Duration
	// Resolver for the target name and refids; nil: the system's.
	Resolver *net.Resolver
	// Live shows what is running while it runs; nil: nothing.
	Live *Live
	// OnTarget and OnSection, when set, get the target once it is
	// resolved and each section of each address as soon as it is done,
	// in the order of DPTSections.
	OnTarget  func(t DPTTarget)
	OnSection func(a *DPTAddrReport, section string)
}

func (o *DPTOptions) defaults() {
	if o.Count <= 0 {
		o.Count = 5
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if len(o.Names) == 0 {
		o.Names = DPTDefaultNames
	}
	if len(o.NTP) == 0 {
		o.NTP = DPTDefaultNTP
	}
	if o.Interval <= 0 {
		o.Interval = time.Second
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
}

// Ms is a duration in milliseconds, as JSON carries it.
type Ms float64

func ms(d time.Duration) Ms { return Ms(math.Round(float64(d)/1e3) / 1e3) }

// DPTTarget is what was asked and what it resolved to.
type DPTTarget struct {
	Input     string   `json:"input"`
	Addresses []string `json:"addresses"`
	Tested    []string `json:"tested"`
}

// DPTPingRow is one echo.
type DPTPingRow struct {
	Seq   int    `json:"seq"`
	OK    bool   `json:"ok"`
	RTT   Ms     `json:"rtt_ms,omitempty"`
	TTL   int    `json:"ttl,omitempty"`
	Error string `json:"error,omitempty"`
}

// DPTPing is the ping section.
type DPTPing struct {
	Rows     []DPTPingRow `json:"replies"`
	Sent     int          `json:"sent"`
	Received int          `json:"received"`
	Loss     float64      `json:"loss_pct"`
	Min      Ms           `json:"min_ms"`
	Avg      Ms           `json:"avg_ms"`
	Max      Ms           `json:"max_ms"`
	StdDev   Ms           `json:"stddev_ms"`
	Error    string       `json:"error,omitempty"`
	Status   string       `json:"status"`
}

// DPTDNSRow is one lookup against the target.
type DPTDNSRow struct {
	Name    string   `json:"name"`
	Rcode   string   `json:"rcode,omitempty"`
	Answers []string `json:"answers,omitempty"`
	Time    Ms       `json:"time_ms,omitempty"`
	Flags   []string `json:"flags,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// DPTDNS is the DNS section.
type DPTDNS struct {
	Server    string      `json:"server"`
	Rows      []DPTDNSRow `json:"queries"`
	Answered  int         `json:"answered"`
	Avg       Ms          `json:"avg_ms"`
	NoService bool        `json:"no_service"`
	Recursion bool        `json:"recursion"`
	DNSSEC    bool        `json:"dnssec_validation"`
	EDNS0     bool        `json:"edns0"`
	EDNSSize  int         `json:"edns_udp_size,omitempty"`
	Status    string      `json:"status"`
}

// DPTTimeRow is one NTP server's answer.
type DPTTimeRow struct {
	Server    string `json:"server"`
	Role      string `json:"role"` // reference, target, dhcp, system (info: the machine's own server)
	Addr      string `json:"address,omitempty"`
	OK        bool   `json:"ok"`
	Offset    Ms     `json:"offset_ms"`
	Delay     Ms     `json:"delay_ms"`
	Stratum   int    `json:"stratum,omitempty"`
	RefID     string `json:"refid,omitempty"`
	RefName   string `json:"refid_name,omitempty"`
	Leap      int    `json:"leap"`
	Precision Ms     `json:"precision_ms"`
	RootDisp  Ms     `json:"root_dispersion_ms"`
	VsRef     Ms     `json:"vs_reference_ms"`
	Error     string `json:"error,omitempty"`
	NoService bool   `json:"no_service,omitempty"`
}

// DPTTime is the time section.
type DPTTime struct {
	Rows          []DPTTimeRow `json:"servers"`
	Reference     string       `json:"reference,omitempty"`
	MaxDivergence Ms           `json:"max_divergence_ms"`
	DivStatus     string       `json:"divergence_status,omitempty"`
	// LocalOffset is this machine's clock minus the reference servers'
	// (their median): negative is behind.  LocalStatus judges it with the
	// same limits; Status is the worse of the two.
	LocalOffset Ms     `json:"local_clock_offset_ms"`
	LocalStatus string `json:"local_clock_status,omitempty"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
}

// DPTFeatures is what the address offers.
type DPTFeatures struct {
	ICMP      bool `json:"icmp"`
	DNSUDP    bool `json:"dns_udp"`
	DNSTCP    bool `json:"dns_tcp"`
	Recursion bool `json:"recursion"`
	EDNS0     bool `json:"edns0"`
	EDNSSize  int  `json:"edns_udp_size,omitempty"`
	DNSSEC    bool `json:"dnssec_validation"`
	DoT       bool `json:"dns_over_tls"`
	NTP       bool `json:"ntp"`
	Stratum   int  `json:"ntp_stratum,omitempty"`
	Whois     bool `json:"whois"` // a whois server on TCP 43
	RDAP      bool `json:"rdap"`  // an RDAP server on HTTPS 443
	LDAP      bool `json:"ldap"`  // LDAP on TCP 389
	LDAPS     bool `json:"ldaps"` // LDAP over TLS on TCP 636
}

// DPTAddrReport is every section for one address.
type DPTAddrReport struct {
	Address  string       `json:"address"`
	Ping     *DPTPing     `json:"ping,omitempty"`
	DNS      *DPTDNS      `json:"dns,omitempty"`
	Time     *DPTTime     `json:"time,omitempty"`
	Features *DPTFeatures `json:"features,omitempty"` // only when all three ran
}

// DPTReport is one dpt run against an address or a name.
type DPTReport struct {
	Target  DPTTarget       `json:"target"`
	Results []DPTAddrReport `json:"results"`
	Started time.Time       `json:"started"`
}

// Failed is true when any test failed (exit code 1).
func (r *DPTReport) Failed() bool {
	for _, a := range r.Results {
		if a.Ping != nil && a.Ping.Status == DPTFail || a.DNS != nil && a.DNS.Status == DPTFail || a.Time != nil && a.Time.Status == DPTFail {
			return true
		}
	}
	return false
}

// DPTResolve gives the addresses of target: itself when it is one.
func DPTResolve(ctx context.Context, target string, family int, r *net.Resolver) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
		return []net.IP{ip}, nil
	}
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupIPAddr(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s", Safe(target))
	}
	var out []net.IP
	for _, a := range addrs {
		v4 := a.IP.To4() != nil
		if family == 4 && !v4 || family == 6 && v4 {
			continue
		}
		out = append(out, a.IP)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("cannot resolve %s (no IPv%d address)", Safe(target), family)
	}
	return out, nil
}

// RunDPT runs the whole test against target.
func RunDPT(ctx context.Context, target string, o DPTOptions) (*DPTReport, error) {
	o.defaults()
	rep := &DPTReport{Target: DPTTarget{Input: target}, Started: time.Now()}
	look, cancel := context.WithTimeout(ctx, o.Timeout*2)
	ips, err := DPTResolve(look, target, o.Family, o.Resolver)
	cancel()
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		rep.Target.Addresses = append(rep.Target.Addresses, ip.String())
	}
	if !o.All {
		ips = ips[:1]
	}
	for _, ip := range ips {
		rep.Target.Tested = append(rep.Target.Tested, ip.String())
	}
	if o.OnTarget != nil {
		o.OnTarget(rep.Target)
	}
	rep.Results = make([]DPTAddrReport, len(ips))
	name := "" // a name, not an address: RDAP may be served under it only
	if net.ParseIP(strings.Trim(target, "[]")) == nil {
		name = strings.TrimSuffix(target, ".")
	}
	for i, ip := range ips {
		runDPTAddr(ctx, ip, name, o, &rep.Results[i])
	}
	return rep, nil
}

func runDPTAddr(ctx context.Context, ip net.IP, name string, o DPTOptions, a *DPTAddrReport) {
	*a = DPTAddrReport{Address: ip.String()}
	emit := func(sec string) {
		if o.OnSection != nil {
			o.OnSection(a, sec)
		}
	}
	emit("ADDRESS")
	t := o.Tests.Effective()
	// all three run at once (the ping takes count seconds); the sections
	// are written in their order as each is done
	ping, dns, tm := make(chan DPTPing, 1), make(chan DPTDNS, 1), make(chan DPTTime, 1)
	if t.Ping {
		go func() { ping <- DPTPingRun(ctx, ip, o) }()
	}
	if t.DNS {
		go func() { dns <- DPTDNSRun(ctx, ip.String(), o) }()
	}
	if t.Time {
		go func() { tm <- DPTTimeRun(ctx, []DPTTimeAsk{{Server: ip.String(), Role: "target"}}, o) }()
	}
	if t.Ping {
		p := <-ping
		a.Ping = &p
		emit("PING")
	}
	if t.DNS {
		d := <-dns
		a.DNS = &d
		emit("DNS")
	}
	if t.Time {
		x := <-tm
		a.Time = &x
		emit("TIME")
	}
	if t.Ping && t.DNS && t.Time {
		o.Live.Set("features", "features of "+ip.String())
		f := dptFeatures(ctx, ip, name, o, a)
		o.Live.Drop("features")
		a.Features = &f
		emit("FEATURES")
	}
}

// DPTPingRun sends o.Count echoes to ip, one per o.Interval.
func DPTPingRun(ctx context.Context, ip net.IP, o DPTOptions) DPTPing {
	o.defaults()
	p := DPTPing{}
	c, err := OpenICMP(ip)
	if err != nil {
		p.Error, p.Status = err.Error(), DPTFail
		return p
	}
	defer c.Close()
	defer o.Live.Drop("ping")
	var replies []EchoReply
	for i := 1; i <= o.Count; i++ {
		if ctx.Err() != nil {
			break
		}
		o.Live.Set("ping", fmt.Sprintf("ping %d/%d", i, o.Count))
		start := time.Now()
		r, err := c.Echo(i, o.Timeout)
		p.Sent++
		row := DPTPingRow{Seq: i}
		if err != nil {
			row.Error = err.Error()
		} else {
			row.OK, row.RTT, row.TTL = true, ms(r.RTT), r.TTL
			replies = append(replies, r)
		}
		p.Rows = append(p.Rows, row)
		if i < o.Count {
			select {
			case <-ctx.Done():
			case <-time.After(o.Interval - time.Since(start)):
			}
		}
	}
	s := PingSummary(p.Sent, replies)
	p.Received, p.Loss = s.Received, s.Loss
	p.Min, p.Avg, p.Max, p.StdDev = ms(s.Min), ms(s.Avg), ms(s.Max), ms(s.StdDev)
	switch {
	case p.Received == 0:
		p.Status = DPTFail
	case p.Received < p.Sent:
		p.Status = DPTWarn
	default:
		p.Status = DPTOK
	}
	return p
}

// DPTDNSRun asks server o.Count questions, wrapping round o.Names.
func DPTDNSRun(ctx context.Context, server string, o DPTOptions) DPTDNS {
	o.defaults()
	d := DPTDNS{Server: server}
	addr := DNSServerAddr(server, 53)
	var total time.Duration
	noAnswer := 0
	defer o.Live.Drop("dns")
	for i := 0; i < o.Count && ctx.Err() == nil; i++ {
		o.Live.Set("dns", fmt.Sprintf("dns %d/%d", i+1, o.Count))
		name := o.Names[i%len(o.Names)]
		row := DPTDNSRow{Name: name}
		a, err := DNSAsk(ctx, addr, name, DNSAskOptions{Type: DNSTypeA}, o.Timeout)
		if err != nil {
			row.Error = err.Error()
			noAnswer++
			d.Rows = append(d.Rows, row)
			// nobody there: one silence is enough to know
			if i == 0 {
				if _, err := DNSAsk(ctx, addr, name, DNSAskOptions{Type: DNSTypeA, TCP: true}, o.Timeout); err != nil {
					d.NoService, d.Status = true, DPTNone
					return d
				}
			}
			continue
		}
		row.Rcode, row.Time = a.RcodeName(), ms(a.Time)
		total += a.Time
		for _, f := range []struct {
			on bool
			n  string
		}{{a.AA, "AA"}, {a.RA, "RA"}, {a.AD, "AD"}, {a.TC, "TC"}} {
			if f.on {
				row.Flags = append(row.Flags, f.n)
			}
		}
		for _, r := range a.Answer {
			row.Answers = append(row.Answers, DNSTypeString(r.Type)+" "+Safe(DNSFormatRData(r.Type, r.Data)))
		}
		if a.Rcode == dnsNoError {
			d.Answered++
		}
		d.Rows = append(d.Rows, row)
	}
	if n := len(d.Rows) - noAnswer; n > 0 {
		d.Avg = ms(total / time.Duration(n))
		for _, r := range d.Rows {
			for _, f := range r.Flags {
				if f == "RA" {
					d.Recursion = true
				}
			}
		}
		// a signed name, with DO: AD set means the resolver validated
		if ans, err := DNSAsk(ctx, addr, "ietf.org", DNSAskOptions{DO: true}, o.Timeout); err == nil {
			d.EDNS0, d.EDNSSize, d.DNSSEC = ans.EDNS, int(ans.EDNSSize), ans.AD
			d.Recursion = d.Recursion || ans.RA
		}
	}
	switch {
	case d.Answered == len(d.Rows) && d.Answered > 0:
		d.Status = DPTOK
	case d.Answered == 0 && noAnswer == len(d.Rows):
		d.Status = DPTFail
	default:
		d.Status = DPTWarn
	}
	return d
}

// DPTTimeAsk is one server for DPTTimeRun besides the references.
type DPTTimeAsk struct {
	Server string
	Role   string // target, dhcp
}

// Time thresholds: divergence up to 50 ms is OK, up to 1 s WARN.
const (
	DPTTimeOK   = 50 * time.Millisecond
	DPTTimeWarn = time.Second
)

// DPTTimeRun queries the references and extra, all at once, and compares
// each with the first reference that answered.
func DPTTimeRun(ctx context.Context, extra []DPTTimeAsk, o DPTOptions) DPTTime {
	o.defaults()
	asks := make([]DPTTimeAsk, 0, len(o.NTP)+len(extra))
	for _, s := range o.NTP {
		asks = append(asks, DPTTimeAsk{Server: s, Role: "reference"})
	}
	asks = append(asks, extra...)
	rows := make([]DPTTimeRow, len(asks))
	results := make([]*NTPResult, len(asks))
	var wg sync.WaitGroup
	var mu sync.Mutex
	answered := 0
	o.Live.Set("time", fmt.Sprintf("time 0/%d", len(asks)))
	defer o.Live.Drop("time")
	for i, a := range asks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				answered++
				o.Live.Set("time", fmt.Sprintf("time %d/%d", answered, len(asks)))
				mu.Unlock()
			}()
			row := DPTTimeRow{Server: a.Server, Role: a.Role}
			r, err := NTPQuery(ctx, a.Server, o.Timeout)
			if err != nil {
				row.Error = err.Error()
				if err.Error() == "no answer" || strings.Contains(err.Error(), "refused") {
					row.NoService = true
				}
			} else {
				results[i] = r
				row.OK, row.Addr = true, r.Addr
				row.Offset, row.Delay, row.Stratum, row.RefID = ms(r.Offset), ms(r.Delay), r.Stratum, r.RefID
				row.Leap, row.Precision, row.RootDisp = r.Leap, ms(r.Precision), ms(r.RootDisp)
				if ip := net.ParseIP(r.RefID); ip != nil && r.Stratum > 1 && r.Stratum < 16 {
					c, cancel := context.WithTimeout(ctx, time.Second)
					if names, err := o.Resolver.LookupAddr(c, r.RefID); err == nil && len(names) > 0 {
						row.RefName = Safe(strings.TrimSuffix(names[0], "."))
					}
					cancel()
				}
			}
			rows[i] = row
		}()
	}
	wg.Wait()
	t := DPTTime{Rows: rows, Status: DPTOK}
	ref := -1
	for i, a := range asks {
		if a.Role == "reference" && results[i] != nil {
			ref = i
			break
		}
	}
	if ref < 0 {
		t.Status, t.Reason = DPTWarn, "no reference server answered"
		// still flag an unsynchronised server
		for i := range rows {
			if results[i] != nil && results[i].Unsynchronised() {
				t.Status, t.Reason = DPTFail, rows[i].Server+" is not synchronised"
			}
		}
		return t
	}
	t.Reference = asks[ref].Server
	lo, hi := time.Duration(math.MaxInt64), time.Duration(math.MinInt64)
	for i := range rows {
		r := results[i]
		if r == nil {
			continue
		}
		rows[i].VsRef = ms(r.Offset - results[ref].Offset)
		lo, hi = min(lo, r.Offset), max(hi, r.Offset)
		if r.Unsynchronised() {
			t.Status, t.Reason = DPTFail, rows[i].Server+" is not synchronised (leap indicator 3)"
		}
	}
	div := hi - lo
	t.MaxDivergence = ms(div)
	if t.Status != DPTFail {
		switch {
		case div > DPTTimeWarn:
			t.Status, t.Reason = DPTFail, "more than 1 s apart"
		case div > DPTTimeOK:
			t.Status, t.Reason = DPTWarn, "more than 50 ms apart"
		}
	}
	t.DivStatus = t.Status
	// this machine's clock against the references that are synchronised:
	// a drifting clock is what makes JWTs fail
	var offs []time.Duration
	for i, a := range asks {
		if a.Role == "reference" && results[i] != nil && !results[i].Unsynchronised() {
			offs = append(offs, results[i].Offset)
		}
	}
	if len(offs) > 0 {
		local := -dptMedian(offs) // the servers' offset is theirs minus ours
		t.LocalOffset = ms(local)
		abs := local
		if abs < 0 {
			abs = -abs
		}
		t.LocalStatus = DPTOK
		switch {
		case abs > DPTTimeWarn:
			t.LocalStatus = DPTFail
		case abs > DPTTimeOK:
			t.LocalStatus = DPTWarn
		}
		if dptRank(t.LocalStatus) > dptRank(t.Status) {
			t.Status, t.Reason = t.LocalStatus, "this clock is "+dptLocalWords(t.LocalOffset)
		}
	}
	return t
}

func dptMedian(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return s[n/2-1]/2 + s[n/2]/2
}

func dptRank(s string) int {
	switch s {
	case DPTFail:
		return 2
	case DPTWarn:
		return 1
	}
	return 0
}

// dptLocalWords: "52.6 ms behind" / "1.2 ms ahead".
func dptLocalWords(v Ms) string {
	if v < 0 {
		return fms(-v) + " ms behind"
	}
	return fms(v) + " ms ahead"
}

func dptFeatures(ctx context.Context, ip net.IP, name string, o DPTOptions, a *DPTAddrReport) DPTFeatures {
	f := DPTFeatures{ICMP: a.Ping.Received > 0}
	d := a.DNS
	if !d.NoService {
		for _, r := range d.Rows {
			if r.Error == "" {
				f.DNSUDP = true
			}
		}
		f.Recursion, f.DNSSEC, f.EDNS0, f.EDNSSize = d.Recursion, d.DNSSEC, d.EDNS0, d.EDNSSize
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := DNSServerAddr(ip.String(), 53)
			if ans, err := DNSAsk(ctx, addr, o.Names[0], DNSAskOptions{TCP: true}, o.Timeout); err == nil && ans.Network == "tcp" {
				f.DNSTCP = true
			}
		}()
		f.DoT = dptDoT(ctx, ip, o.Timeout)
		wg.Wait()
	} else {
		f.DoT = dptDoT(ctx, ip, o.Timeout)
	}
	for _, r := range a.Time.Rows {
		if r.Role == "target" && r.OK {
			f.NTP, f.Stratum = true, r.Stratum
		}
	}
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); f.Whois = dptWhoisServer(ctx, ip, o.Timeout) }()
	go func() { defer wg.Done(); f.RDAP = dptRDAPServer(ctx, ip, name, o.Timeout) }()
	go func() { defer wg.Done(); f.LDAP = dptLDAPServer(ctx, ip, false, o.Timeout) }()
	go func() { defer wg.Done(); f.LDAPS = dptLDAPServer(ctx, ip, true, o.Timeout) }()
	wg.Wait()
	return f
}

// dptWhoisServer says whether ip answers whois on TCP 43: asked for
// "help", it sends text back.
func dptWhoisServer(ctx context.Context, ip net.IP, timeout time.Duration) bool {
	t, err := whoisTCP(ctx, net.JoinHostPort(ip.String(), "43"), "help", WhoisOptions{Timeout: timeout})
	return err == nil && strings.TrimSpace(t) != ""
}

// ldapAnonBind is an LDAP anonymous simple bind (RFC 4511): message 1,
// version 3, no name, no password.  It reads nothing from the directory.
var ldapAnonBind = []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}

// dptLDAPServer says whether ip answers LDAP on TCP 389 (tls: LDAPS on
// 636): an anonymous bind gets a BindResponse back, whether the server
// allows anonymous binds or not.  The certificate is not checked.
func dptLDAPServer(ctx context.Context, ip net.IP, tlsOn bool, timeout time.Duration) bool {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var conn net.Conn
	var err error
	if tlsOn {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
		conn, err = d.DialContext(c, "tcp", net.JoinHostPort(ip.String(), "636"))
	} else {
		conn, err = (&net.Dialer{Timeout: timeout}).DialContext(c, "tcp", net.JoinHostPort(ip.String(), "389"))
	}
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(ldapAnonBind); err != nil {
		return false
	}
	b := make([]byte, 64)
	n, _ := io.ReadAtLeast(conn, b, 8)
	return isLDAPBindResponse(b[:n])
}

// isLDAPBindResponse: a SEQUENCE holding message ID 1 and a BindResponse
// ([APPLICATION 1], 0x61).
func isLDAPBindResponse(b []byte) bool {
	if len(b) < 8 || b[0] != 0x30 {
		return false
	}
	i := 2
	if b[1]&0x80 != 0 { // a long length
		i += int(b[1] & 0x7f)
	}
	return i+3 < len(b) && b[i] == 0x02 && b[i+1] == 0x01 && b[i+2] == 0x01 && b[i+3] == 0x61
}

// dptRDAPServer says whether ip answers RDAP on HTTPS 443: its help (at
// /help, or under /rdap/ or /registry/, where registries put it) is
// RDAP's JSON.  Asked under name where there is one (a server may serve
// RDAP under its name only), always at ip.  The certificate is not
// checked: the test is whether RDAP answers, not whose it is.
func dptRDAPServer(ctx context.Context, ip net.IP, name string, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip.String(), "443")
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, ServerName: name},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: timeout}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	host := name
	if host == "" {
		host = addr
	}
	base := "https://" + host
	for _, p := range []string{"/help", "/rdap/help", "/registry/help"} {
		resp, b, err := whoisGet(ctx, cl, base+p, "")
		if err != nil {
			return false // no HTTPS at all: no need to try the other paths
		}
		if resp.StatusCode == 200 && (strings.Contains(resp.Header.Get("Content-Type"), "rdap") ||
			strings.Contains(string(b), `"rdapConformance"`)) {
			return true
		}
	}
	return false
}

// dptDoT is a TLS handshake on TCP 853.  The certificate is not checked:
// an address has no name to check it against; the handshake is the test.
func dptDoT(ctx context.Context, ip net.IP, timeout time.Duration) bool {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(c, "tcp", net.JoinHostPort(ip.String(), "853"))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ------------------------------------------------------------- DHCP mode

// DPTDHCPServer is one server's offer, as dpt shows it.
type DPTDHCPServer struct {
	ServerID  string            `json:"server_id,omitempty"`
	SourceIP  string            `json:"source_ip"`
	SourceMAC string            `json:"source_mac,omitempty"`
	Relay     string            `json:"relay,omitempty"`
	Offered   string            `json:"offered"`
	Mask      string            `json:"mask,omitempty"`
	Router    string            `json:"router,omitempty"`
	Broadcast string            `json:"broadcast,omitempty"`
	Lease     string            `json:"lease,omitempty"`
	T1        string            `json:"t1,omitempty"`
	T2        string            `json:"t2,omitempty"`
	DNS       []string          `json:"dns,omitempty"`
	Domain    string            `json:"domain,omitempty"`
	Search    string            `json:"search,omitempty"`
	NTP       []string          `json:"ntp,omitempty"`
	TimeSrv   []string          `json:"time_servers,omitempty"`
	TimeOff   string            `json:"time_offset,omitempty"`
	TZPOSIX   string            `json:"tz_posix,omitempty"`
	TZName    string            `json:"tz_database,omitempty"`
	Routes    string            `json:"classless_routes,omitempty"`
	MTU       string            `json:"mtu,omitempty"`
	Hostname  string            `json:"hostname,omitempty"`
	NextSrv   string            `json:"next_server,omitempty"`
	SName     string            `json:"sname,omitempty"`
	File      string            `json:"file,omitempty"`
	TFTP      string            `json:"tftp_server,omitempty"`
	BootFile  string            `json:"boot_file,omitempty"`
	TFTPList  string            `json:"tftp_servers,omitempty"`
	WPAD      string            `json:"wpad,omitempty"`
	Vendor    string            `json:"vendor_hex,omitempty"`
	Other     map[string]string `json:"other,omitempty"`
	After     Ms                `json:"after_ms"`
}

// DPTDHCPCheck is one DNS server an offer named, tested.
type DPTDHCPCheck struct {
	Server string `json:"server"`
	OK     bool   `json:"ok"`
	Rcode  string `json:"rcode,omitempty"`
	Time   Ms     `json:"time_ms,omitempty"`
	Error  string `json:"error,omitempty"`
}

// DPTDHCPReport is a DHCP-mode run.
type DPTDHCPReport struct {
	Iface    string          `json:"interface"`
	MAC      string          `json:"client_mac"`
	Listen   Ms              `json:"listen_ms"`
	Servers  []DPTDHCPServer `json:"servers"`
	Multiple bool            `json:"multiple_servers"`
	Note     string          `json:"note,omitempty"`
	// VPN names the VPN tunnels that are up: the system may send the
	// probe's answers, or the probe itself, through one
	VPN      []string       `json:"vpn_tunnel,omitempty"`
	DNS      []DPTDHCPCheck `json:"dns,omitempty"`
	DNSState string         `json:"dns_status,omitempty"`
	Time     *DPTTime       `json:"time,omitempty"`
	Status   string         `json:"status"`
	Started  time.Time      `json:"started"`
}

// Failed is true when a test failed (exit code 1).
func (r *DPTDHCPReport) Failed() bool {
	return r.Status == DPTFail || r.DNSState == DPTFail || r.Time != nil && r.Time.Status == DPTFail
}

// DPTDHCPOptions is a DHCP-mode run.
type DPTDHCPOptions struct {
	DPTOptions
	Iface     string
	RandomMAC bool
	Listen    time.Duration
	// OnDHCPSection, when set, gets each section as soon as it is done,
	// in the order of DPTDHCPSections.
	OnDHCPSection func(r *DPTDHCPReport, section string)
}

// DPTDefaultIface is the interface a DHCP probe goes out of when none is
// named: up, not a loopback, an Ethernet address and a real IPv4 address
// (not 169.254); of those, one with an IPv4 default gateway first.  A VPN
// tunnel has no Ethernet address, so it is never chosen.
func DPTDefaultIface() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var cands []net.Interface
	for _, i := range ifs {
		if dptProbeable(i) {
			cands = append(cands, i)
		}
	}
	if len(cands) == 0 {
		return "", errors.New("no active Ethernet interface with an IPv4 address")
	}
	gw := gatewayIfaces()
	for _, i := range cands {
		if gw[i.Index] {
			return i.Name, nil
		}
	}
	return cands[0].Name, nil
}

// DPTVPNTunnels names the interfaces that look like a VPN tunnel that is
// up: up, not a loopback, no Ethernet address, and a real IPv4 address
// (macOS's idle utun0-2 have only IPv6 link-local addresses).
func DPTVPNTunnels() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 6 {
			continue
		}
		if dptHasIPv4(i) {
			out = append(out, i.Name)
		}
	}
	return out
}

func dptHasIPv4(i net.Interface) bool {
	addrs, _ := i.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if v4 := n.IP.To4(); v4 != nil && !v4.IsLinkLocalUnicast() && !v4.IsLoopback() {
				return true
			}
		}
	}
	return false
}

// gatewayIfaces: the interfaces (by index) with an IPv4 default gateway.
func gatewayIfaces() map[int]bool {
	out := map[int]bool{}
	for i := range gateways() {
		out[i] = true
	}
	return out
}

func dptProbeable(i net.Interface) bool {
	if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 {
		return false
	}
	return dptHasIPv4(i)
}

// RunDPTDHCP probes the segment and tests what the offers name.
func RunDPTDHCP(ctx context.Context, o DPTDHCPOptions) (*DPTDHCPReport, error) {
	o.defaults()
	if o.Iface == "" {
		i, err := DPTDefaultIface()
		if err != nil {
			return nil, err
		}
		o.Iface = i
	}
	if o.Listen <= 0 {
		o.Listen = 5 * time.Second
	}
	var mac net.HardwareAddr
	if o.RandomMAC {
		mac = DHCPRandomMAC()
	} else if ifi, err := net.InterfaceByName(o.Iface); err == nil {
		mac = ifi.HardwareAddr
	}
	rep := &DPTDHCPReport{Iface: o.Iface, MAC: mac.String(), Listen: ms(o.Listen), Started: time.Now(), VPN: DPTVPNTunnels()}
	emit := func(sec string) {
		if o.OnDHCPSection != nil {
			o.OnDHCPSection(rep, sec)
		}
	}
	listening, stopped := make(chan struct{}), make(chan struct{})
	if o.Live == nil {
		close(stopped)
	} else {
		go func() {
			defer close(stopped)
			start := time.Now()
			t := time.NewTicker(250 * time.Millisecond)
			defer t.Stop()
			for {
				left := (o.Listen - time.Since(start) + time.Second - 1) / time.Second
				o.Live.Set("dhcp", fmt.Sprintf("dhcp: listening for offers on %s, %d s to go", o.Iface, max(left, 1)))
				select {
				case <-listening:
					o.Live.Drop("dhcp")
					return
				case <-t.C:
				}
			}
		}()
	}
	offers, err := DHCPProbe(ctx, DHCPProbeOptions{Iface: o.Iface, MAC: mac, Listen: o.Listen})
	close(listening)
	<-stopped
	if err != nil {
		return nil, err
	}
	dns, ntp := []string{}, []string{}
	seen := map[string]bool{}
	for _, of := range offers {
		s := dptDHCPServer(of)
		rep.Servers = append(rep.Servers, s)
		for _, d := range s.DNS {
			if !seen["d"+d] {
				seen["d"+d] = true
				dns = append(dns, d)
			}
		}
		for _, n := range s.NTP {
			if !seen["n"+n] {
				seen["n"+n] = true
				ntp = append(ntp, n)
			}
		}
	}
	rep.Multiple = len(rep.Servers) > 1
	switch {
	case len(rep.Servers) == 0:
		rep.Status, rep.Note = DPTWarn, "no DHCP offers on "+o.Iface
		if DHCPProbeNote != "" {
			rep.Note += ": " + DHCPProbeNote
		} else {
			rep.Note += " (a switch port with DHCP snooping or port security may drop a probe from another MAC)"
		}
	case rep.Multiple:
		rep.Status = DPTWarn
	default:
		rep.Status = DPTOK
	}
	emit("DHCP")
	tests := o.Tests.Effective()
	if !tests.DNS {
		dns = nil
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	asked := 0
	if len(dns) > 0 {
		o.Live.Set("dns", fmt.Sprintf("dns 0/%d servers", len(dns)))
	}
	rep.DNS = make([]DPTDHCPCheck, len(dns))
	for i, d := range dns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				asked++
				o.Live.Set("dns", fmt.Sprintf("dns %d/%d servers", asked, len(dns)))
				mu.Unlock()
			}()
			c := DPTDHCPCheck{Server: d}
			a, err := DNSAsk(ctx, DNSServerAddr(d, 53), o.Names[0], DNSAskOptions{}, o.Timeout)
			if err != nil {
				c.Error = err.Error()
			} else {
				c.OK, c.Rcode, c.Time = a.Rcode == dnsNoError, a.RcodeName(), ms(a.Time)
			}
			rep.DNS[i] = c
		}()
	}
	var extra []DPTTimeAsk
	for _, n := range ntp {
		extra = append(extra, DPTTimeAsk{Server: n, Role: "dhcp"})
	}
	tmc := make(chan DPTTime, 1)
	if tests.Time {
		go func() { tmc <- DPTTimeRun(ctx, extra, o.DPTOptions) }()
	}
	wg.Wait()
	o.Live.Drop("dns")
	if tests.DNS {
		rep.DNSState = DPTOK
		if len(dns) == 0 {
			rep.DNSState = DPTNone
		}
		for _, c := range rep.DNS {
			if !c.OK {
				rep.DNSState = DPTFail
			}
		}
	} else {
		rep.DNS = nil
	}
	emit("DNS")
	if tests.Time {
		tm := <-tmc
		rep.Time = &tm
	}
	if rep.Time != nil {
		for _, r := range rep.Time.Rows {
			if r.Role == "dhcp" && !r.OK {
				rep.Time.Status, rep.Time.Reason = DPTFail, r.Server+" (from DHCP) does not answer"
			}
		}
	}
	emit("TIME")
	return rep, nil
}

func dptDHCPServer(of DHCPOfferSeen) DPTDHCPServer {
	m := of.Msg
	s := DPTDHCPServer{SourceIP: of.SrcIP.String(), Offered: m.YIAddr.String(), After: ms(of.After), SName: of.SName, File: of.File}
	if of.SrcMAC != nil {
		s.SourceMAC = of.SrcMAC.String()
	}
	if g := m.GIAddr; g != nil && !g.IsUnspecified() {
		s.Relay = g.String()
	}
	if n := m.SIAddr; n != nil && !n.IsUnspecified() {
		s.NextSrv = n.String()
	}
	ipList := func(d []byte) []string {
		var out []string
		for i := 0; i+4 <= len(d); i += 4 {
			out = append(out, net.IP(d[i:i+4]).String())
		}
		return out
	}
	for _, op := range of.Options {
		v := Safe(DHCPOptionValue(op.Code, op.Data))
		switch op.Code {
		case 53:
		case 54:
			s.ServerID = v
		case 1:
			s.Mask = v
		case 3:
			s.Router = v
		case 28:
			s.Broadcast = v
		case 51:
			s.Lease = v
		case 58:
			s.T1 = v
		case 59:
			s.T2 = v
		case 6:
			s.DNS = ipList(op.Data)
		case 15:
			s.Domain = v
		case 119:
			s.Search = v
		case 42:
			s.NTP = ipList(op.Data)
		case 4:
			s.TimeSrv = ipList(op.Data)
		case 2:
			s.TimeOff = v
		case 100:
			s.TZPOSIX = v
		case 101:
			s.TZName = v
		case 121:
			s.Routes = v
		case 26:
			s.MTU = v
		case 12:
			s.Hostname = v
		case 66:
			s.TFTP = v
		case 67:
			s.BootFile = v
		case 150:
			s.TFTPList = v
		case 252:
			s.WPAD = v
		case 43:
			s.Vendor = fmt.Sprintf("%x", op.Data)
		default:
			if s.Other == nil {
				s.Other = map[string]string{}
			}
			s.Other[strconv.Itoa(int(op.Code))] = fmt.Sprintf("%x", op.Data)
		}
	}
	return s
}
