// SPDX-License-Identifier: MIT
package dpt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dpt — DNS Ping Time.  "Is this address working as a network peer", in
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
	Role      string `json:"role"` // reference, target, dhcp
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
	Status        string       `json:"status"`
	Reason        string       `json:"reason,omitempty"`
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
		rep.Results = append(rep.Results, runDPTAddr(ctx, ip, o))
	}
	return rep, nil
}

func runDPTAddr(ctx context.Context, ip net.IP, o DPTOptions) DPTAddrReport {
	a := DPTAddrReport{Address: ip.String()}
	t := o.Tests.Effective()
	var wg sync.WaitGroup
	// the ping takes count seconds: the rest runs meanwhile
	if t.Ping {
		wg.Add(1)
		go func() { defer wg.Done(); p := DPTPingRun(ctx, ip, o); a.Ping = &p }()
	}
	if t.DNS {
		wg.Add(1)
		go func() { defer wg.Done(); d := DPTDNSRun(ctx, ip.String(), o); a.DNS = &d }()
	}
	if t.Time {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm := DPTTimeRun(ctx, []DPTTimeAsk{{Server: ip.String(), Role: "target"}}, o)
			a.Time = &tm
		}()
	}
	wg.Wait()
	if t.Ping && t.DNS && t.Time {
		f := dptFeatures(ctx, ip, o, &a)
		a.Features = &f
	}
	return a
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
	var replies []EchoReply
	for i := 1; i <= o.Count; i++ {
		if ctx.Err() != nil {
			break
		}
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
	for i := 0; i < o.Count && ctx.Err() == nil; i++ {
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
	for i, a := range asks {
		wg.Add(1)
		go func() {
			defer wg.Done()
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
	return t
}

func dptFeatures(ctx context.Context, ip net.IP, o DPTOptions, a *DPTAddrReport) DPTFeatures {
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
	return f
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
	DNS      []DPTDHCPCheck  `json:"dns,omitempty"`
	DNSState string          `json:"dns_status,omitempty"`
	Time     *DPTTime        `json:"time,omitempty"`
	Status   string          `json:"status"`
	Started  time.Time       `json:"started"`
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
}

// DPTDefaultIface is the first interface that is up, not a loopback and
// has an Ethernet address.
func DPTDefaultIface() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 && len(i.HardwareAddr) == 6 {
			if addrs, _ := i.Addrs(); len(addrs) > 0 {
				return i.Name, nil
			}
		}
	}
	return "", errors.New("no active network interface")
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
		o.Listen = 3 * time.Second
	}
	var mac net.HardwareAddr
	if o.RandomMAC {
		mac = DHCPRandomMAC()
	} else if ifi, err := net.InterfaceByName(o.Iface); err == nil {
		mac = ifi.HardwareAddr
	}
	rep := &DPTDHCPReport{Iface: o.Iface, MAC: mac.String(), Listen: ms(o.Listen), Started: time.Now()}
	offers, err := DHCPProbe(ctx, DHCPProbeOptions{Iface: o.Iface, MAC: mac, Listen: o.Listen})
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
	tests := o.Tests.Effective()
	if !tests.DNS {
		dns = nil
	}
	var wg sync.WaitGroup
	rep.DNS = make([]DPTDHCPCheck, len(dns))
	for i, d := range dns {
		wg.Add(1)
		go func() {
			defer wg.Done()
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
	if tests.Time {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm := DPTTimeRun(ctx, extra, o.DPTOptions)
			rep.Time = &tm
		}()
	}
	wg.Wait()
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
	if rep.Time != nil {
		for _, r := range rep.Time.Rows {
			if r.Role == "dhcp" && !r.OK {
				rep.Time.Status, rep.Time.Reason = DPTFail, r.Server+" (from DHCP) does not answer"
			}
		}
	}
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

// ------------------------------------------------------------ rendering

// DPTJSON writes v (a *DPTReport or *DPTDHCPReport) as one JSON document.
func DPTJSON(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

// dptOut writes the sectioned text: a 10-column section name, the body,
// and the status at the right.
type dptOut struct {
	w     io.Writer
	color bool
}

const dptWidth = 72

func (o dptOut) status(s string) string {
	if !o.color {
		return s
	}
	switch s {
	case DPTOK:
		return "\x1b[32m" + s + "\x1b[0m"
	case DPTWarn:
		return "\x1b[33m" + s + "\x1b[0m"
	case DPTFail:
		return "\x1b[31m" + s + "\x1b[0m"
	}
	return s
}

func (o dptOut) line(section, body, status string) {
	l := fmt.Sprintf("%-10s%s", section, body)
	if status != "" {
		if pad := dptWidth - len(l); pad > 0 {
			l += strings.Repeat(" ", pad)
		} else {
			l += "  "
		}
		l += o.status(status)
	}
	fmt.Fprintln(o.w, strings.TrimRight(l, " "))
}

func fms(v Ms) string { return strconv.FormatFloat(float64(v), 'f', 1, 64) }

func fsigned(v Ms) string {
	s := fms(v)
	if v >= 0 {
		s = "+" + s
	}
	return s + " ms"
}

// RenderDPT writes a report as sectioned text; verbose adds a line per
// echo and per lookup.
func RenderDPT(w io.Writer, r *DPTReport, color, verbose bool) {
	o := dptOut{w: w, color: color}
	t := r.Target.Input
	if len(r.Target.Addresses) > 1 || r.Target.Addresses[0] != t {
		t += "  (" + strings.Join(r.Target.Addresses, " ") + ")"
	}
	o.line("TARGET", t, "")
	for _, a := range r.Results {
		if len(r.Results) > 1 {
			o.line("ADDRESS", a.Address, "")
		}
		if p := a.Ping; p == nil {
		} else if p.Error != "" {
			o.line("PING", p.Error, p.Status)
		} else {
			if verbose {
				for _, row := range p.Rows {
					if row.OK {
						ttl := ""
						if row.TTL >= 0 {
							ttl = "  ttl " + strconv.Itoa(row.TTL)
						}
						o.line("", fmt.Sprintf("seq %d  %s ms%s", row.Seq, fms(row.RTT), ttl), "")
					} else {
						o.line("", fmt.Sprintf("seq %d  %s", row.Seq, row.Error), "")
					}
				}
			}
			body := fmt.Sprintf("%d/%d  loss %.0f%%", p.Received, p.Sent, p.Loss)
			if p.Received > 0 {
				body += fmt.Sprintf("  rtt min/avg/max/sd %s/%s/%s/%s ms", fms(p.Min), fms(p.Avg), fms(p.Max), fms(p.StdDev))
			}
			o.line("PING", body, p.Status)
		}
		if d := a.DNS; d == nil {
		} else if d.NoService {
			o.line("DNS", "no DNS service", "")
		} else {
			if verbose {
				for _, row := range d.Rows {
					if row.Error != "" {
						o.line("", fmt.Sprintf("%-16s %s", row.Name, row.Error), "")
						continue
					}
					o.line("", fmt.Sprintf("%-16s %-8s %6s ms  %-8s %s", row.Name, row.Rcode, fms(row.Time), strings.Join(row.Flags, " "), strings.Join(row.Answers, ", ")), "")
				}
			}
			flags := ""
			if d.Recursion {
				flags += " RA"
			}
			if d.DNSSEC {
				flags += " AD"
			}
			if d.EDNS0 {
				flags += fmt.Sprintf(" EDNS0(%d)", d.EDNSSize)
			}
			o.line("DNS", fmt.Sprintf("%d/%d answered by %s  avg %s ms %s", d.Answered, len(d.Rows), d.Server, fms(d.Avg), flags), d.Status)
		}
		if a.Time != nil {
			renderDPTTime(o, *a.Time)
		}
		if a.Features != nil {
			o.line("FEATURES", dptFeatureWords(*a.Features), "")
		}
	}
}

func renderDPTTime(o dptOut, t DPTTime) {
	first := true
	sec := func() string {
		if first {
			first = false
			return "TIME"
		}
		return ""
	}
	for _, r := range t.Rows {
		name := r.Server
		if r.Role == "dhcp" {
			name += " (dhcp)"
		}
		if !r.OK {
			msg := r.Error
			if r.NoService {
				msg = "no NTP service"
			}
			o.line(sec(), fmt.Sprintf("%-22s %s", name, msg), "")
			continue
		}
		ref := r.RefID
		if r.RefName != "" {
			ref += " " + r.RefName
		}
		extra := ""
		if r.Leap == 3 {
			extra = "  UNSYNCHRONISED"
		} else if r.Leap != 0 {
			extra = fmt.Sprintf("  leap %d", r.Leap)
		}
		o.line(sec(), fmt.Sprintf("%-22s %11s  s%-2d delay %6s ms  %s%s", name, fsigned(r.Offset), r.Stratum,
			fms(r.Delay), ref, extra), "")
	}
	body := "max divergence " + fms(t.MaxDivergence) + " ms"
	if t.Reference == "" {
		body = "no reference answered"
	}
	if t.Reason != "" {
		body += "  (" + t.Reason + ")"
	}
	o.line(sec(), body, t.Status)
}

func dptFeatureWords(f DPTFeatures) string {
	var w []string
	add := func(on bool, s string) {
		if on {
			w = append(w, s)
		}
	}
	add(f.ICMP, "icmp")
	add(f.DNSUDP, "dns/udp")
	add(f.DNSTCP, "dns/tcp")
	add(f.Recursion, "recursion")
	add(f.EDNS0, "edns0")
	add(f.DNSSEC, "dnssec")
	add(f.DoT, "dot(853)")
	if f.NTP {
		w = append(w, fmt.Sprintf("ntp(s%d)", f.Stratum))
	}
	if len(w) == 0 {
		return "none"
	}
	return strings.Join(w, " ")
}

// RenderDPTDHCP writes a DHCP-mode report as sectioned text.
func RenderDPTDHCP(w io.Writer, r *DPTDHCPReport, color bool) {
	o := dptOut{w: w, color: color}
	o.line("DHCP", fmt.Sprintf("%s  client %s  listened %s ms", r.Iface, r.MAC, fms(r.Listen)), "")
	if r.Multiple {
		o.line("", "WARNING: multiple DHCP servers on "+r.Iface, "")
	}
	if r.Note != "" {
		o.line("", r.Note, "")
	}
	for _, s := range r.Servers {
		kv := func(k, v string) {
			if v != "" {
				o.line("", fmt.Sprintf("  %-18s %s", k, v), "")
			}
		}
		head := "server " + s.ServerID
		if s.ServerID == "" {
			head = "server (no identifier)"
		}
		head += "  from " + s.SourceIP
		if s.SourceMAC != "" {
			head += " " + s.SourceMAC
		}
		head += "  after " + fms(s.After) + " ms"
		o.line("", head, "")
		kv("relay (giaddr)", s.Relay)
		kv("offered", s.Offered)
		kv("mask", s.Mask)
		kv("router", s.Router)
		kv("broadcast", s.Broadcast)
		kv("lease / T1 / T2", strings.Trim(strings.Join([]string{s.Lease, s.T1, s.T2}, " / "), " /"))
		kv("DNS", strings.Join(s.DNS, " "))
		kv("domain", s.Domain)
		kv("search", s.Search)
		kv("NTP (42)", strings.Join(s.NTP, " "))
		kv("time srv (4)", strings.Join(s.TimeSrv, " "))
		kv("time offset (2)", s.TimeOff)
		kv("TZ POSIX (100)", s.TZPOSIX)
		kv("TZ name (101)", s.TZName)
		if len(s.NTP) == 0 {
			kv("NTP (42)", "none offered")
		}
		kv("routes (121)", s.Routes)
		kv("MTU", s.MTU)
		kv("hostname", s.Hostname)
		kv("next-server", s.NextSrv)
		kv("sname", s.SName)
		kv("file", s.File)
		kv("TFTP (66)", s.TFTP)
		kv("boot file (67)", s.BootFile)
		kv("TFTP (150)", s.TFTPList)
		kv("WPAD (252)", s.WPAD)
		kv("vendor (43)", s.Vendor)
		keys := make([]string, 0, len(s.Other))
		for k := range s.Other {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { a, _ := strconv.Atoi(keys[i]); b, _ := strconv.Atoi(keys[j]); return a < b })
		for _, k := range keys {
			kv("option "+k, s.Other[k])
		}
	}
	o.line("", fmt.Sprintf("%d server(s)", len(r.Servers)), r.Status)
	first := true
	for _, c := range r.DNS {
		sec := ""
		if first {
			sec, first = "DNS", false
		}
		if c.Error != "" {
			o.line(sec, fmt.Sprintf("%-22s %s", c.Server, c.Error), "")
		} else {
			o.line(sec, fmt.Sprintf("%-22s %-8s %s ms", c.Server, c.Rcode, fms(c.Time)), "")
		}
	}
	if r.DNSState == "" {
		// DNS not tested (t only)
	} else if len(r.DNS) == 0 {
		o.line("DNS", "no DNS servers offered", r.DNSState)
	} else {
		ok := 0
		for _, c := range r.DNS {
			if c.OK {
				ok++
			}
		}
		o.line("", fmt.Sprintf("%d/%d DNS servers answer", ok, len(r.DNS)), r.DNSState)
	}
	if r.Time != nil {
		renderDPTTime(o, *r.Time)
	}
}

// RenderDPTTime writes a time section alone (the shell's time command).
func RenderDPTTime(w io.Writer, t DPTTime, color bool) {
	renderDPTTime(dptOut{w: w, color: color}, t)
}
