// SPDX-License-Identifier: MIT

package dpt

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ------------------------------------------------------------ rendering

// DPTJSON writes v (a *DPTReport or *DPTDHCPReport) as one JSON document.
func DPTJSON(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

// dptOut writes the sectioned text: a 10-column section name and the
// body; a blank line comes before every section but the first.
type dptOut struct {
	w     io.Writer
	color bool
	any   *bool // a section has been written
}

func newOut(w io.Writer, color bool) dptOut { return dptOut{w: w, color: color, any: new(bool)} }

// DPTRule is the line between the results and the summary.
const DPTRule = "_______________________________________________________"

func (o dptOut) paint(code, s string) string {
	if !o.color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (o dptOut) red(s string) string    { return o.paint("1;31", s) }
func (o dptOut) yellow(s string) string { return o.paint("33", s) }
func (o dptOut) bold(s string) string   { return o.paint("1", s) }
func (o dptOut) dim(s string) string    { return o.paint("2", s) }

// status colours a status word: OK green, WARN yellow, FAIL red.
func (o dptOut) status(s string) string {
	switch s {
	case DPTOK:
		return o.paint("1;32", s)
	case DPTWarn, DPTNone:
		return o.paint("1;33", s)
	case DPTFail:
		return o.paint("1;31", s)
	}
	return s
}

// by colours s the way status would: plain when OK.
func (o dptOut) by(status, s string) string {
	switch status {
	case DPTWarn, DPTNone:
		return o.yellow(s)
	case DPTFail:
		return o.red(s)
	}
	return s
}

func (o dptOut) line(section, body string) {
	if section != "" {
		if o.any != nil {
			if *o.any {
				fmt.Fprintln(o.w)
			}
			*o.any = true
		}
		section = o.paint("1;36", fmt.Sprintf("%-10s", section))
	} else {
		section = strings.Repeat(" ", 10)
	}
	fmt.Fprintln(o.w, strings.TrimRight(section+body, " "))
}

// pad pads s (which may hold colour) to n visible columns.
func pad(s string, visible, n int) string {
	if visible < n {
		return s + strings.Repeat(" ", n-visible)
	}
	return s
}

func fms(v Ms) string { return strconv.FormatFloat(float64(v), 'f', 1, 64) }

func fsigned(v Ms) string {
	s := fms(v)
	if v >= 0 {
		s = "+" + s
	}
	return s
}

// summary writes the rule and the one-line result: PING OK   DNS OK ...
func (o dptOut) summary(lines [][2][]string) {
	fmt.Fprintln(o.w, o.dim(DPTRule))
	for _, l := range lines {
		var b []string
		for i, name := range l[0] {
			b = append(b, o.bold(name)+" "+o.status(l[1][i]))
		}
		fmt.Fprintln(o.w, strings.Join(b, "   "))
	}
}

// DPTPrinter writes a dpt run as it comes: the target, then each section
// when its test is done, then the summary.
type DPTPrinter struct {
	o       dptOut
	verbose bool
	many    bool
}

// NewDPTPrinter writes to w.
func NewDPTPrinter(w io.Writer, color, verbose bool) *DPTPrinter {
	return &DPTPrinter{o: newOut(w, color), verbose: verbose}
}

// Target writes the TARGET section.
func (p *DPTPrinter) Target(t DPTTarget) {
	s := p.o.bold(t.Input)
	p.many = len(t.Tested) > 1
	if len(t.Addresses) > 3 {
		// many addresses: in columns under the name, wrapped to fit
		p.o.line("TARGET", s+fmt.Sprintf("  (%d addresses)", len(t.Addresses)))
		for _, row := range Columns(t.Addresses, 80-10) {
			p.o.line("", row)
		}
		return
	}
	if len(t.Addresses) > 1 || len(t.Addresses) == 1 && t.Addresses[0] != t.Input {
		s += "  (" + strings.Join(t.Addresses, " ") + ")"
	}
	p.o.line("TARGET", s)
}

// Columns lays items out in even columns, as many to a row as fit in
// width; the last item of a row has no padding after it.
func Columns(items []string, width int) []string {
	col := 0
	for _, it := range items {
		col = max(col, len(it)+2)
	}
	per := max(1, (width+2)/col)
	var rows []string
	for k := 0; k < len(items); k += per {
		var b strings.Builder
		end := min(k+per, len(items))
		for i := k; i < end; i++ {
			if i == end-1 {
				b.WriteString(items[i])
			} else {
				fmt.Fprintf(&b, "%-*s", col, items[i])
			}
		}
		rows = append(rows, b.String())
	}
	return rows
}

// Section writes one section of a: ADDRESS, PING, DNS, TIME or FEATURES.
func (p *DPTPrinter) Section(a *DPTAddrReport, sec string) {
	o := p.o
	switch sec {
	case "ADDRESS":
		if p.many {
			o.line("ADDRESS", o.bold(a.Address))
		}
	case "PING":
		if a.Ping != nil {
			p.ping(*a.Ping)
		}
	case "DNS":
		if a.DNS != nil {
			p.dns(*a.DNS)
		}
	case "TIME":
		if a.Time != nil {
			renderDPTTime(o, *a.Time)
		}
	case "FEATURES":
		if a.Features != nil {
			o.line("FEATURES", dptFeatureWords(*a.Features))
		}
	}
}

// The PING and DNS lines share their columns:
//
//	PING      5/5    loss 0%      rtt  32.5 / 33.2 / 34.0 ms     sd 0.6 ms
//	DNS       5/5                 avg  35.6 ms                   RA AD EDNS0(512)
func (p *DPTPrinter) cols(count, mid, midShown, label, value, extra string) string {
	s := fmt.Sprintf("%-5s  ", count) + pad(midShown, len(mid), 12) + " " + label + "  " + pad(value, len(value), 21)
	if extra != "" {
		s += "   " + extra
	}
	return s
}

func (p *DPTPrinter) ping(pg DPTPing) {
	o := p.o
	if pg.Error != "" {
		o.line("PING", o.red(pg.Error))
		return
	}
	loss := fmt.Sprintf("loss %.0f%%", pg.Loss)
	value, extra := "", ""
	if pg.Received > 0 {
		value = fmt.Sprintf("%s / %s / %s ms", fms(pg.Min), fms(pg.Avg), fms(pg.Max))
		extra = "sd " + fms(pg.StdDev) + " ms"
	}
	label := "rtt"
	if value == "" {
		label = "   "
	}
	o.line("PING", p.cols(fmt.Sprintf("%d/%d", pg.Received, pg.Sent), loss, o.by(pg.Status, loss), label, value, extra))
	if p.verbose {
		for _, row := range pg.Rows {
			if row.OK {
				ttl := ""
				if row.TTL >= 0 {
					ttl = "   ttl " + strconv.Itoa(row.TTL)
				}
				o.line("", fmt.Sprintf("  seq %-4d %8s ms%s", row.Seq, fms(row.RTT), ttl))
			} else {
				o.line("", fmt.Sprintf("  seq %-4d %s", row.Seq, o.red(row.Error)))
			}
		}
	}
}

func (p *DPTPrinter) dns(d DPTDNS) {
	o := p.o
	if d.NoService {
		o.line("DNS", o.yellow("no DNS service"))
		return
	}
	var flags []string
	if d.Recursion {
		flags = append(flags, "RA")
	}
	if d.DNSSEC {
		flags = append(flags, "AD")
	}
	if d.EDNS0 {
		flags = append(flags, fmt.Sprintf("EDNS0(%d)", d.EDNSSize))
	}
	mid := ""
	if n := len(d.Rows) - d.Answered; n > 0 {
		mid = fmt.Sprintf("%d failed", n)
	}
	value, label := "", "avg"
	if d.Answered > 0 || d.Avg > 0 {
		value = fms(d.Avg) + " ms"
	} else {
		label = "   "
	}
	o.line("DNS", p.cols(fmt.Sprintf("%d/%d", d.Answered, len(d.Rows)), mid, o.by(d.Status, mid), label, value, strings.Join(flags, " ")))
	if p.verbose {
		w := 0
		for _, row := range d.Rows {
			w = max(w, len(row.Name))
		}
		for _, row := range d.Rows {
			if row.Error != "" {
				o.line("", fmt.Sprintf("  %-*s  %s", w, row.Name, o.red(row.Error)))
				continue
			}
			o.line("", fmt.Sprintf("  %-*s  %-8s %8s ms   %-8s %s", w, row.Name, row.Rcode, fms(row.Time), strings.Join(row.Flags, " "), strings.Join(row.Answers, ", ")))
		}
	}
}

// Summary writes the rule and PING OK   DNS OK   TIME OK, one line per
// address tested.
func (p *DPTPrinter) Summary(r *DPTReport) {
	var lines [][2][]string
	for _, a := range r.Results {
		var names, st []string
		if p.many {
			names, st = append(names, a.Address), append(st, "")
		}
		if a.Ping != nil {
			names, st = append(names, "PING"), append(st, a.Ping.Status)
		}
		if a.DNS != nil {
			names, st = append(names, "DNS"), append(st, a.DNS.Status)
		}
		if a.Time != nil {
			names, st = append(names, "TIME"), append(st, a.Time.Status)
		}
		lines = append(lines, [2][]string{names, st})
	}
	p.o.summary(lines)
}

// DPTSections is the order a dpt run's sections are written in.
var DPTSections = []string{"ADDRESS", "PING", "DNS", "TIME", "FEATURES"}

// RenderDPT writes a whole report as sectioned text; verbose adds a line
// per echo and per lookup.
func RenderDPT(w io.Writer, r *DPTReport, color, verbose bool) {
	p := NewDPTPrinter(w, color, verbose)
	p.Target(r.Target)
	for i := range r.Results {
		for _, s := range DPTSections {
			p.Section(&r.Results[i], s)
		}
	}
	p.Summary(r)
}

// The TIME section: names in one column, offsets right-aligned so the
// decimal points line up.
//
//	TIME      time.google.com      -3.9 ms   s1    delay  60.4 ms   .GOOG.
//	          8.8.8.8              no NTP service
//	          max divergence        2.3 ms
//	          this clock           +5.0 ms   ahead of the reference servers
func renderDPTTime(o dptOut, t DPTTime) {
	first := true
	sec := func() string {
		if first {
			first = false
			return "TIME"
		}
		return ""
	}
	w := len("max divergence")
	names := make([]string, len(t.Rows))
	for i, r := range t.Rows {
		names[i] = r.Server
		switch r.Role {
		case "dhcp":
			names[i] += " (dhcp)"
		case "system":
			names[i] += " (this machine's)"
		}
		w = max(w, len(names[i]))
	}
	name := func(s string) string { return o.bold(s) + strings.Repeat(" ", w-len(s)+2) }
	// the numbers right-aligned in one width, messages starting where
	// the numbers start
	nw := len(fms(t.MaxDivergence))
	nw = max(nw, len(fsigned(t.LocalOffset)))
	for _, r := range t.Rows {
		if r.OK {
			nw = max(nw, len(fsigned(r.Offset)))
		}
	}
	num := func(s string) string { return fmt.Sprintf("%*s ms", nw, s) }
	for i, r := range t.Rows {
		if !r.OK {
			msg := o.red(r.Error)
			if r.NoService {
				msg = o.yellow("no NTP service")
			}
			o.line(sec(), name(names[i])+msg)
			continue
		}
		extra := ""
		if r.Leap == 3 {
			extra = "   " + o.red("UNSYNCHRONISED")
		} else if r.Leap != 0 {
			extra = fmt.Sprintf("   leap %d", r.Leap)
		}
		o.line(sec(), fmt.Sprintf("%s%s   %-4s  delay %6s ms   %s%s", name(names[i]), num(fsigned(r.Offset)),
			"s"+strconv.Itoa(r.Stratum), fms(r.Delay), r.RefID, extra))
	}
	if t.Reference == "" {
		o.line(sec(), o.by(t.Status, "no reference server answered"))
		if t.Reason != "" && t.Reason != "no reference server answered" {
			o.line(sec(), o.by(t.Status, t.Reason))
		}
		return
	}
	div := t.DivStatus
	if div == "" {
		div = t.Status
	}
	body := name("max divergence") + o.by(div, num(fms(t.MaxDivergence)))
	if t.Reason != "" && t.Status != DPTOK && !strings.HasPrefix(t.Reason, "this clock") {
		body += "   " + o.by(t.Status, t.Reason)
	}
	o.line(sec(), body)
	if t.LocalStatus != "" {
		words := "ahead of the reference servers"
		if t.LocalOffset < 0 {
			words = "behind the reference servers"
		}
		o.line(sec(), name("this clock")+o.by(t.LocalStatus, num(fsigned(t.LocalOffset))+"   "+words))
	}
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
	return strings.Join(w, "  ")
}

// DPTDHCPPrinter writes a DHCP-mode run as it comes: the offers, then
// the DNS and TIME sections, then the summary.
type DPTDHCPPrinter struct{ o dptOut }

// NewDPTDHCPPrinter writes to w.
func NewDPTDHCPPrinter(w io.Writer, color bool) *DPTDHCPPrinter {
	return &DPTDHCPPrinter{o: newOut(w, color)}
}

// Section writes DHCP, DNS or TIME.
func (p *DPTDHCPPrinter) Section(r *DPTDHCPReport, sec string) {
	o := p.o
	switch sec {
	case "DHCP":
		p.offers(r)
	case "DNS":
		if r.DNSState == "" {
			return // not tested (t only)
		}
		if len(r.DNS) == 0 {
			o.line("DNS", o.yellow("no DNS servers offered"))
			return
		}
		w := 0
		for _, c := range r.DNS {
			w = max(w, len(c.Server))
		}
		first := "DNS"
		ok := 0
		for _, c := range r.DNS {
			name := o.bold(c.Server) + strings.Repeat(" ", w-len(c.Server)+2)
			if c.Error != "" {
				o.line(first, name+o.red(c.Error))
			} else {
				rc := c.Rcode
				if !c.OK {
					rc = o.red(rc)
				} else {
					ok++
				}
				o.line(first, name+pad(rc, len(c.Rcode), 9)+fmt.Sprintf("%7s ms", fms(c.Time)))
			}
			first = ""
		}
		o.line("", o.by(r.DNSState, fmt.Sprintf("%d of %d DNS servers answer", ok, len(r.DNS))))
	case "TIME":
		if r.Time != nil {
			renderDPTTime(o, *r.Time)
		}
	}
}

func (p *DPTDHCPPrinter) offers(r *DPTDHCPReport) {
	o := p.o
	o.line("DHCP", fmt.Sprintf("%s  client %s  listened %s s", o.bold(r.Iface), r.MAC, strconv.FormatFloat(float64(r.Listen)/1000, 'f', -1, 64)))
	if len(r.VPN) > 0 {
		o.line("", o.red("A VPN TUNNEL IS UP ("+strings.Join(r.VPN, ", ")+"): dhcp might not work on "+r.Iface))
	}
	if r.Multiple {
		o.line("", o.yellow("WARNING: multiple DHCP servers on "+r.Iface))
	}
	if r.Note != "" {
		o.line("", o.yellow(r.Note))
	}
	for _, s := range r.Servers {
		kv := func(k, v string) {
			if v != "" {
				o.line("", fmt.Sprintf("  %-18s %s", k, v))
			}
		}
		o.line("", "")
		head := "server " + s.ServerID
		if s.ServerID == "" {
			head = "server (no identifier)"
		}
		head = o.bold(head) + "  from " + s.SourceIP
		if s.SourceMAC != "" {
			head += " " + s.SourceMAC
		}
		head += "  after " + fms(s.After) + " ms"
		o.line("", head)
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
	o.line("", "")
	o.line("", o.by(r.Status, fmt.Sprintf("%d server(s)", len(r.Servers))))
}

// Summary writes the rule and DHCP OK   DNS OK   TIME OK.
func (p *DPTDHCPPrinter) Summary(r *DPTDHCPReport) {
	names, st := []string{"DHCP"}, []string{r.Status}
	if r.DNSState != "" {
		names, st = append(names, "DNS"), append(st, r.DNSState)
	}
	if r.Time != nil {
		names, st = append(names, "TIME"), append(st, r.Time.Status)
	}
	p.o.summary([][2][]string{{names, st}})
}

// DPTDHCPSections is the order a DHCP-mode run's sections are written in.
var DPTDHCPSections = []string{"DHCP", "DNS", "TIME"}

// RenderDPTDHCP writes a whole DHCP-mode report as sectioned text.
func RenderDPTDHCP(w io.Writer, r *DPTDHCPReport, color bool) {
	p := NewDPTDHCPPrinter(w, color)
	for _, s := range DPTDHCPSections {
		p.Section(r, s)
	}
	p.Summary(r)
}

// RenderDPTTime writes a time section alone (the shell's time command),
// with its summary.
func RenderDPTTime(w io.Writer, t DPTTime, color bool) {
	o := newOut(w, color)
	renderDPTTime(o, t)
	o.summary([][2][]string{{{"TIME"}, {t.Status}}})
}
