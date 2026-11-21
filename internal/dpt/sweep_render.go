// SPDX-License-Identifier: MIT

package dpt

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// SweepPrinter writes a sweep as it comes:
//
//	NETWORK   192.168.1.0/24 on en0   this machine 192.168.1.23   gateway 192.168.1.1
//
//	LIVE      192.168.1.1       0.9 ms  ttl 64   router.lan   gateway
//	          192.168.1.23      0.1 ms  ttl 64   this machine
//
// With ports, each live address is followed by its open ports:
//
//	192.168.1.1       0.9 ms  ttl 64   53 dns  80 http  443 https   router.lan   gateway
type SweepPrinter struct {
	o     dptOut
	first bool
	ports bool
	width int // the terminal's columns; the ports wrap to it
}

// NewSweepPrinter writes to w.
func NewSweepPrinter(w io.Writer, color bool) *SweepPrinter {
	return &SweepPrinter{o: newOut(w, color), first: true, width: termWidth(w)}
}

// Network writes the NETWORK section.
func (p *SweepPrinter) Network(r *SweepReport) {
	o := p.o
	p.ports = r.Ports
	s := o.bold(r.Network)
	if r.Iface != "" {
		s += " on " + r.Iface
	}
	if r.Self != "" {
		s += "   this machine " + r.Self
	}
	if r.Gateway != "" {
		s += "   gateway " + r.Gateway
	}
	o.line("NETWORK", s)
	what := "ping"
	if r.Ports {
		what = fmt.Sprintf("ping, then %d TCP and %d UDP ports of each", len(DPTTopPorts), len(DPTUDPPorts))
	}
	o.line("", o.dim(fmt.Sprintf("%d addresses, 25 at a time: %s", r.Tried, what)))
	if r.Ports && o.color {
		o.line("", portsLegend(o))
	}
	if r.Note != "" {
		o.line("", o.yellow(r.Note))
	}
}

// Host writes one live address: its ports to the right, in colour by
// kind, wrapped under themselves; its name and tags after them.
//
//	192.168.178.196   5.8 ms  ttl 60   23 telnet  80 http  443 https
func (p *SweepPrinter) Host(h *SweepHost) {
	o := p.o
	sec := ""
	if p.first {
		sec, p.first = "LIVE", false
	}
	left := fmt.Sprintf("%-15s %7s ms", h.Address, fms(h.RTT))
	if h.TTL > 0 {
		left += fmt.Sprintf("  ttl %-3d", h.TTL)
	} else {
		left += "         "
	}
	var tags []string
	if h.Name != "" {
		tags = append(tags, h.Name)
	}
	if h.Gateway {
		tags = append(tags, o.bold("gateway"))
	}
	if h.Self {
		tags = append(tags, o.bold("this machine"))
	}
	tail, tailLen := "", 0
	if len(tags) > 0 {
		tail = "   " + strings.Join(tags, "   ")
		tailLen = visibleLen(tail)
	}
	if !h.Scanned {
		o.line(sec, left+tail)
		return
	}
	left += "   "
	room := p.width - 10 - len(left)
	rows := portRows(o, h.Open, h.Closed, h.Filtered, room)
	if tail != "" && visibleLen(rows[len(rows)-1])+tailLen > room {
		// the name does not fit after the ports: a line of its own
		rows = append(rows, strings.TrimLeft(tail, " "))
		tail = ""
	}
	for i, r := range rows {
		if i == len(rows)-1 {
			r += tail
		}
		if i == 0 {
			o.line(sec, left+r)
		} else {
			o.line("", strings.Repeat(" ", len(left))+r)
		}
	}
}

// termWidth is w's columns when it is a terminal, else 80; at most 160,
// so the ports stay near the address.
func termWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if c, _, err := term.GetSize(int(f.Fd())); err == nil && c >= 40 {
			return min(c, 160)
		}
	}
	return 80
}

// portRows lays out the open ports ("23 telnet  80 http  53/udp dns"),
// coloured by kind, in rows of at most width visible columns; with
// none open, the closed and no-answer counts.
func portRows(o dptOut, open []DPTOpenPort, closed, filtered, width int) []string {
	if len(open) == 0 {
		return []string{o.dim(fmt.Sprintf("no open port (%d closed, %d no answer)", closed, filtered))}
	}
	var rows []string
	row, n := "", 0
	for _, x := range open {
		plain := portProto(x.Port, x.Proto, false) + " " + x.Service
		item := o.portColor(x, o.bold(portProto(x.Port, x.Proto, false))+" "+x.Service)
		if n > 0 && n+2+len(plain) > width {
			rows = append(rows, row)
			row, n = "", 0
		}
		if n > 0 {
			row += "  "
			n += 2
		}
		row += item
		n += len(plain)
	}
	return append(rows, row)
}

// Port kinds, and their colours:
//
//	red      logins in the clear, or open to anyone: telnet, ftp, rsh, redis...
//	yellow   remote control and Windows sharing: ssh, rdp, vnc, smb...
//	green    web: http, https, QUIC
//	magenta  mail
//	blue     names and time: DNS, NTP, NetBIOS names, mDNS, SSDP
var (
	portsRisky  = map[int]bool{21: true, 23: true, 69: true, 514: true, 1080: true, 1883: true, 2049: true, 6379: true, 9200: true}
	portsRemote = map[int]bool{22: true, 135: true, 139: true, 161: true, 445: true, 1723: true, 3389: true, 5900: true, 5985: true}
	portsMail   = map[int]bool{25: true, 110: true, 143: true, 465: true, 587: true, 993: true, 995: true, 2525: true, 8025: true}
	portsNames  = map[int]bool{53: true, 123: true, 137: true, 1900: true, 5353: true}
)

// PortKind is a port's kind: risky, remote, web, mail, names, or "".
func PortKind(x DPTOpenPort) string {
	switch {
	case portsRisky[x.Port] && !(x.Port == 514 && x.Proto == "udp"):
		return "risky"
	case portsRemote[x.Port]:
		return "remote"
	case portsMail[x.Port]:
		return "mail"
	case portsNames[x.Port]:
		return "names"
	case x.Service == "quic" || strings.HasPrefix(x.Service, "http") || x.Port%1000 == 443:
		return "web"
	}
	return ""
}

func (o dptOut) portColor(x DPTOpenPort, s string) string {
	switch PortKind(x) {
	case "risky":
		return o.paint("31", s)
	case "remote":
		return o.paint("33", s)
	case "web":
		return o.paint("32", s)
	case "mail":
		return o.paint("35", s)
	case "names":
		return o.paint("94", s)
	}
	return s
}

// portsLegend says what the colours mean.
func portsLegend(o dptOut) string {
	return o.paint("31", "clear-text logins") + "  " + o.paint("33", "remote access") + "  " +
		o.paint("32", "web") + "  " + o.paint("35", "mail") + "  " + o.paint("94", "names & time")
}

// Summary writes the rule and the count.
func (p *SweepPrinter) Summary(r *SweepReport) {
	o := p.o
	if len(r.Hosts) == 0 {
		o.line("LIVE", o.yellow("nothing answered a ping"))
	}
	fmt.Fprintln(o.w, o.dim(DPTRule))
	s := fmt.Sprintf("%s of %d addresses answered a ping", o.bold(strconv.Itoa(len(r.Hosts))), r.Tried)
	if r.Ports {
		n := 0
		for _, h := range r.Hosts {
			n += len(h.Open)
		}
		s += fmt.Sprintf(", %s open ports", o.bold(strconv.Itoa(n)))
	}
	s += "   (" + took(r.Elapsed) + ")"
	fmt.Fprintln(o.w, s)
	fmt.Fprintln(o.w, o.dim("an address that drops pings (Windows' firewall does by default) is not listed"))
}

// RenderSweep writes a whole sweep.
func RenderSweep(w io.Writer, r *SweepReport, color bool) {
	p := NewSweepPrinter(w, color)
	p.Network(r)
	for i := range r.Hosts {
		p.Host(&r.Hosts[i])
	}
	p.Summary(r)
}

// RenderPorts writes ports <address>.
//
//	TARGET    192.168.1.1  router.lan
//
//	OPEN      22    ssh            1.2 ms
//	          443   https          1.0 ms
//	_______________________________________________________
//	2 of 50 ports open, 47 closed, 1 no answer   (1.0 s)
func RenderPorts(w io.Writer, r *PortsReport, color bool) {
	o := newOut(w, color)
	s := o.bold(r.Target.Input)
	if ip := r.Target.Tested[0]; ip != r.Target.Input {
		s += "  (" + ip + ")"
	}
	if r.Name != "" {
		s += "  " + r.Name
	}
	o.line("TARGET", s)
	if len(r.Open) == 0 {
		o.line("OPEN", o.yellow("none of the "+strconv.Itoa(r.Tried)+" ports tried"))
	}
	for i, x := range r.Open {
		sec := ""
		if i == 0 {
			sec = "OPEN"
		}
		o.line(sec, o.portColor(x, fmt.Sprintf("%-9s %-15s", portProto(x.Port, x.Proto, true), x.Service))+fmt.Sprintf(" %6s ms", fms(x.Connect)))
	}
	fmt.Fprintln(o.w, o.dim(DPTRule))
	fmt.Fprintf(o.w, "%s of %d ports open, %d closed, %d no answer   (%s)\n",
		o.bold(strconv.Itoa(len(r.Open))), r.Tried, r.Closed, r.Filtered, took(r.Elapsed))
}

// portProto is "25/tcp" (always: true) or "25", and "53/udp".
func portProto(port int, proto string, always bool) string {
	if proto == "udp" || always && proto != "" {
		return strconv.Itoa(port) + "/" + proto
	}
	return strconv.Itoa(port)
}

// RenderOutsideIP writes outside-ip.
//
//	OUTSIDE   203.0.113.7  host-203-0-113-7.example.net
//	          as seen by https://ifconfig.me/ip in 182.4 ms
func RenderOutsideIP(w io.Writer, r *OutsideIP, color bool) {
	o := newOut(w, color)
	s := o.bold(r.Address)
	if r.Name != "" {
		s += "  " + r.Name
	}
	o.line("OUTSIDE", s)
	o.line("", o.dim(fmt.Sprintf("as seen by %s in %s ms", r.Source, fms(r.Elapsed))))
}

// took is a run's length: 340 ms, 22.1 s.
func took(v Ms) string {
	if v < 1000 {
		return fmt.Sprintf("%.0f ms", float64(v))
	}
	return fmt.Sprintf("%.1f s", float64(v)/1000)
}

// visibleLen is s's columns, colour codes left out.
func visibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == 0x1b:
			esc = true
		case esc:
			esc = r != 'm'
		default:
			n++
		}
	}
	return n
}
