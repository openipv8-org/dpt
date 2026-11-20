// SPDX-License-Identifier: MIT

package dpt

import (
	"fmt"
	"io"
	"strconv"
	"strings"
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
//	192.168.1.1       0.9 ms  ttl 64   router.lan   gateway
//	  open 53 dns  80 http  443 https
type SweepPrinter struct {
	o     dptOut
	first bool
	ports bool
}

// NewSweepPrinter writes to w.
func NewSweepPrinter(w io.Writer, color bool) *SweepPrinter {
	return &SweepPrinter{o: newOut(w, color), first: true}
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
		what = "ping, then the " + strconv.Itoa(len(DPTTopPorts)) + " common TCP ports of each live address"
	}
	o.line("", o.dim(fmt.Sprintf("%d addresses, 25 at a time: %s", r.Tried, what)))
	if r.Note != "" {
		o.line("", o.yellow(r.Note))
	}
}

// Host writes one live address.
func (p *SweepPrinter) Host(h *SweepHost) {
	o := p.o
	sec := ""
	if p.first {
		sec, p.first = "LIVE", false
	}
	s := fmt.Sprintf("%-15s %7s ms", h.Address, fms(h.RTT))
	if h.TTL > 0 {
		s += fmt.Sprintf("  ttl %-3d", h.TTL)
	} else {
		s += "         "
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
	if len(tags) > 0 {
		s += "  " + strings.Join(tags, "   ")
	}
	o.line(sec, s)
	if h.Scanned {
		o.line("", "  "+portsLine(o, h.Open, h.Closed, h.Filtered))
	}
}

// portsLine is "open 22 ssh  80 http" or "no open port", with the
// closed and filtered counts.
func portsLine(o dptOut, open []DPTOpenPort, closed, filtered int) string {
	if len(open) == 0 {
		return o.dim(fmt.Sprintf("no open port (%d closed, %d no answer)", closed, filtered))
	}
	var b []string
	for _, x := range open {
		b = append(b, o.bold(strconv.Itoa(x.Port))+" "+x.Service)
	}
	return "open " + strings.Join(b, "  ")
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
		o.line("OPEN", o.yellow("none of the "+strconv.Itoa(r.Tried)+" common ports"))
	}
	for i, x := range r.Open {
		sec := ""
		if i == 0 {
			sec = "OPEN"
		}
		o.line(sec, fmt.Sprintf("%-5d %-15s %6s ms", x.Port, x.Service, fms(x.Connect)))
	}
	fmt.Fprintln(o.w, o.dim(DPTRule))
	fmt.Fprintf(o.w, "%s of %d ports open, %d closed, %d no answer   (%s)\n",
		o.bold(strconv.Itoa(len(r.Open))), r.Tried, r.Closed, r.Filtered, took(r.Elapsed))
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
