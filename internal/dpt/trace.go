// SPDX-License-Identifier: MIT

package dpt

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// trace <host>: the routers on the way, as traceroute and mtr show
// them.  Each hop is found with ICMP echoes whose TTL runs out there: the
// router at that hop says so.  Every hop is asked at once, Probes times,
// so a trace takes about Probes x Timeout at most, however long the path.

// TraceOptions is one trace.
type TraceOptions struct {
	MaxHops  int           // 0: 30
	Probes   int           // echoes per hop; 0: 3
	Timeout  time.Duration // per echo; 0: 1 s
	Family   int
	Resolver *net.Resolver
	Names    func(ctx context.Context, ip string) string // nil: reverse DNS
	Live     *Live
	// Open, for tests: nil is OpenICMP
	Open func(ip net.IP) (TraceEchoer, error)
}

// TraceEchoer sends echoes with a TTL.
type TraceEchoer interface {
	EchoTTL(seq, ttl int, timeout time.Duration) (EchoReply, error)
	Close() error
}

// TraceHop is one hop.
type TraceHop struct {
	TTL     int      `json:"hop"`
	From    []string `json:"from,omitempty"` // who answered (more than one: the path splits here)
	Name    string   `json:"name,omitempty"`
	RTTs    []Ms     `json:"rtt_ms"` // the answers, in order
	Sent    int      `json:"sent"`
	Lost    int      `json:"lost"`
	Reached bool     `json:"reached,omitempty"` // the address itself answered
	Unreach bool     `json:"unreachable,omitempty"`
}

// TraceReport is a trace.
type TraceReport struct {
	Target  DPTTarget  `json:"target"`
	Hops    []TraceHop `json:"hops"`
	Reached bool       `json:"reached"`
	MaxHops int        `json:"max_hops"`
	Elapsed Ms         `json:"elapsed_ms"`
	Status  string     `json:"status"`
	Note    string     `json:"note,omitempty"`
	// OneAtATime: no answer came to all hops at once, so they were asked
	// one at a time
	OneAtATime bool `json:"one_at_a_time,omitempty"`
}

// RunTrace traces the way to target's first address.
func RunTrace(ctx context.Context, target string, o TraceOptions) (*TraceReport, error) {
	if o.MaxHops <= 0 {
		o.MaxHops = 30
	}
	if o.Probes <= 0 {
		o.Probes = 3
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	if o.Names == nil {
		o.Names = reverseName
	}
	if o.Open == nil {
		o.Open = func(ip net.IP) (TraceEchoer, error) { return OpenICMP(ip) }
	}
	o.Live.Set("trace", "looking up "+Safe(target))
	defer o.Live.Drop("trace")
	look, cancel := context.WithTimeout(ctx, 2*o.Timeout+3*time.Second)
	ips, err := DPTResolve(look, target, o.Family, o.Resolver)
	cancel()
	if err != nil {
		return nil, err
	}
	ip := ips[0]
	rep := &TraceReport{Target: DPTTarget{Input: target, Tested: []string{ip.String()}}, MaxHops: o.MaxHops}
	for _, a := range ips {
		rep.Target.Addresses = append(rep.Target.Addresses, a.String())
	}
	start := time.Now()
	hops := make([]TraceHop, o.MaxHops)
	conns := make([]TraceEchoer, o.MaxHops)
	for i := range conns {
		c, err := o.Open(ip)
		if err != nil {
			for _, x := range conns[:i] {
				x.Close()
			}
			return nil, err
		}
		conns[i] = c
		hops[i] = TraceHop{TTL: i + 1}
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	// a round asks every hop once, all at once.  Some NATs (VirtualBox's)
	// answer only one of many echoes to the same address at the same
	// time: when a whole round hears nothing, the hops are asked one at a
	// time instead, nearest first, as far as the address.
	var mu sync.Mutex
	done := 0
	oneAtATime := false
	probe := func(i, round int) {
		h := &hops[i]
		c := conns[i]
		if oneAtATime {
			c = conns[0] // one socket: such a NAT gives every answer to the first
		}
		r, err := c.EchoTTL(round*o.MaxHops+h.TTL, h.TTL, o.Timeout) // each its own sequence number
		mu.Lock()
		defer mu.Unlock()
		h.Sent++
		done++
		o.Live.Set("trace", fmt.Sprintf("trace to %s: %d echoes", ip, done))
		if err != nil {
			h.Lost++
			return
		}
		h.RTTs = append(h.RTTs, ms(r.RTT))
		if !containsStr(h.From, r.From) {
			h.From = append(h.From, r.From)
		}
		switch {
		case r.Unreachable:
			h.Unreach = true
		case !r.Hop:
			h.Reached = true
		}
	}
	for round := 0; round < o.Probes && ctx.Err() == nil; round++ {
		if oneAtATime {
			for i := range hops {
				if ctx.Err() != nil {
					break
				}
				probe(i, round)
				if hops[i].Reached || hops[i].Unreach {
					break
				}
			}
			continue
		}
		var wg sync.WaitGroup
		for i := range hops {
			wg.Add(1)
			go func() {
				defer wg.Done()
				probe(i, round)
			}()
		}
		wg.Wait()
		if round == 0 && !anyAnswer(hops) {
			oneAtATime = true
			rep.OneAtATime = true
			for i := range hops {
				hops[i] = TraceHop{TTL: i + 1}
			}
			round--
		}
	}
	// the path ends at the first hop the address (or an unreachable)
	// answered from; a later TTL only reaches it again
	end := len(hops)
	for i, h := range hops {
		if h.Reached || h.Unreach {
			end = i + 1
			rep.Reached = h.Reached
			break
		}
	}
	rep.Hops = hops[:end]
	// trailing silent hops past the last answer are one line, not many
	if !rep.Reached {
		last := -1
		for i, h := range rep.Hops {
			if len(h.From) > 0 {
				last = i
			}
		}
		switch {
		case last < 0:
			rep.Hops = nil
			rep.Note = fmt.Sprintf("nothing answered, at any of %d hops: ICMP is blocked here, or on the way", o.MaxHops)
		case last+2 < len(rep.Hops):
			rep.Hops = rep.Hops[:last+2]
			rep.Note = fmt.Sprintf("nothing answered from hop %d to %d", last+2, o.MaxHops)
		}
	}
	if rep.Reached && len(rep.Hops) == 1 && !onLink(ip) {
		rep.Note = "it answered at hop 1 but is not on this network: a NAT on the way (a virtual machine's)\n" +
			"answers echoes for it, so the routers in between cannot be seen from here"
		rep.Status = DPTWarn
	}
	o.Live.Set("trace", "names of the hops")
	var wg sync.WaitGroup
	for i := range rep.Hops {
		if len(rep.Hops[i].From) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep.Hops[i].Name = o.Names(ctx, rep.Hops[i].From[0])
		}()
	}
	wg.Wait()
	rep.Elapsed = ms(time.Since(start))
	switch {
	case rep.Status == DPTWarn:
	case rep.Reached && traceLossAtEnd(rep):
		rep.Status = DPTWarn
	case rep.Reached:
		rep.Status = DPTOK
	default:
		rep.Status = DPTFail
	}
	return rep, nil
}

// onLink: ip is on a network an interface of this machine is on.
func onLink(ip net.IP) bool {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.Contains(ip) {
			return true
		}
	}
	return false
}

// traceLossAtEnd: echoes were lost on the last hop, the address itself.
// (Loss at a hop in the middle that the hops after it do not show is a
// router too busy to answer, not loss.)
func traceLossAtEnd(r *TraceReport) bool {
	h := r.Hops[len(r.Hops)-1]
	return h.Lost > 0
}

func anyAnswer(hops []TraceHop) bool {
	for _, h := range hops {
		if len(h.From) > 0 {
			return true
		}
	}
	return false
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// RenderTrace writes a trace.
//
//	TARGET    dns.google  (8.8.8.8)
//
//	TRACE      1  192.168.178.1    fritz.box                  1.1    0.9    1.0 ms
//	           2  *
//	           3  62.155.243.81    p3e9bf351.dip0.t-ipconnect.de   9.8  ...
func RenderTrace(w io.Writer, r *TraceReport, color bool) {
	o := newOut(w, color)
	s := o.bold(r.Target.Input)
	if ip := r.Target.Tested[0]; ip != r.Target.Input {
		s += "  (" + ip + ")"
	}
	o.line("TARGET", s)
	aw, nw := 7, 0
	for _, h := range r.Hops {
		if len(h.From) > 0 {
			aw = max(aw, len(h.From[0]))
		}
		nw = max(nw, min(len(h.Name), 40))
	}
	for i, h := range r.Hops {
		sec := ""
		if i == 0 {
			sec = "TRACE"
		}
		if len(h.From) == 0 {
			o.line(sec, fmt.Sprintf("%2d  %s", h.TTL, o.dim("*   no answer")))
			continue
		}
		name := h.Name
		if len(name) > 40 {
			name = name[:39] + "~"
		}
		var times []string
		for _, t := range h.RTTs {
			times = append(times, fmt.Sprintf("%6s", fms(t)))
		}
		for k := len(h.RTTs); k < h.Sent; k++ {
			times = append(times, fmt.Sprintf("%6s", "*"))
		}
		line := fmt.Sprintf("%2d  %-*s  %-*s  %s ms", h.TTL, aw, h.From[0], nw, name, strings.Join(times, " "))
		if h.Lost > 0 {
			line += "   " + o.yellow(strconv.Itoa(h.Lost)+"/"+strconv.Itoa(h.Sent)+" lost")
		}
		if h.Unreach {
			line += "   " + o.red("unreachable")
		}
		o.line(sec, line)
		if len(h.From) > 1 {
			o.line("", o.dim(fmt.Sprintf("    also %s: the path splits here", strings.Join(h.From[1:], ", "))))
		}
	}
	if r.Note != "" {
		sec := ""
		if len(r.Hops) == 0 {
			sec = "TRACE"
		}
		for k, l := range strings.Split(r.Note, "\n") {
			if k > 0 {
				sec = ""
			}
			o.line(sec, o.yellow(l))
		}
	}
	fmt.Fprintln(o.w, o.dim(DPTRule))
	how := fmt.Sprintf("%d hops", len(r.Hops))
	if len(r.Hops) == 1 {
		how = "1 hop"
	}
	if !r.Reached {
		how = "not reached in " + how
	}
	fmt.Fprintf(o.w, "TRACE %s   %s   (%s)\n", o.status(r.Status), how, took(r.Elapsed))
}
