// SPDX-License-Identifier: MIT

package dpt

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// The outside addresses for info: asked of OutsideIPURL over IPv4 and over
// IPv6 at once, as info starts, and shown at its end.

// DPTOutsideWait is the longest info waits for them, from the start.
const DPTOutsideWait = 2500 * time.Millisecond

// DPTOutside is the addresses the internet sees, one per family; Why says
// why one is missing.
type DPTOutside struct {
	IPv4    *OutsideIP `json:"ipv4,omitempty"`
	IPv6    *OutsideIP `json:"ipv6,omitempty"`
	IPv4Why string     `json:"ipv4_error,omitempty"`
	IPv6Why string     `json:"ipv6_error,omitempty"`
	Source  string     `json:"source"`
}

// StartOutside asks for the outside addresses now, over IPv4 and IPv6
// (family 4 or 6: that one only), and gives the wait for them: it gives
// what has come by deadline; what has not is "no answer".
func StartOutside(ctx context.Context, family int, deadline time.Time) (wait func() *DPTOutside) {
	ctx, cancel := context.WithDeadline(ctx, deadline)
	type got struct {
		r   *OutsideIP
		why string
	}
	ask := func(fam int) chan got {
		ch := make(chan got, 1)
		if family != 0 && family != fam {
			ch <- got{why: "not asked (-" + fmt.Sprint(family) + ")"}
			return ch
		}
		go func() {
			r, err := RunOutsideIP(ctx, fam, time.Until(deadline))
			if err != nil {
				ch <- got{why: outsideWhy(err, fam)}
				return
			}
			ch <- got{r: r}
		}()
		return ch
	}
	v4, v6 := ask(4), ask(6)
	return func() *DPTOutside {
		defer cancel()
		o := &DPTOutside{Source: OutsideIPURL}
		late := fmt.Sprintf("no answer in %.1f s", DPTOutsideWait.Seconds())
		take := func(ch chan got) (*OutsideIP, string) {
			select {
			case g := <-ch:
				return g.r, g.why
			case <-ctx.Done():
				// a last look: it may have come as the time ran out
				select {
				case g := <-ch:
					return g.r, g.why
				default:
					return nil, late
				}
			}
		}
		o.IPv4, o.IPv4Why = take(v4)
		o.IPv6, o.IPv6Why = take(v6)
		return o
	}
}

// outsideWhy is why an outside address did not come, in plain words.
func outsideWhy(err error, fam int) string {
	e := strings.ToLower(err.Error())
	switch {
	case strings.Contains(e, "network is unreachable") || strings.Contains(e, "unreachable network") ||
		strings.Contains(e, "no suitable address") || strings.Contains(e, "no route to host") ||
		strings.Contains(e, "cannot assign requested address") || strings.Contains(e, "address family not supported") ||
		strings.Contains(e, "address incompatible with the requested protocol"):
		return fmt.Sprintf("no IPv%d way out from this machine", fam)
	case strings.Contains(e, "deadline exceeded") || strings.Contains(e, "timeout"):
		return fmt.Sprintf("no answer in %.1f s", DPTOutsideWait.Seconds())
	case strings.Contains(e, "no such host"):
		return "could not look up " + OutsideIPURL
	}
	return Safe(err.Error())
}

// renderOutside writes the outside addresses:
//
//	OUTSIDE   IPv4   203.0.113.7  host-203-0-113-7.example.net
//	          IPv6   no IPv6 way out from this machine
//	          as seen by https://ifconfig.me/ip
func renderOutside(o dptOut, x *DPTOutside) {
	if x == nil {
		return
	}
	sec := "OUTSIDE"
	row := func(fam string, r *OutsideIP, why string) {
		if r == nil && why == "" {
			return
		}
		s := o.dim(why)
		if r != nil {
			s = o.bold(r.Address)
			if r.Name != "" {
				s += "  " + r.Name
			}
		}
		o.line(sec, fmt.Sprintf("%-6s %s", fam, s))
		sec = ""
	}
	row("IPv4", x.IPv4, x.IPv4Why)
	row("IPv6", x.IPv6, x.IPv6Why)
	o.line("", o.dim("as seen by "+x.Source))
}
