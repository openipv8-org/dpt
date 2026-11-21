// SPDX-License-Identifier: MIT

package dpt

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The CLOCK part of dpt info: this machine's time and zone, and how the
// system keeps it, read from the system, nothing sent.  It is shown
// always: with no NTP server set the clock is only what was set on this
// machine by hand, and that is worth seeing.

// DPTClock is the machine's clock.
type DPTClock struct {
	Now  time.Time `json:"now"`
	Zone string    `json:"zone"` // the zone's name (Europe/London) when known, else its abbreviation
	// Auto: the system sets the clock itself ("yes"), not ("no"), or
	// could not be read ("").  How: NTP, the domain, ...
	Auto     string     `json:"set_automatically,omitempty"`
	How      string     `json:"how,omitempty"`
	Synced   string     `json:"synchronised,omitempty"` // yes, no, or "" (not known)
	Source   string     `json:"source,omitempty"`       // where the time last came from
	Last     *time.Time `json:"last_sync,omitempty"`
	Offset   string     `json:"offset,omitempty"` // as the system last measured it
	Note     string     `json:"note,omitempty"`   // what could not be read, and why
	ReadFrom []string   `json:"read_from,omitempty"`
}

// DPTClockGather reads the clock.
func DPTClockGather() *DPTClock {
	c := &DPTClock{Now: time.Now()}
	c.Zone, _ = c.Now.Zone()
	clockRead(c)
	return c
}

// clockRun runs a system tool, briefly; the output is "" if it fails.
func clockRun(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// clockKV reads "Key : value" or "Key=value" lines; keys are lowercased.
func clockKV(s, sep string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, sep)
		if ok {
			m[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(strings.TrimSuffix(v, "\r"))
		}
	}
	return m
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// clockFromTimedatectl reads "timedatectl show".
func clockFromTimedatectl(c *DPTClock, s string) bool {
	m := clockKV(s, "=")
	if len(m) == 0 {
		return false
	}
	if z := m["timezone"]; z != "" {
		c.Zone = Safe(z)
	}
	if v, ok := m["ntp"]; ok {
		c.Auto, c.How = yesNo(v == "yes"), "NTP"
	}
	if v, ok := m["ntpsynchronized"]; ok {
		c.Synced = yesNo(v == "yes")
	}
	c.ReadFrom = append(c.ReadFrom, "timedatectl")
	return true
}

// clockFromChrony reads "chronyc -n tracking".
func clockFromChrony(c *DPTClock, s string) bool {
	m := clockKV(s, ":")
	ref, ok := m["reference id"]
	if !ok {
		return false
	}
	c.How = "NTP (chrony)"
	if i, j := strings.Index(ref, "("), strings.LastIndex(ref, ")"); i >= 0 && j > i {
		c.Source = Safe(ref[i+1 : j])
	}
	if l := m["leap status"]; l != "" {
		c.Synced = yesNo(!strings.EqualFold(l, "not synchronised"))
		if c.Synced == "no" {
			c.Source = ""
		}
	}
	if t, err := time.Parse("Mon Jan _2 15:04:05 2006", m["ref time (utc)"]); err == nil && t.Year() > 1970 {
		c.Last = &t
	}
	// System time : 0.000124529 seconds fast of NTP time
	if f := strings.Fields(m["system time"]); len(f) >= 3 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil && c.Synced != "no" {
			c.Offset = fmt.Sprintf("%.3f ms %s", v*1000, Safe(f[2]))
		}
	}
	c.ReadFrom = append(c.ReadFrom, "chronyc tracking")
	return true
}

// clockFromW32tm reads "w32tm /query /status" (English only: the
// labels are translated on other Windows languages).
func clockFromW32tm(c *DPTClock, s string) bool {
	m := clockKV(s, ": ")
	src, ok := m["source"]
	if !ok {
		return false
	}
	c.ReadFrom = append(c.ReadFrom, "w32tm /query /status")
	if li := m["leap indicator"]; li != "" {
		c.Synced = yesNo(!strings.HasPrefix(li, "3"))
	}
	switch {
	case strings.EqualFold(src, "Local CMOS Clock"), strings.EqualFold(src, "Free-running System Clock"):
		c.Source = "this machine's own clock (" + Safe(src) + ")"
		c.Synced = "no"
	default:
		c.Source = Safe(strings.TrimSuffix(src, ",0x9"))
	}
	for _, f := range []string{"1/2/2006 3:04:05 PM", "2/1/2006 15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(f, m["last successful sync time"], time.Local); err == nil {
			c.Last = &t
			break
		}
	}
	if p := strings.TrimSuffix(m["phase offset"], "s"); p != "" && c.Synced != "no" {
		if v, err := strconv.ParseFloat(p, 64); err == nil {
			c.Offset = fmt.Sprintf("%+.3f ms", v*1000)
		}
	}
	return true
}

// renderClock writes the CLOCK section.
func renderClock(o dptOut, c *DPTClock) {
	if c == nil {
		return
	}
	o.line("CLOCK", fmt.Sprintf("%s  %s", c.Now.Format("2006-01-02 15:04:05"), c.Zone))
	kv := func(k, v string) { o.line("", fmt.Sprintf("  %-18s %s", k, v)) }
	switch c.Auto {
	case "yes":
		kv("set automatically", "yes, by "+c.How)
	case "no":
		kv("set automatically", o.red("NO: set by hand on this machine, it keeps only its own time"))
	default:
		kv("set automatically", "not known")
	}
	if c.Synced != "" {
		s := c.Synced
		if c.Last != nil {
			s += ", last " + c.Last.Local().Format("2006-01-02 15:04")
		}
		if c.Offset != "" {
			s += ", " + c.Offset
		}
		if c.Synced == "no" && c.Auto != "no" {
			s = o.red(strings.ToUpper(s[:1]) + s[1:])
		}
		kv("synchronised", s)
	}
	if c.Source != "" {
		kv("time from", c.Source)
	}
	if c.Note != "" {
		kv("note", c.Note)
	}
	if len(c.ReadFrom) > 0 {
		kv("read from", strings.Join(c.ReadFrom, ", "))
	}
}
