// SPDX-License-Identifier: MIT

// Package timenative is dpt time native: the system's own time tools,
// each command shown and waited for (Enter) before it runs.
//
//	time native            what the system says of its clock (w32tm, sntp,
//	                       chronyc / timedatectl / ntpq)
//	time native sync       resync now, then the same
//	time native sync fix   set the system to keep its clock in sync, then
//	                       resync.  Refused on a Windows PC on a domain:
//	                       it MUST take its time from a domain controller.
package timenative

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"openipv8.org/dpt/internal/dpt"
)

// Servers are the time servers fix sets, and the ones the clock is
// measured against.
var Servers = []string{"time.cloudflare.com", "time.google.com", "time.windows.com"}

// PollSeconds is how often fix has Windows sync: every hour, not the
// week a PC on no domain waits by default.
const PollSeconds = 3600

// Step is one command.
type Step struct {
	Line    string   // as shown; on Windows, the exact command line run
	Argv    []string // the program and its arguments
	Admin   bool     // needs Administrator / root
	MayFail bool     // a failure is not one (a service already started)
}

// Plan is what a time native command does.
type Plan struct {
	What   string   // time native, time native sync, time native sync fix
	Refuse string   // set: nothing is changed; Steps (read-only) still show why
	Warn   []string // said, and Enter waited for, before anything runs
	Notes  []string // said first
	Undo   []string // how to put back what fix changes
	Steps  []Step
	// Measure: dpt's own measurement of the clock, before (sync) and after
	MeasureBefore, MeasureAfter bool
}

// Env is what the plans depend on, read from the system (Detect).
type Env struct {
	OS     string // windows, darwin, linux
	Domain string // Windows: the domain the PC is joined to, or ""
	// Linux: the time service, "" when none is installed
	// (chrony, systemd-timesyncd, ntp)
	Service, Unit string // the kind, and its systemd unit
	Active        bool
}

func step(admin bool, argv ...string) Step {
	return Step{Line: strings.Join(argv, " "), Argv: argv, Admin: admin}
}

// Status is time native: what the system says of its clock.
func Status(e Env) Plan {
	p := Plan{What: "time native", MeasureAfter: true}
	p.Steps = statusSteps(e, &p)
	return p
}

func statusSteps(e Env, p *Plan) []Step {
	var s []Step
	switch e.OS {
	case "windows":
		s = append(s, step(false, "w32tm", "/query", "/status"))
		for _, srv := range Servers {
			s = append(s, step(false, "w32tm", "/stripchart", "/computer:"+srv, "/samples:5", "/dataonly"))
		}
	case "darwin":
		for _, srv := range Servers {
			s = append(s, step(false, "sntp", srv))
		}
	case "linux":
		switch e.Service {
		case "chrony":
			s = append(s, step(false, "chronyc", "tracking"), step(false, "chronyc", "sources", "-v"))
		case "systemd-timesyncd":
			s = append(s, step(false, "timedatectl", "status"), step(false, "timedatectl", "timesync-status"))
		case "ntp":
			s = append(s, step(false, "ntpq", "-p"))
		default:
			s = append(s, step(false, "timedatectl", "status"))
		}
		if !e.Active {
			p.Notes = appendOnce(p.Notes, linuxNoService(e))
		}
	}
	return s
}

func appendOnce(l []string, s string) []string {
	if s == "" || slices.Contains(l, s) {
		return l
	}
	return append(l, s)
}

func linuxNoService(e Env) string {
	if e.Service == "" {
		return "no time service is installed (chrony, systemd-timesyncd, ntp): nothing keeps this clock in sync"
	}
	return e.Unit + " is installed but not running: nothing keeps this clock in sync (time native sync fix starts it)"
}

// Sync is time native sync: resync now.
func Sync(e Env) Plan {
	p := Plan{What: "time native sync", MeasureBefore: true, MeasureAfter: true}
	switch e.OS {
	case "windows":
		if e.Domain != "" {
			p.Notes = append(p.Notes, "this PC is on the domain "+e.Domain+": it resyncs with its domain controller")
		}
		p.Steps = append(p.Steps, step(true, "w32tm", "/resync", "/force"))
	case "darwin":
		p.Steps = append(p.Steps, step(true, "sntp", "-sS", "time.apple.com"))
	case "linux":
		switch {
		case !e.Active:
			p.Refuse = linuxNoService(e)
			return p
		case e.Service == "chrony":
			p.Steps = append(p.Steps, step(true, "chronyc", "makestep"))
		default:
			p.Steps = append(p.Steps, step(true, "systemctl", "restart", e.Unit))
		}
	default:
		p.Refuse = "time native is for Windows, macOS and Linux"
		return p
	}
	p.Steps = append(p.Steps, statusSteps(e, &p)...)
	return p
}

// Warning is said before fix changes anything.
const Warning = "you should be the system admin to run this fix: it changes how this machine keeps its time"

// Fix is time native sync fix: set the system to keep its clock in sync.
func Fix(e Env) Plan {
	p := Plan{What: "time native sync fix", MeasureBefore: true, MeasureAfter: true}
	switch e.OS {
	case "windows":
		if e.Domain != "" {
			p.Refuse = "this PC is on the domain " + e.Domain + ": it MUST get its time from a domain controller.\n" +
				"fix changes nothing here (a PC with its own time breaks Kerberos logins, and a\n" +
				"network's time is set on its domain controllers). time native sync resyncs with it."
			p.Steps = []Step{step(false, "w32tm", "/query", "/source")}
			return p
		}
		p.Warn = []string{Warning,
			"this PC is on no domain (a PC on a domain must take its time from a domain controller: fix refuses there)"}
		const key = `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient`
		var peers []string
		for _, s := range Servers {
			peers = append(peers, s+",0x9") // 0x1 SpecialPollInterval, 0x8 as a client
		}
		peerArg := `/manualpeerlist:"` + strings.Join(peers, " ") + `"`
		p.Notes = append(p.Notes, fmt.Sprintf("fix: Windows Time starts with Windows, syncs with %s, every %d minutes",
			strings.Join(Servers, ", "), PollSeconds/60))
		p.Undo = []string{
			`w32tm /config /manualpeerlist:time.windows.com,0x9 /syncfromflags:manual /update`,
			`reg add ` + key + ` /v SpecialPollInterval /t REG_DWORD /d 604800 /f`,
		}
		start := step(true, "net", "start", "w32time")
		start.MayFail = true // already started
		resync := step(true, "w32tm", "/resync", "/force")
		resync.MayFail = true // just set: it may have no answer yet
		p.Steps = []Step{
			step(false, "w32tm", "/query", "/peers"),
			step(false, "reg", "query", key, "/v", "SpecialPollInterval"),
			{Line: "sc config w32time start= auto", Argv: []string{"sc", "config", "w32time", "start=", "auto"}, Admin: true},
			start,
			step(true, "reg", "add", key, "/v", "SpecialPollInterval", "/t", "REG_DWORD", "/d", fmt.Sprint(PollSeconds), "/f"),
			{Line: "w32tm /config " + peerArg + " /syncfromflags:manual /update",
				Argv: []string{"w32tm", "/config", "/manualpeerlist:" + strings.Join(peers, " "), "/syncfromflags:manual", "/update"}, Admin: true},
			resync,
		}
	case "darwin":
		p.Warn = []string{Warning}
		p.Notes = append(p.Notes, "fix: network time on, from time.apple.com (macOS keeps one time server, and has no sync interval to set: timed decides)")
		p.Undo = []string{"sudo systemsetup -setusingnetworktime off   (only if it was off before)"}
		p.Steps = []Step{
			step(true, "systemsetup", "-getusingnetworktime"),
			step(true, "systemsetup", "-getnetworktimeserver"),
			step(true, "systemsetup", "-setnetworktimeserver", "time.apple.com"),
			step(true, "systemsetup", "-setusingnetworktime", "on"),
			step(true, "sntp", "-sS", "time.apple.com"),
		}
	case "linux":
		switch {
		case e.Active:
			p.Notes = append(p.Notes, "nothing to fix: "+e.Unit+" is running and keeps this clock in sync")
			p.Steps = statusSteps(e, &p)
			p.MeasureBefore = false
			return p
		case e.Service == "":
			p.Refuse = "no time service is installed: install chrony (apt install chrony, dnf install chrony), then run this again"
			return p
		}
		p.Warn = []string{Warning}
		p.Undo = []string{"sudo systemctl disable --now " + e.Unit}
		if e.Service == "systemd-timesyncd" {
			p.Steps = []Step{step(true, "timedatectl", "set-ntp", "true")}
		} else {
			p.Steps = []Step{step(true, "systemctl", "enable", "--now", e.Unit)}
		}
		if e.Service == "chrony" {
			mk := step(true, "chronyc", "makestep")
			mk.MayFail = true // just started: it may have no measurement yet
			p.Steps = append(p.Steps, mk)
		}
		e.Active = true
	default:
		p.Refuse = "time native is for Windows, macOS and Linux"
		return p
	}
	p.Steps = append(p.Steps, statusSteps(e, &p)...)
	return p
}

// Options are how a plan is run.
type Options struct {
	Out   io.Writer
	Color bool
	// Wait shows prompt and waits for Enter; an error (Ctrl-C, end of
	// input) stops.  nil: from a script, nothing is waited for.
	Wait func(prompt string) error
	// Elevated: Administrator or root already
	Elevated bool
	// Elevate runs steps [from, to) as Administrator (Windows: UAC) and
	// gives their exit code; nil: sudo before each command (Linux, macOS)
	Elevate func(from, to int) (int, error)
	// From, To: run only these steps (the elevated copy on Windows)
	From, To int
}

// Exit codes, as dpt's.
const (
	exitOK    = 0
	exitFail  = 1
	exitMEL   = 2
	exitUsage = 3
)

// ErrStopped is a wait that was answered with Ctrl-C.
var ErrStopped = errors.New("stopped")

// Run runs the plan, each command shown and waited for, and gives dpt's
// exit code.
func Run(ctx context.Context, p Plan, o Options) int {
	bold := func(s string) string { return paint(o.Color, "1", s) }
	part := o.To > 0 // the elevated copy: the steps, nothing else
	if !part {
		fmt.Fprintln(o.Out, bold(strings.ToUpper(p.What)))
		for _, n := range p.Notes {
			fmt.Fprintln(o.Out, "  "+n)
		}
		if p.Refuse != "" {
			for _, l := range strings.Split(p.Refuse, "\n") {
				fmt.Fprintln(o.Out, "  "+paint(o.Color, "1;31", l))
			}
		}
		if len(p.Warn) > 0 && p.Refuse == "" {
			if o.Wait == nil {
				fmt.Fprintln(o.Out, "  "+p.What+" asks at a terminal before it changes anything: run it there")
				return exitUsage
			}
			fmt.Fprintln(o.Out)
			for _, w := range p.Warn {
				fmt.Fprintln(o.Out, "  "+paint(o.Color, "1;33", w))
			}
			if len(p.Undo) > 0 {
				fmt.Fprintln(o.Out, "  to put it back:")
				for _, u := range p.Undo {
					fmt.Fprintln(o.Out, "    "+u)
				}
			}
			if o.Wait("\n  Enter to go on, Ctrl-C to stop: ") != nil {
				fmt.Fprintln(o.Out, "  stopped: nothing changed")
				return exitFail
			}
		}
		if p.MeasureBefore && p.Refuse == "" {
			Measure(ctx, o.Out, o.Color, "before")
		}
	}
	steps, from := p.Steps, 0
	if part {
		if o.From < 0 || o.To > len(steps) || o.From >= o.To {
			fmt.Fprintln(os.Stderr, "dpt: time native: no such steps")
			return exitUsage
		}
		steps, from = steps[o.From:o.To], o.From
	}
	code := exitOK
	for i := 0; i < len(steps); i++ {
		s := steps[i]
		if s.Admin && !o.Elevated && p.Refuse == "" {
			if o.Elevate != nil {
				// Windows: the admin commands in a row, shown and waited for
				// each, then one UAC prompt for them all
				j := i
				for j < len(steps) && steps[j].Admin {
					j++
				}
				fmt.Fprintln(o.Out)
				fmt.Fprintln(o.Out, "  as Administrator:")
				for _, x := range steps[i:j] {
					fmt.Fprintln(o.Out, "  "+bold("$ "+x.Line))
					if o.Wait != nil && o.Wait("    Enter to run it, Ctrl-C to stop: ") != nil {
						fmt.Fprintln(o.Out, "  stopped: nothing of these ran")
						return exitFail
					}
				}
				if o.Wait == nil {
					fmt.Fprintln(o.Out, "  these need an Administrator prompt")
					return exitMEL
				}
				c, err := o.Elevate(from+i, from+j)
				if err != nil {
					fmt.Fprintf(o.Out, "  not run: %v\n", err)
					return exitMEL
				}
				if c != exitOK {
					code = exitFail
				}
				i = j - 1
				continue
			}
			if o.Wait == nil {
				fmt.Fprintf(o.Out, "  $ %s needs sudo, or root: from a script it is not asked for\n", s.Line)
				return exitMEL
			}
			s.Line, s.Argv = "sudo "+s.Line, append([]string{"sudo"}, s.Argv...)
		}
		if s.Admin && p.Refuse != "" {
			continue // refused: only what reads runs
		}
		fmt.Fprintln(o.Out)
		fmt.Fprintln(o.Out, bold("$ "+s.Line))
		if o.Wait != nil {
			if err := o.Wait("  Enter to run it, Ctrl-C to stop: "); err != nil {
				fmt.Fprintln(o.Out, "  stopped")
				return exitFail
			}
		}
		if err := runStep(ctx, s, o.Out); err != nil {
			if s.MayFail {
				fmt.Fprintf(o.Out, "  (%v: that is all right here)\n", err)
				continue
			}
			fmt.Fprintf(o.Out, "  %s\n", paint(o.Color, "1;31", err.Error()))
			code = exitFail
			if s.Admin {
				break // a change that failed: the next ones may depend on it
			}
		}
		if ctx.Err() != nil {
			return exitFail
		}
	}
	if !part {
		if p.MeasureAfter && p.Refuse == "" {
			fmt.Fprintln(o.Out)
			Measure(ctx, o.Out, o.Color, "now")
		}
		if p.Refuse != "" {
			code = exitFail
		}
	}
	return code
}

// runStep runs one command, its output to w.
func runStep(ctx context.Context, s Step, w io.Writer) error {
	path, err := exec.LookPath(s.Argv[0])
	if err != nil {
		return fmt.Errorf("%s is not on this system", s.Argv[0])
	}
	c := exec.CommandContext(ctx, path, s.Argv[1:]...)
	exactLine(c, s)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, w, w
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("exit %d", ee.ExitCode())
		}
		return err
	}
	return nil
}

func paint(on bool, code, s string) string {
	if !on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Measure writes dpt's own measurement of this clock, against Servers:
//
//	dpt now: this clock is 452.1 ms behind  (time.cloudflare.com +452.0 ms ...)
func Measure(ctx context.Context, w io.Writer, color bool, when string) {
	type got struct {
		srv string
		off time.Duration
		err error
	}
	res := make([]got, len(Servers))
	var wg sync.WaitGroup
	for i, s := range Servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := dpt.NTPQuery(ctx, s, 2*time.Second)
			res[i] = got{srv: s, err: err}
			if err == nil {
				if r.Unsynchronised() {
					res[i].err = errors.New("unsynchronised")
				} else {
					res[i].off = r.Offset
				}
			}
		}()
	}
	wg.Wait()
	var offs []time.Duration
	var each []string
	for _, g := range res {
		if g.err != nil {
			each = append(each, g.srv+" no answer")
			continue
		}
		offs = append(offs, g.off)
		each = append(each, fmt.Sprintf("%s %+.1f ms", g.srv, float64(g.off)/float64(time.Millisecond)))
	}
	head := paint(color, "1", "dpt "+when+":")
	if len(offs) == 0 {
		fmt.Fprintf(w, "%s no time server answered  (%s)\n", head, strings.Join(each, ", "))
		return
	}
	slices.Sort(offs)
	local := -offs[len(offs)/2] // the servers' offset is theirs minus ours
	fmt.Fprintf(w, "%s this clock is %s  (%s)\n", head, ClockWords(local), strings.Join(each, ", "))
}

// ClockWords: "452.1 ms behind", "1.2 ms ahead", "in step (0.3 ms)".
func ClockWords(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	switch {
	case ms > -0.5 && ms < 0.5:
		return fmt.Sprintf("in step (%.1f ms)", ms)
	case ms < 0:
		return fmt.Sprintf("%.1f ms behind", -ms)
	}
	return fmt.Sprintf("%.1f ms ahead", ms)
}
