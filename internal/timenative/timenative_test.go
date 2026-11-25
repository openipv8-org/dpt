// SPDX-License-Identifier: MIT

package timenative

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func lines(p Plan) string {
	var l []string
	for _, s := range p.Steps {
		a := ""
		if s.Admin {
			a = "admin "
		}
		l = append(l, a+s.Line)
	}
	return strings.Join(l, "\n")
}

func TestWindowsPlans(t *testing.T) {
	e := Env{OS: "windows"}
	st := lines(Status(e))
	for _, want := range []string{"w32tm /query /status", "w32tm /stripchart /computer:time.cloudflare.com /samples:5 /dataonly",
		"/computer:time.google.com", "/computer:time.windows.com"} {
		if !strings.Contains(st, want) {
			t.Errorf("status: no %q in\n%s", want, st)
		}
	}
	if s := lines(Sync(e)); !strings.HasPrefix(s, "admin w32tm /resync /force\nw32tm /query /status") {
		t.Errorf("sync:\n%s", s)
	}

	f := Fix(e)
	fl := lines(f)
	for _, want := range []string{
		"admin sc config w32time start= auto",
		"admin net start w32time",
		`admin reg add HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient /v SpecialPollInterval /t REG_DWORD /d 3600 /f`,
		`admin w32tm /config /manualpeerlist:"time.cloudflare.com,0x9 time.google.com,0x9 time.windows.com,0x9" /syncfromflags:manual /update`,
		"admin w32tm /resync /force",
	} {
		if !strings.Contains(fl, want) {
			t.Errorf("fix: no %q in\n%s", want, fl)
		}
	}
	if f.Refuse != "" || len(f.Warn) == 0 || f.Warn[0] != Warning || len(f.Undo) != 2 {
		t.Errorf("fix: %+v", f)
	}
	// what runs is what is shown
	for _, s := range f.Steps {
		if strings.Join(s.Argv, " ") != strings.ReplaceAll(s.Line, `"`, "") {
			t.Errorf("argv %q is not the line %q", s.Argv, s.Line)
		}
	}
}

func TestWindowsDomainRefused(t *testing.T) {
	e := Env{OS: "windows", Domain: "CORP"}
	f := Fix(e)
	if f.Refuse == "" || !strings.Contains(f.Refuse, "MUST get its time from a domain controller") || !strings.Contains(f.Refuse, "CORP") {
		t.Fatalf("not refused: %+v", f)
	}
	for _, s := range f.Steps {
		if s.Admin {
			t.Errorf("a refused fix has a change in it: %s", s.Line)
		}
	}
	if len(f.Warn) != 0 {
		t.Error("refused: nothing to warn of")
	}
	// sync still resyncs, with the domain controller
	s := Sync(e)
	if s.Refuse != "" || !strings.Contains(strings.Join(s.Notes, " "), "domain controller") {
		t.Errorf("sync on a domain: %+v", s)
	}
}

func TestDarwinPlans(t *testing.T) {
	e := Env{OS: "darwin"}
	if s := lines(Status(e)); s != "sntp time.cloudflare.com\nsntp time.google.com\nsntp time.windows.com" {
		t.Errorf("status:\n%s", s)
	}
	if s := lines(Sync(e)); !strings.HasPrefix(s, "admin sntp -sS time.apple.com\nsntp time.cloudflare.com") {
		t.Errorf("sync:\n%s", s)
	}
	f := lines(Fix(e))
	if !strings.Contains(f, "admin systemsetup -setusingnetworktime on") || !strings.Contains(f, "admin systemsetup -setnetworktimeserver time.apple.com") {
		t.Errorf("fix:\n%s", f)
	}
}

func TestLinuxPlans(t *testing.T) {
	chrony := Env{OS: "linux", Service: "chrony", Unit: "chrony", Active: true}
	if s := lines(Status(chrony)); s != "chronyc tracking\nchronyc sources -v" {
		t.Errorf("status:\n%s", s)
	}
	if s := lines(Sync(chrony)); !strings.HasPrefix(s, "admin chronyc makestep") {
		t.Errorf("sync:\n%s", s)
	}
	f := Fix(chrony)
	if len(f.Warn) != 0 || strings.Contains(lines(f), "admin") || !strings.Contains(f.Notes[0], "nothing to fix") {
		t.Errorf("fix with chrony running changes something: %+v", f)
	}

	off := Env{OS: "linux", Service: "chrony", Unit: "chronyd"}
	if Sync(off).Refuse == "" {
		t.Error("sync with nothing running: not refused")
	}
	fo := lines(Fix(off))
	if !strings.HasPrefix(fo, "admin systemctl enable --now chronyd\nadmin chronyc makestep\nchronyc tracking") {
		t.Errorf("fix, chrony stopped:\n%s", fo)
	}
	ts := Env{OS: "linux", Service: "systemd-timesyncd", Unit: "systemd-timesyncd"}
	if s := lines(Fix(ts)); !strings.HasPrefix(s, "admin timedatectl set-ntp true\ntimedatectl status") {
		t.Errorf("fix, timesyncd:\n%s", s)
	}
	if Fix(Env{OS: "linux"}).Refuse == "" {
		t.Error("fix with no time service installed: not refused")
	}
}

// a plan of harmless commands
func fakePlan() Plan {
	fail := step(false, "false")
	return Plan{What: "time native test", Steps: []Step{
		step(false, "echo", "one"), fail, step(true, "echo", "two"), step(true, "echo", "three"), step(false, "echo", "four"),
	}}
}

func TestRunWaitsAndStops(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("echo and false are commands of Linux and macOS")
	}
	var b bytes.Buffer
	n := 0
	o := Options{Out: &b, Elevated: true, Wait: func(string) error {
		n++
		if n == 3 {
			return ErrStopped // Ctrl-C at the third command
		}
		return nil
	}}
	if code := Run(context.Background(), fakePlan(), o); code != exitFail {
		t.Errorf("exit %d", code)
	}
	out := b.String()
	if !strings.Contains(out, "$ echo one\none\n") || !strings.Contains(out, "$ echo two\n") || strings.Contains(out, "\ntwo\n") {
		t.Errorf("not stopped before the third:\n%s", out)
	}
}

func TestRunElevatesInOneGo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("echo and false are commands of Linux and macOS")
	}
	var b bytes.Buffer
	var asked [][2]int
	waits := 0
	o := Options{Out: &b, Wait: func(string) error { waits++; return nil },
		Elevate: func(from, to int) (int, error) { asked = append(asked, [2]int{from, to}); return 0, nil }}
	p := fakePlan()
	p.Steps[1].MayFail = true
	if code := Run(context.Background(), p, o); code != exitOK {
		t.Errorf("exit %d:\n%s", code, b.String())
	}
	if len(asked) != 1 || asked[0] != [2]int{2, 4} {
		t.Errorf("elevated %v, want steps 2-4 at once", asked)
	}
	if waits != 5 {
		t.Errorf("%d waits, want one per command (5)", waits)
	}
	if !strings.Contains(b.String(), "$ echo four\nfour") {
		t.Errorf("did not go on after the admin commands:\n%s", b.String())
	}

	// the elevated copy: those steps only, no waiting, no measuring
	b.Reset()
	if code := Run(context.Background(), p, Options{Out: &b, Elevated: true, From: 2, To: 4}); code != exitOK {
		t.Errorf("copy: exit %d", code)
	}
	if got := b.String(); strings.Contains(got, "one") || !strings.Contains(got, "two") || !strings.Contains(got, "three") ||
		strings.Contains(got, "four") || strings.Contains(got, "dpt now") {
		t.Errorf("copy ran:\n%s", got)
	}
}

func TestRunFixNeedsATerminal(t *testing.T) {
	var b bytes.Buffer
	p := Fix(Env{OS: "darwin"})
	if code := Run(context.Background(), p, Options{Out: &b}); code != exitUsage || !strings.Contains(b.String(), "asks at a terminal") {
		t.Errorf("fix from a script: exit %d\n%s", code, b.String())
	}
	// the warning stops it when not agreed to
	b.Reset()
	code := Run(context.Background(), p, Options{Out: &b, Wait: func(string) error { return errors.New("no") }})
	if code != exitFail || !strings.Contains(b.String(), Warning) || !strings.Contains(b.String(), "nothing changed") {
		t.Errorf("warning refused: exit %d\n%s", code, b.String())
	}
}

func TestClockWords(t *testing.T) {
	for d, want := range map[float64]string{-452.1: "452.1 ms behind", 1.25: "1.2 ms ahead", 0.2: "in step (0.2 ms)"} {
		if got := ClockWords(msDur(d)); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

func msDur(ms float64) time.Duration { return time.Duration(ms * float64(time.Millisecond)) }
