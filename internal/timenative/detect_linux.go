// SPDX-License-Identifier: MIT

//go:build linux

package timenative

import (
	"os"
	"os/exec"
	"strings"
)

// linuxServices are the time services, as systemd names their units.
var linuxServices = []struct{ kind, unit, program string }{
	{"chrony", "chrony", "chronyc"},
	{"chrony", "chronyd", "chronyc"},
	{"systemd-timesyncd", "systemd-timesyncd", ""},
	{"ntp", "ntpsec", "ntpq"},
	{"ntp", "ntp", "ntpq"},
	{"ntp", "ntpd", "ntpq"},
}

// Detect reads the system: which time service runs (the first that
// does), else which is installed.
func Detect() Env {
	e := Env{OS: "linux"}
	for _, s := range linuxServices {
		if unitState(s.unit, "is-active") == "active" {
			e.Service, e.Unit, e.Active = s.kind, s.unit, true
			return e
		}
	}
	for _, s := range linuxServices {
		st := unitState(s.unit, "is-enabled")
		if st != "" && st != "not-found" && !strings.Contains(st, "No such") && (s.program == "" || onPath(s.program)) {
			e.Service, e.Unit = s.kind, s.unit
			return e
		}
	}
	if _, err := os.Stat("/lib/systemd/systemd-timesyncd"); err == nil {
		e.Service, e.Unit = "systemd-timesyncd", "systemd-timesyncd"
	}
	return e
}

// unitState is systemctl's word for a unit: active, inactive, enabled,
// disabled, masked, not-found...; "" when there is no systemctl.
func unitState(unit, verb string) string {
	out, err := exec.Command("systemctl", verb, unit).Output()
	s := strings.TrimSpace(string(out))
	if s == "" && err != nil {
		return ""
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func onPath(p string) bool {
	_, err := exec.LookPath(p)
	return err == nil
}

func exactLine(*exec.Cmd, Step) {}
