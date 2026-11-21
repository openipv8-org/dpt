// SPDX-License-Identifier: MIT

//go:build darwin

package dpt

import (
	"os"
	"strings"
)

// clockRead: the zone from /etc/localtime; "Set time and date
// automatically" from systemsetup, which answers only an administrator,
// else from whether Date & Time has a server in /etc/ntp.conf.
func clockRead(c *DPTClock) {
	if l, err := os.Readlink("/etc/localtime"); err == nil {
		if _, z, ok := strings.Cut(l, "zoneinfo/"); ok {
			c.Zone = Safe(z)
		}
	}
	// "Network Time: On" / "Network Time: Off"
	if out := clockRun("/usr/sbin/systemsetup", "-getusingnetworktime"); strings.Contains(out, "Network Time:") {
		c.Auto, c.How = yesNo(strings.Contains(out, ": On")), "NTP"
		c.ReadFrom = append(c.ReadFrom, "systemsetup")
		if out := clockRun("/usr/sbin/systemsetup", "-getnetworktimeserver"); out != "" {
			if _, s, ok := strings.Cut(out, ": "); ok {
				c.Source = Safe(strings.TrimSpace(s))
			}
		}
		return
	}
	if b, err := os.ReadFile("/etc/ntp.conf"); err == nil {
		if s := ntpConfServers(string(b)); len(s) > 0 {
			c.How, c.Source = "NTP", s[0]
			c.Note = "on or off is shown to an administrator only (sudo dpt info)"
			c.ReadFrom = append(c.ReadFrom, "/etc/ntp.conf")
			return
		}
	}
	c.Note = "on or off is shown to an administrator only (sudo dpt info)"
}
