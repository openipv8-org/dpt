// SPDX-License-Identifier: MIT

//go:build linux

package dpt

import (
	"os"
	"path/filepath"
	"strings"
)

// clockRead: timedatectl (systemd) for the zone and whether NTP is on,
// chronyc for where the time came from and how far off it was.  Neither
// sends anything off the machine.
func clockRead(c *DPTClock) {
	clockFromTimedatectl(c, clockRun("timedatectl", "show"))
	clockFromChrony(c, clockRun("chronyc", "-n", "tracking"))
	if c.Source == "" {
		m := clockKV(clockRun("timedatectl", "show-timesync"), "=")
		if s := m["servername"]; s != "" && c.Synced == "yes" {
			c.Source = Safe(s)
		}
	}
	if !strings.Contains(c.Zone, "/") {
		if l, err := os.Readlink("/etc/localtime"); err == nil {
			if _, z, ok := strings.Cut(l, "zoneinfo/"); ok {
				c.Zone = Safe(z)
			}
		}
	}
	if c.Auto == "" {
		// no timedatectl: is an NTP daemon set up at all?
		for _, f := range []string{"/etc/chrony/chrony.conf", "/etc/chrony.conf", "/etc/ntp.conf", "/etc/ntpsec/ntp.conf", "/etc/openntpd/ntpd.conf"} {
			if _, err := os.Stat(f); err == nil {
				c.Auto, c.How = "yes", "NTP ("+filepath.Base(filepath.Dir(f))+"/"+filepath.Base(f)+")"
				break
			}
		}
		if c.Auto == "" {
			c.Note = "no timedatectl and no NTP daemon's settings found"
		}
	}
}
