// SPDX-License-Identifier: MIT

//go:build windows

package dpt

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// clockRead: Windows Time's settings in the registry (what it syncs from,
// and whether the service may run at all), the zone's name, and
// "w32tm /query /status" for where the time last came from.  With no
// server set, or the service off, the clock is the machine's own: "Set
// time automatically" is off in Settings.
func clockRead(c *DPTClock) {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, registry.QUERY_VALUE); err == nil {
		if z, _, err := k.GetStringValue("TimeZoneKeyName"); err == nil && z != "" {
			c.Zone = Safe(z)
		}
		k.Close()
	}
	start := uint64(0)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\W32Time`, registry.QUERY_VALUE); err == nil {
		start, _, _ = k.GetIntegerValue("Start")
		k.Close()
	}
	typ := ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\W32Time\Parameters`, registry.QUERY_VALUE); err == nil {
		typ, _, _ = k.GetStringValue("Type")
		k.Close()
		c.ReadFrom = append(c.ReadFrom, "Windows Time settings")
	}
	switch {
	case start == 4:
		c.Auto, c.Note = "no", "the Windows Time service is disabled"
	case strings.EqualFold(typ, "NoSync"):
		c.Auto = "no"
	case strings.EqualFold(typ, "NT5DS"):
		c.Auto, c.How = "yes", "the domain (its domain controllers)"
	case strings.EqualFold(typ, "AllSync"):
		c.Auto, c.How = "yes", "the domain, else NTP"
	case strings.EqualFold(typ, "NTP"):
		c.Auto, c.How = "yes", "NTP"
	}
	clockFromW32tm(c, clockRun("w32tm", "/query", "/status"))
}
