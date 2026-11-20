// SPDX-License-Identifier: MIT

//go:build darwin

package dpt

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func infoDNSSource() string { return "/etc/resolv.conf" }

// infoLease: the lease configd keeps (/var/db/dhcpclient/leases: the
// server's message and when it started), else what "ipconfig getpacket"
// shows (no start time there).
func infoLease(i net.Interface) (*DPTLease, string) {
	note := ""
	files, _ := filepath.Glob("/var/db/dhcpclient/leases/" + i.Name + "-*")
	for _, p := range newestFirstDarwin(files) {
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsPermission(err) && note == "" {
				note = "the lease (" + p + ") " + leaseNeedsPriv + DHCPNeeds + " to read: sudo dpt info"
			}
			continue
		}
		if l := leaseFromPlist(b, p); l != nil {
			return l, ""
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/ipconfig", "getpacket", i.Name).Output()
	if err == nil {
		if l := leaseFromGetpacket(string(out), "ipconfig getpacket "+i.Name); l != nil {
			return l, ""
		}
	}
	if note != "" {
		return nil, note
	}
	return nil, leaseNone
}

func newestFirstDarwin(paths []string) []string {
	type pt struct {
		p string
		t time.Time
	}
	var v []pt
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil {
			v = append(v, pt{p, st.ModTime()})
		}
	}
	for a := 1; a < len(v); a++ {
		for b := a; b > 0 && v[b].t.After(v[b-1].t); b-- {
			v[b], v[b-1] = v[b-1], v[b]
		}
	}
	out := make([]string, len(v))
	for k := range v {
		out[k] = v[k].p
	}
	return out
}

// infoNTP: macOS's Date & Time server, kept in /etc/ntp.conf.
func infoNTP() ([]string, string) {
	b, err := os.ReadFile("/etc/ntp.conf")
	if err != nil {
		return nil, "Date & Time: no /etc/ntp.conf"
	}
	return uniq(ntpConfServers(string(b))), "Date & Time: /etc/ntp.conf"
}
