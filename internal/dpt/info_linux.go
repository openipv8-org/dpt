// SPDX-License-Identifier: MIT

//go:build linux

package dpt

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func infoDNSSource() string { return "/etc/resolv.conf" }

// infoLease looks where Linux's DHCP clients keep their lease: dhcpcd,
// systemd-networkd, NetworkManager (internal client and dhclient), and
// dhclient.
func infoLease(i net.Interface) (*DPTLease, string) {
	note := ""
	try := func(path string, parse func(b []byte, mtime time.Time) *DPTLease) *DPTLease {
		l, n, found := readLease(path, parse)
		if found && n != "" && note == "" {
			note = n
		}
		return l
	}
	packet := func(path string) func([]byte, time.Time) *DPTLease {
		return func(b []byte, t time.Time) *DPTLease { return leaseFromPacket(b, t, path) }
	}
	kv := func(path string) func([]byte, time.Time) *DPTLease {
		return func(b []byte, t time.Time) *DPTLease { return leaseFromKV(string(b), t, path) }
	}
	dhc := func(path string) func([]byte, time.Time) *DPTLease {
		return func(b []byte, _ time.Time) *DPTLease { return leaseFromDhclient(string(b), i.Name, path) }
	}
	for _, p := range []string{"/var/lib/dhcpcd/" + i.Name + ".lease", "/var/lib/dhcpcd/dhcpcd-" + i.Name + ".lease", "/var/lib/dhcpcd5/dhcpcd-" + i.Name + ".lease", "/var/db/dhcpcd/" + i.Name + ".lease"} {
		if l := try(p, packet(p)); l != nil {
			return l, ""
		}
	}
	p := "/run/systemd/netif/leases/" + strconv.Itoa(i.Index)
	if l := try(p, kv(p)); l != nil {
		return l, ""
	}
	nm, _ := filepath.Glob("/var/lib/NetworkManager/internal-*-" + i.Name + ".lease")
	for _, p := range newestFirst(nm) {
		if l := try(p, kv(p)); l != nil {
			return l, ""
		}
	}
	var dh []string
	for _, g := range []string{"/var/lib/NetworkManager/dhclient-*-" + i.Name + ".lease", "/var/lib/dhcp/dhclient*.leases", "/var/lib/dhcp/dhclient*.lease", "/var/lib/dhclient/*.lease*"} {
		m, _ := filepath.Glob(g)
		dh = append(dh, m...)
	}
	for _, p := range newestFirst(dh) {
		if l := try(p, dhc(p)); l != nil {
			return l, ""
		}
	}
	if note != "" {
		return nil, note
	}
	return nil, leaseNone
}

func newestFirst(paths []string) []string {
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

// infoNTP: the time servers the running time service is set to use:
// chrony, systemd-timesyncd or ntpd.
func infoNTP() ([]string, string) {
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	chrony := func() ([]string, string) {
		for _, c := range []string{"/etc/chrony/chrony.conf", "/etc/chrony.conf"} {
			if exists(c) {
				return uniq(chronySources(c, 0, map[string]bool{})), "chrony: " + c
			}
		}
		return nil, ""
	}
	timesyncd := func() ([]string, string) {
		files := []string{"/etc/systemd/timesyncd.conf"}
		for _, d := range []string{"/usr/lib/systemd/timesyncd.conf.d", "/etc/systemd/timesyncd.conf.d", "/run/systemd/timesyncd.conf.d"} {
			m, _ := filepath.Glob(d + "/*.conf")
			files = append(files, m...)
		}
		var ntp, fallback []string
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			kv := leaseKV(string(b))
			if v, ok := kv["NTP"]; ok {
				ntp = safeFields(v)
			}
			if v, ok := kv["FallbackNTP"]; ok {
				fallback = safeFields(v)
			}
		}
		if len(ntp) > 0 {
			return ntp, "systemd-timesyncd"
		}
		if len(fallback) > 0 {
			return fallback, "systemd-timesyncd fallback"
		}
		return nil, "systemd-timesyncd (built-in defaults, or servers from DHCP)"
	}
	ntpd := func() ([]string, string) {
		for _, c := range []string{"/etc/ntpsec/ntp.conf", "/etc/ntp.conf"} {
			if b, err := os.ReadFile(c); err == nil {
				return uniq(ntpConfServers(string(b))), "ntpd: " + c
			}
		}
		return nil, ""
	}
	switch {
	case exists("/run/chrony") || exists("/run/chronyd.pid") || exists("/var/run/chrony"):
		return chrony()
	case exists("/run/systemd/timesync"):
		return timesyncd()
	case exists("/run/ntpd.pid") || exists("/var/run/ntpd.pid"):
		return ntpd()
	}
	for _, f := range []func() ([]string, string){chrony, ntpd} {
		if s, src := f(); src != "" {
			return s, src + " (not running)"
		}
	}
	return nil, "no time service found"
}
