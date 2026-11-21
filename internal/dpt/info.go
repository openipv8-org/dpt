// SPDX-License-Identifier: MIT

package dpt

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// dpt info: what this machine already has, read from the system (NTP
// time requests are sent, to see how far off its clock is, and
// OutsideIPURL is asked for the outside addresses): each interface's
// address and gateway, the DHCP lease it holds (server, times, the DNS
// and NTP servers in it), the DNS and NTP servers the machine uses, and
// the addresses the internet sees.

// DPTInfo is the machine's picture.
type DPTInfo struct {
	Ifaces    []DPTInfoIface `json:"interfaces"`
	DNS       []string       `json:"dns_servers"`
	DNSSource string         `json:"dns_source,omitempty"`
	NTP       []string       `json:"ntp_servers"`
	NTPSource string         `json:"ntp_source,omitempty"`
	VPN       []string       `json:"vpn_tunnel,omitempty"`
	Clock     *DPTClock      `json:"clock,omitempty"`
	Time      *DPTTime       `json:"time,omitempty"` // the time services and this clock against them
	Outside   *DPTOutside    `json:"outside,omitempty"`
}

// DPTInfoIface is one interface.
type DPTInfoIface struct {
	Name      string    `json:"name"`
	MAC       string    `json:"mac,omitempty"`
	Addrs     []string  `json:"addresses"`
	Gateway   string    `json:"gateway,omitempty"`
	Lease     *DPTLease `json:"dhcp,omitempty"`
	LeaseNote string    `json:"dhcp_note,omitempty"`
}

// DPTLease is the DHCP lease an interface holds.
type DPTLease struct {
	Server   string     `json:"server,omitempty"`
	Address  string     `json:"address,omitempty"`
	Length   string     `json:"lease,omitempty"`
	Obtained *time.Time `json:"obtained,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`
	DNS      []string   `json:"dns,omitempty"`
	NTP      []string   `json:"ntp,omitempty"`
	Domain   string     `json:"domain,omitempty"`
	Source   string     `json:"source"`
	// NTPNotKept: the system keeps no record of the NTP servers in the
	// lease (Windows), so none is not known to be none
	NTPNotKept bool `json:"ntp_not_kept,omitempty"`
}

// Lease notes.
const (
	leaseNeedsPriv = "needs " // + DHCPNeeds + to read <file>
	leaseNone      = "no DHCP lease found: a static address?"
)

// DPTInfoGather reads the machine; dns is the system's resolvers.  With
// iface, only that interface is shown (with an address or not).
func DPTInfoGather(dns []string, iface string) *DPTInfo {
	r := &DPTInfo{DNS: dns, DNSSource: infoDNSSource(), VPN: DPTVPNTunnels()}
	r.NTP, r.NTPSource = infoNTP()
	r.Clock = DPTClockGather()
	gw := gateways()
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if iface != "" && i.Name != iface || iface == "" && !dptProbeable(i) {
			continue
		}
		x := DPTInfoIface{Name: i.Name, MAC: i.HardwareAddr.String()}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				x.Addrs = append(x.Addrs, n.String())
			}
		}
		if g := gw[i.Index]; g != nil {
			x.Gateway = g.String()
		}
		x.Lease, x.LeaseNote = infoLease(i)
		r.Ifaces = append(r.Ifaces, x)
	}
	return r
}

// leaseFromPacket reads a lease kept as the server's DHCP message (dhcpcd's
// lease file, macOS's PacketData); obtained may be zero.
func leaseFromPacket(b []byte, obtained time.Time, source string) *DPTLease {
	m, err := ParseDHCP(b)
	if err != nil {
		return nil
	}
	l := &DPTLease{Source: source}
	if ip := m.YIAddr; ip != nil && !ip.IsUnspecified() {
		l.Address = ip.String()
	} else if ip := m.CIAddr; ip != nil && !ip.IsUnspecified() {
		l.Address = ip.String()
	}
	if v := m.Get(54); len(v) == 4 {
		l.Server = net.IP(v).String()
	}
	if v := m.Get(51); len(v) == 4 {
		l.setLength(time.Duration(uint32(v[0])<<24|uint32(v[1])<<16|uint32(v[2])<<8|uint32(v[3]))*time.Second, obtained)
	} else if !obtained.IsZero() {
		l.Obtained = &obtained
	}
	l.DNS = ipList4(m.Get(6))
	l.NTP = ipList4(m.Get(42))
	if v := m.Get(15); len(v) > 0 {
		l.Domain = Safe(strings.TrimRight(string(v), "\x00"))
	}
	return l
}

func ipList4(d []byte) []string {
	var out []string
	for i := 0; i+4 <= len(d); i += 4 {
		out = append(out, net.IP(d[i:i+4]).String())
	}
	return out
}

// setLength records the lease length and, from when it was obtained, when
// it expires.  0xffffffff is infinite.
func (l *DPTLease) setLength(d time.Duration, obtained time.Time) {
	if d == 0xffffffff*time.Second {
		l.Length = "infinite"
	} else if d > 0 {
		l.Length = d.String()
	}
	if !obtained.IsZero() {
		l.Obtained = &obtained
		if d > 0 && l.Length != "infinite" {
			e := obtained.Add(d)
			l.Expires = &e
		}
	}
}

// leaseFromKV reads systemd-networkd's lease (and NetworkManager's
// internal client's, the same format): KEY=value lines.
func leaseFromKV(s string, obtained time.Time, source string) *DPTLease {
	kv := leaseKV(s)
	if kv["ADDRESS"] == "" && kv["SERVER_ADDRESS"] == "" {
		return nil
	}
	l := &DPTLease{Source: source, Address: Safe(kv["ADDRESS"]), Server: Safe(kv["SERVER_ADDRESS"]), Domain: Safe(kv["DOMAINNAME"])}
	n, _ := strconv.Atoi(kv["LIFETIME"])
	l.setLength(time.Duration(n)*time.Second, obtained)
	l.DNS = safeFields(kv["DNS"])
	l.NTP = safeFields(kv["NTP"])
	return l
}

// dhcpNameServers reads Windows's DhcpNameServer value: addresses
// separated by spaces (or commas).
func dhcpNameServers(v string) []string { return safeFields(strings.TrimSpace(v)) }

// leaseKV reads KEY=value lines (lease files, systemd .conf files).
func leaseKV(s string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return kv
}

func safeFields(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' }) {
		out = append(out, Safe(f))
	}
	return out
}

// leaseFromDhclient reads the newest lease for iface in an ISC dhclient
// leases file.  The times in it are UTC: "expire 4 2026/11/19 12:00:00;".
func leaseFromDhclient(s, iface, source string) *DPTLease {
	var best *DPTLease
	var bestExp time.Time
	for _, block := range strings.Split(s, "lease {")[1:] {
		block, _, _ = strings.Cut(block, "}")
		l := &DPTLease{Source: source}
		var ifc string
		var length time.Duration
		var expire time.Time
		for _, line := range strings.Split(block, ";") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) < 2 {
				continue
			}
			switch {
			case f[0] == "interface":
				ifc = strings.Trim(f[1], `"`)
			case f[0] == "fixed-address":
				l.Address = Safe(f[1])
			case f[0] == "expire" && len(f) >= 4:
				expire, _ = time.Parse("2006/01/02 15:04:05", f[2]+" "+f[3])
			case f[0] == "option" && len(f) >= 3:
				v := strings.Trim(strings.Join(f[2:], " "), `"`)
				switch f[1] {
				case "dhcp-server-identifier":
					l.Server = Safe(v)
				case "dhcp-lease-time":
					n, _ := strconv.Atoi(v)
					length = time.Duration(n) * time.Second
				case "domain-name-servers":
					l.DNS = safeFields(v)
				case "ntp-servers":
					l.NTP = safeFields(v)
				case "domain-name":
					l.Domain = Safe(v)
				}
			}
		}
		if ifc != iface {
			continue
		}
		var obtained time.Time
		if !expire.IsZero() && length > 0 {
			obtained = expire.Add(-length)
		}
		l.setLength(length, obtained)
		if best == nil || expire.After(bestExp) {
			best, bestExp = l, expire
		}
	}
	return best
}

// leaseFromGetpacket reads macOS's "ipconfig getpacket <if>": "name
// (type): value" lines, and yiaddr/ciaddr.
func leaseFromGetpacket(s string, source string) *DPTLease {
	if !strings.Contains(s, "BOOTREPLY") && !strings.Contains(s, "server_identifier") {
		return nil
	}
	l := &DPTLease{Source: source}
	list := func(v string) []string { return safeFields(strings.Trim(v, "{} ")) }
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, " = "); ok {
			switch k {
			case "yiaddr":
				if v != "0.0.0.0" {
					l.Address = Safe(v)
				}
			case "ciaddr":
				if l.Address == "" && v != "0.0.0.0" {
					l.Address = Safe(v)
				}
			}
			continue
		}
		head, v, ok := strings.Cut(line, "): ")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(head, " (")
		switch {
		case name == "server_identifier":
			l.Server = Safe(v)
		case name == "lease_time":
			if n, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32); err == nil {
				l.setLength(time.Duration(n)*time.Second, time.Time{})
			}
		case name == "domain_name_server":
			l.DNS = list(v)
		case name == "domain_name":
			l.Domain = Safe(v)
		case strings.Contains(name, "ntp") || strings.Contains(name, "network_time") || name == "option_42":
			l.NTP = list(v)
		}
	}
	return l
}

// leaseFromPlist reads a configd lease plist: PacketData (the server's
// message), LeaseStartDate, LeaseLength.
func leaseFromPlist(b []byte, source string) *DPTLease {
	d := xml.NewDecoder(bytes.NewReader(b))
	vals := map[string]string{}
	key, inKey, inVal := "", false, ""
	for {
		t, err := d.Token()
		if err != nil {
			break
		}
		switch t := t.(type) {
		case xml.StartElement:
			if t.Name.Local == "key" {
				inKey = true
			} else if key != "" {
				inVal = t.Name.Local
			}
		case xml.CharData:
			if inKey {
				key = string(t)
			} else if inVal != "" && key != "" {
				vals[key] += string(t)
			}
		case xml.EndElement:
			if t.Name.Local == "key" {
				inKey = false
			} else if inVal != "" {
				inVal, key = "", ""
			}
		}
	}
	pkt, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(vals["PacketData"]), ""))
	if err != nil || len(pkt) == 0 {
		return nil
	}
	start, _ := time.Parse(time.RFC3339, strings.TrimSpace(vals["LeaseStartDate"]))
	l := leaseFromPacket(pkt, start, source)
	if l != nil && l.Length == "" {
		if n, err := strconv.Atoi(strings.TrimSpace(vals["LeaseLength"])); err == nil {
			l.setLength(time.Duration(n)*time.Second, start)
		}
	}
	return l
}

// readLease reads a lease file: the lease (or nil), or a note when the
// file is there but this user may not read it.
func readLease(path string, parse func(b []byte, mtime time.Time) *DPTLease) (*DPTLease, string, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, "", false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsPermission(err) {
			return nil, "the lease (" + path + ") " + leaseNeedsPriv + DHCPNeeds + " to read: sudo dpt info", true
		}
		return nil, "", false
	}
	if l := parse(b, st.ModTime()); l != nil {
		return l, "", true
	}
	return nil, "", false
}

// chronySources reads chrony's configuration: server, pool and peer lines,
// following sourcedir (*.sources), confdir (*.conf) and include.
func chronySources(path string, depth int, seen map[string]bool) []string {
	if depth > 4 || seen[path] {
		return nil
	}
	seen[path] = true
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 2 || strings.HasPrefix(fl[0], "#") || strings.HasPrefix(fl[0], "!") {
			continue
		}
		switch fl[0] {
		case "server", "pool", "peer":
			out = append(out, Safe(fl[1]))
		case "sourcedir", "confdir":
			ext := map[string]string{"sourcedir": "*.sources", "confdir": "*.conf"}[fl[0]]
			for _, d := range fl[1:] {
				ms, _ := filepath.Glob(filepath.Join(d, ext))
				sort.Strings(ms)
				for _, m := range ms {
					out = append(out, chronySources(m, depth+1, seen)...)
				}
			}
		case "include":
			ms, _ := filepath.Glob(fl[1])
			sort.Strings(ms)
			for _, m := range ms {
				out = append(out, chronySources(m, depth+1, seen)...)
			}
		}
	}
	return out
}

// ntpConfServers reads ntpd's (and macOS's) ntp.conf: server and pool.
func ntpConfServers(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		fl := strings.Fields(line)
		if len(fl) >= 2 && (fl[0] == "server" || fl[0] == "pool") {
			out = append(out, Safe(strings.TrimSuffix(fl[1], ".")))
		}
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// RenderDPTInfo writes the machine's picture.
func RenderDPTInfo(w io.Writer, r *DPTInfo, color bool) {
	o := newOut(w, color)
	when := func(t *time.Time) string { return t.Local().Format("2006-01-02 15:04") }
	none := func(v []string) string {
		if len(v) == 0 {
			return "none"
		}
		return strings.Join(v, ", ")
	}
	if len(r.Ifaces) == 0 {
		o.line("INFO", "no active Ethernet interface with an IPv4 address")
	}
	for _, x := range r.Ifaces {
		head := x.Name + "  " + x.MAC + "  " + strings.Join(x.Addrs, " ")
		if x.Gateway != "" {
			head += "  gateway " + x.Gateway
		}
		o.line("INFO", head)
		kv := func(k, v string) { o.line("", fmt.Sprintf("  %-18s %s", k, v)) }
		if l := x.Lease; l != nil {
			kv("DHCP server", none([]string{l.Server}))
			if l.Address != "" {
				kv("leased address", l.Address)
			}
			lease := l.Length
			if l.Obtained != nil {
				lease += "  obtained " + when(l.Obtained)
			}
			if l.Expires != nil {
				lease += "  expires " + when(l.Expires)
			}
			if lease != "" {
				kv("lease", strings.TrimSpace(lease))
			}
			kv("DNS (from DHCP)", none(l.DNS))
			if l.NTPNotKept {
				kv("NTP (from DHCP)", "not kept by this system")
			} else {
				kv("NTP (from DHCP)", none(l.NTP))
			}
			if l.Domain != "" {
				kv("domain", l.Domain)
			}
			kv("read from", l.Source)
		} else if x.LeaseNote != "" {
			kv("DHCP", x.LeaseNote)
		}
	}
	src := func(s string) string {
		if s == "" {
			return ""
		}
		return "  (" + s + ")"
	}
	o.line("SYSTEM", fmt.Sprintf("%-20s %s%s", "DNS", none(r.DNS), src(r.DNSSource)))
	o.line("", fmt.Sprintf("%-20s %s%s", "NTP", none(r.NTP), src(r.NTPSource)))
	if len(r.VPN) > 0 {
		o.line("", o.red("A VPN TUNNEL IS UP ("+strings.Join(r.VPN, ", ")+")"))
	}
	renderClock(o, r.Clock)
	if r.Time != nil {
		renderDPTTime(o, *r.Time)
	}
	renderOutside(o, r.Outside)
}
