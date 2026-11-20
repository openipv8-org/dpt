// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLeaseFromPacket(t *testing.T) {
	m := &DHCPMessage{Op: 2, XID: 1, YIAddr: []byte{10, 0, 2, 15}}
	m.Set(53, []byte{5})
	m.Set(54, []byte{10, 0, 2, 2})
	m.Set(51, []byte{0, 1, 0x51, 0x80}) // 86400
	m.Set(6, []byte{8, 8, 8, 8, 1, 1, 1, 1})
	m.Set(42, []byte{10, 0, 2, 3})
	m.Set(15, []byte("lan\x00"))
	ob := time.Date(2026, 11, 19, 4, 8, 0, 0, time.UTC)
	l := leaseFromPacket(m.Marshal(), ob, "f")
	if l == nil || l.Server != "10.0.2.2" || l.Address != "10.0.2.15" || l.Length != "24h0m0s" ||
		!l.Expires.Equal(ob.Add(24*time.Hour)) || strings.Join(l.DNS, ",") != "8.8.8.8,1.1.1.1" ||
		strings.Join(l.NTP, ",") != "10.0.2.3" || l.Domain != "lan" {
		t.Fatalf("%+v", l)
	}
}

func TestLeaseFromKV(t *testing.T) {
	s := "# This is private data. Do not parse.\nADDRESS=192.168.1.20\nNETMASK=255.255.255.0\nSERVER_ADDRESS=192.168.1.1\nLIFETIME=3600\nDNS=192.168.1.1 9.9.9.9\nNTP=192.168.1.1\nDOMAINNAME=home\n"
	l := leaseFromKV(s, time.Unix(1000, 0), "f")
	if l == nil || l.Server != "192.168.1.1" || l.Length != "1h0m0s" || len(l.DNS) != 2 || l.NTP[0] != "192.168.1.1" || l.Domain != "home" {
		t.Fatalf("%+v", l)
	}
	if leaseFromKV("X=1\n", time.Time{}, "f") != nil {
		t.Error("not a lease")
	}
}

func TestLeaseFromDhclient(t *testing.T) {
	s := `lease {
  interface "eth0";
  fixed-address 10.9.0.5;
  option dhcp-server-identifier 10.9.0.1;
  option dhcp-lease-time 600;
  option domain-name-servers 10.9.0.1,8.8.4.4;
  option ntp-servers 10.9.0.1;
  option domain-name "corp.example";
  expire 4 2026/11/19 10:00:00;
}
lease {
  interface "eth0";
  fixed-address 10.9.0.6;
  option dhcp-server-identifier 10.9.0.1;
  option dhcp-lease-time 600;
  expire 4 2026/11/19 11:00:00;
}
lease {
  interface "wlan0";
  fixed-address 172.16.0.9;
  expire 4 2026/11/19 12:00:00;
}`
	l := leaseFromDhclient(s, "eth0", "f")
	if l == nil || l.Address != "10.9.0.6" || l.Length != "10m0s" || l.Expires.Format("15:04") != "11:00" || l.Obtained.Format("15:04") != "10:50" {
		t.Fatalf("%+v", l)
	}
	if leaseFromDhclient(s, "eth1", "f") != nil {
		t.Error("eth1 has none")
	}
}

func TestLeaseFromGetpacket(t *testing.T) {
	s := `op = BOOTREPLY
htype = 1
ciaddr = 0.0.0.0
yiaddr = 192.168.178.224
siaddr = 192.168.178.254
chaddr = 98:9e:63:32:a4:94
Options count is 9
dhcp_message_type (uint8): ACK 0x5
server_identifier (ip): 192.168.178.254
lease_time (uint32): 0xe10
subnet_mask (ip): 255.255.255.0
router (ip_mult): {192.168.178.254}
domain_name_server (ip_mult): {8.8.8.8, 1.1.1.1}
domain_name (string): fritz.box
end (none):
`
	l := leaseFromGetpacket(s, "ipconfig")
	if l == nil || l.Server != "192.168.178.254" || l.Address != "192.168.178.224" || l.Length != "1h0m0s" ||
		strings.Join(l.DNS, ",") != "8.8.8.8,1.1.1.1" || l.Domain != "fritz.box" {
		t.Fatalf("%+v", l)
	}
	if leaseFromGetpacket("", "x") != nil {
		t.Error("empty")
	}
}

func TestNTPConfigs(t *testing.T) {
	if got := ntpConfServers("server time.apple.com.\n# server x\npool pool.ntp.org iburst\n"); strings.Join(got, ",") != "time.apple.com,pool.ntp.org" {
		t.Errorf("%v", got)
	}
	d := t.TempDir()
	write := func(n, s string) string {
		p := d + "/" + n
		if err := writeFileT(p, s); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("a.sources", "server 10.0.0.1 iburst\n")
	write("b.conf", "pool 2.debian.pool.ntp.org iburst\n")
	main := write("chrony.conf", "! pool x\nsourcedir "+d+"\nconfdir "+d+"\nserver time.google.com iburst\nkeyfile k\n")
	got := chronySources(main, 0, map[string]bool{})
	if strings.Join(got, ",") != "10.0.0.1,2.debian.pool.ntp.org,time.google.com" {
		t.Errorf("%v", got)
	}
}

func TestRenderDPTInfo(t *testing.T) {
	ob := time.Now()
	r := &DPTInfo{Ifaces: []DPTInfoIface{
		{Name: "en1", MAC: "98:9e:63:32:a4:94", Addrs: []string{"192.168.178.224/24"}, Gateway: "192.168.178.254",
			Lease: &DPTLease{Server: "192.168.178.254", Length: "1h0m0s", Obtained: &ob, DNS: []string{"8.8.8.8"}, Source: "ipconfig getpacket en1"}},
		{Name: "en0", MAC: "x", Addrs: []string{"10.0.0.2/24"}, LeaseNote: leaseNone},
	}, DNS: []string{"8.8.8.8"}, DNSSource: "/etc/resolv.conf", NTP: []string{"time.apple.com"}, NTPSource: "Date & Time", VPN: []string{"utun3"}}
	var b bytes.Buffer
	RenderDPTInfo(&b, r, false)
	for _, w := range []string{"gateway 192.168.178.254", "DHCP server        192.168.178.254", "NTP (from DHCP)    none", "time.apple.com  (Date & Time)", "A VPN TUNNEL IS UP (utun3)", leaseNone} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("lacks %q:\n%s", w, b.String())
		}
	}
	var j bytes.Buffer
	DPTJSON(&j, r)
	var back map[string]any
	if err := json.Unmarshal(j.Bytes(), &back); err != nil || back["vpn_tunnel"] == nil {
		t.Errorf("json: %v\n%s", err, j.String())
	}
}

func writeFileT(p, s string) error { return os.WriteFile(p, []byte(s), 0o644) }

func TestLeaseFromPlist(t *testing.T) {
	m := &DHCPMessage{Op: 2, XID: 1, YIAddr: []byte{192, 168, 178, 224}}
	m.Set(53, []byte{5})
	m.Set(54, []byte{192, 168, 178, 254})
	m.Set(51, []byte{0, 0, 0x0e, 0x10})
	pkt := base64.StdEncoding.EncodeToString(m.Marshal())
	s := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>IPAddress</key>
	<string>192.168.178.224</string>
	<key>LeaseLength</key>
	<integer>3600</integer>
	<key>LeaseStartDate</key>
	<date>2026-11-19T16:44:00Z</date>
	<key>PacketData</key>
	<data>
	` + pkt[:20] + `
	` + pkt[20:] + `
	</data>
	<key>RouterIPAddress</key>
	<string>192.168.178.254</string>
</dict>
</plist>`
	l := leaseFromPlist([]byte(s), "plist")
	if l == nil || l.Server != "192.168.178.254" || l.Length != "1h0m0s" || l.Expires == nil || l.Expires.UTC().Format("15:04") != "17:44" {
		t.Fatalf("%+v", l)
	}
}

func TestDPTIfacePick(t *testing.T) {
	list := []DPTIfaceEntry{{Name: "en1"}, {Name: "en0"}}
	for _, c := range []struct{ in, want string }{{"", "en1"}, {"2", "en0"}, {"EN0", "en0"}, {" 1\n", "en1"}} {
		if got, err := DPTIfacePick(list, "en1", c.in); err != nil || got != c.want {
			t.Errorf("%q: %q %v", c.in, got, err)
		}
	}
	for _, bad := range []string{"0", "3", "eth9"} {
		if _, err := DPTIfacePick(list, "en1", bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
	if _, err := DPTIfacePick(list, "", ""); err == nil {
		t.Error("no default taken")
	}
	var b bytes.Buffer
	RenderIfaceList(&b, []DPTIfaceEntry{{Name: "en1", MAC: "m", Addrs: []string{"10.0.0.2/24"}, Gateway: "10.0.0.1"}, {Name: "en0", MAC: "n"}}, "en1")
	if !strings.Contains(b.String(), "* 1  en1  m  10.0.0.2/24  gateway 10.0.0.1") || !strings.Contains(b.String(), "no IPv4 address") {
		t.Errorf("%s", b.String())
	}
	for _, c := range []struct {
		st   DPTArgStyle
		args string
		ok   bool
	}{
		{DPTStyleUnix, "dhcp --select", true},
		{DPTStyleUnix, "info --select", true},
		{DPTStyleWindows, "dhcp /select", true},
		{DPTStyleUnix, "1.1.1.1 --select", false},
		{DPTStyleUnix, "dhcp --select --iface en0", false},
	} {
		cmd, err := ParseDPTArgs(strings.Fields(c.args), c.st)
		if (err == nil) != c.ok || err == nil && !cmd.Select {
			t.Errorf("%q: %v", c.args, err)
		}
	}
}

func TestDHCPNameServers(t *testing.T) {
	if got := dhcpNameServers(" 8.8.8.8 192.168.178.254 "); strings.Join(got, ",") != "8.8.8.8,192.168.178.254" {
		t.Errorf("%v", got)
	}
	if got := dhcpNameServers(""); len(got) != 0 {
		t.Errorf("%v", got)
	}
	var b bytes.Buffer
	RenderDPTInfo(&b, &DPTInfo{Ifaces: []DPTInfoIface{{Name: "Wi-Fi", Lease: &DPTLease{Server: "x", DNS: []string{"8.8.8.8"}, NTPNotKept: true, Source: "adapter settings"}}}}, false)
	if !strings.Contains(b.String(), "DNS (from DHCP)    8.8.8.8") || !strings.Contains(b.String(), "NTP (from DHCP)    not kept by this system") {
		t.Errorf("%s", b.String())
	}
}
