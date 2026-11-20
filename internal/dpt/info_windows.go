// SPDX-License-Identifier: MIT

//go:build windows

package dpt

import (
	"net"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func infoDNSSource() string { return "adapter settings" }

// infoLease: the adapter's DHCP server and lease times (GetAdaptersInfo).
func infoLease(i net.Interface) (*DPTLease, string) {
	size := uint32(16 << 10)
	for range 3 {
		buf := make([]byte, size)
		a := (*windows.IpAdapterInfo)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersInfo(a, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, leaseNone
		}
		for ; a != nil; a = a.Next {
			if int(a.Index) != i.Index {
				continue
			}
			if a.DhcpEnabled == 0 {
				return nil, "DHCP is off on this adapter (a static address)"
			}
			l := &DPTLease{Source: "adapter settings", Server: cstr(a.DhcpServer.IpAddress.String[:]), Address: cstr(a.IpAddressList.IpAddress.String[:]), NTPNotKept: true}
			// what DHCP gave is kept under the adapter's GUID
			if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+cstr(a.AdapterName[:]), registry.QUERY_VALUE); err == nil {
				if v, _, err := k.GetStringValue("DhcpNameServer"); err == nil {
					l.DNS = dhcpNameServers(v)
				}
				if v, _, err := k.GetStringValue("DhcpDomain"); err == nil {
					l.Domain = Safe(v)
				}
				k.Close()
			}
			if a.LeaseObtained > 0 {
				ob := time.Unix(a.LeaseObtained, 0)
				l.Obtained = &ob
				if a.LeaseExpires > a.LeaseObtained {
					ex := time.Unix(a.LeaseExpires, 0)
					l.Expires = &ex
					l.Length = ex.Sub(ob).String()
				}
			}
			return l, ""
		}
		return nil, leaseNone
	}
	return nil, leaseNone
}

func cstr(b []byte) string {
	if k := strings.IndexByte(string(b), 0); k >= 0 {
		b = b[:k]
	}
	return Safe(string(b))
}

// infoNTP: the Windows Time service's servers.
func infoNTP() ([]string, string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\W32Time\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return nil, "Windows Time: not readable"
	}
	defer k.Close()
	typ, _, _ := k.GetStringValue("Type")
	if typ == "NT5DS" {
		return nil, "Windows Time: from the domain controller"
	}
	v, _, err := k.GetStringValue("NtpServer")
	if err != nil {
		return nil, "Windows Time: no server set"
	}
	var out []string
	for _, f := range strings.Fields(v) {
		h, _, _ := strings.Cut(f, ",") // time.windows.com,0x9
		out = append(out, Safe(h))
	}
	return uniq(out), "Windows Time"
}
