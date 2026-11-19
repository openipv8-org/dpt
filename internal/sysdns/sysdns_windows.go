// SPDX-License-Identifier: MIT

//go:build windows

package sysdns

import (
	"net"

	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// servers reads every up adapter's DNS servers (GetAdaptersAddresses).
func servers() []string {
	size := uint32(15000)
	for tries := 0; tries < 3; tries++ {
		buf := make([]byte, size)
		a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, a, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var out []string
		seen := map[string]bool{}
		for ; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				ip := sockaddrIP(d.Address.Sockaddr)
				if ip == nil || ip.IsLinkLocalUnicast() && ip.To4() == nil {
					continue
				}
				if s := ip.String(); !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

func sockaddrIP(sa *syscall.RawSockaddrAny) net.IP {
	if sa == nil {
		return nil
	}
	switch sa.Addr.Family {
	case windows.AF_INET:
		p := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
		return net.IP(append([]byte(nil), p.Addr[:]...))
	case windows.AF_INET6:
		p := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sa))
		return net.IP(append([]byte(nil), p.Addr[:]...))
	}
	return nil
}
