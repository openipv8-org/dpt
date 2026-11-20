// SPDX-License-Identifier: MIT

//go:build windows

package dpt

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// gateways: the IPv4 gateway of each adapter (by IPv4 interface index)
// that has one.
func gateways() map[int]net.IP {
	size := uint32(15000)
	for range 3 {
		buf := make([]byte, size)
		a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, a, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		out := map[int]net.IP{}
		for ; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for g := a.FirstGatewayAddress; g != nil; g = g.Next {
				if ip := g.Address.IP(); ip != nil && ip.To4() != nil {
					out[int(a.IfIndex)] = ip.To4()
					break
				}
			}
		}
		return out
	}
	return nil
}
