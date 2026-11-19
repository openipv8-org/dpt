// SPDX-License-Identifier: MIT

//go:build windows

package dpt

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// gatewayIfaces: the adapters (by IPv4 interface index) that have an IPv4
// gateway.
func gatewayIfaces() map[int]bool {
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
		out := map[int]bool{}
		for ; a != nil; a = a.Next {
			if a.OperStatus == windows.IfOperStatusUp && a.FirstGatewayAddress != nil {
				out[int(a.IfIndex)] = true
			}
		}
		return out
	}
	return nil
}
