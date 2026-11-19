// SPDX-License-Identifier: MIT

//go:build darwin

package dpt

import (
	"syscall"

	"golang.org/x/net/route"
)

// gatewayIfaces: the interfaces (by index) with an IPv4 default route,
// scoped ones too (a VPN takes the main default; the LAN's stays scoped).
func gatewayIfaces() map[int]bool {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	out := map[int]bool{}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			continue
		}
		if mask, ok := rm.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
			continue
		}
		if _, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr); !ok {
			continue // a gateway that is not an IPv4 address: a tunnel's
		}
		out[rm.Index] = true
	}
	return out
}
