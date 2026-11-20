// SPDX-License-Identifier: MIT

//go:build darwin

package dpt

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// gateways: the IPv4 default gateway of each interface (by index) that
// has one, scoped routes too (a VPN takes the main default; the LAN's
// stays scoped).
func gateways() map[int]net.IP {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	out := map[int]net.IP{}
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
		gw, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok {
			continue // a gateway that is not an IPv4 address: a tunnel's
		}
		if _, seen := out[rm.Index]; !seen {
			out[rm.Index] = net.IP(gw.IP[:]).To4()
		}
	}
	return out
}
