// SPDX-License-Identifier: MIT

//go:build windows

package dpt

import "golang.org/x/sys/windows"

// ipUnicastIF is IP_UNICAST_IF: the interface outgoing packets leave by
// (the index in network byte order).
const ipUnicastIF = 31

func dhcpProbeSockopts(fd uintptr, ifindex int) error {
	h := windows.Handle(fd)
	for _, o := range []int{windows.SO_REUSEADDR, windows.SO_BROADCAST} {
		if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, o, 1); err != nil {
			return err
		}
	}
	v := int(uint32(ifindex)>>24 | uint32(ifindex)>>8&0xff00 | uint32(ifindex)<<8&0xff0000 | uint32(ifindex)<<24)
	return windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIF, v)
}
