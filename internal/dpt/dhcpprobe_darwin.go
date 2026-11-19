// SPDX-License-Identifier: MIT

//go:build darwin

package dpt

import "golang.org/x/sys/unix"

func dhcpProbeSockopts(fd uintptr, ifindex int) error {
	for _, o := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT, unix.SO_BROADCAST} {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, o, 1); err != nil {
			return err
		}
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifindex)
}
