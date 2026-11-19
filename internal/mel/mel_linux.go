// SPDX-License-Identifier: MIT

//go:build linux

package mel

import "golang.org/x/sys/unix"

// dhcpPrivileged: a packet socket opens (root or CAP_NET_RAW).
func dhcpPrivileged() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
