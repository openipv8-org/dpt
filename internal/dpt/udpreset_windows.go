// SPDX-License-Identifier: MIT

package dpt

import (
	"net"
	"syscall"
	"unsafe"
)

// udpReportUnreachable turns back on what Go turns off on every Windows UDP
// socket (SIO_UDP_CONNRESET): the ICMP port unreachable that came back for
// what was sent, reported on the next read as WSAECONNRESET.  Without it a
// closed port is only silence on Windows, never "closed".
func udpReportUnreachable(c net.Conn) {
	u, ok := c.(*net.UDPConn)
	if !ok {
		return
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		on, ret := uint32(1), uint32(0)
		syscall.WSAIoctl(syscall.Handle(fd), syscall.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&on)), uint32(unsafe.Sizeof(on)), nil, 0, &ret, nil, 0)
	})
}
