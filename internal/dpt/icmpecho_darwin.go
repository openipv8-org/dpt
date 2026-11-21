// SPDX-License-Identifier: MIT

//go:build darwin

package dpt

// sockCloexec: macOS's socket() takes no SOCK_CLOEXEC; the program
// starts no children while a socket is open.
func sockCloexec() int { return 0 }

// macOS gives a datagram socket the routers' errors as packets: no error
// queue to read.
func icmpRecvErr(fd int, v6 bool)                               {}
func icmpErrQueue(fd int, v6 bool, seq int) (string, int, bool) { return "", 0, false }
