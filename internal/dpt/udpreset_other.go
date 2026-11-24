// SPDX-License-Identifier: MIT

//go:build !windows

package dpt

import "net"

// udpReportUnreachable: Linux and macOS report port unreachable on a
// connected UDP socket already (ECONNREFUSED).
func udpReportUnreachable(net.Conn) {}
