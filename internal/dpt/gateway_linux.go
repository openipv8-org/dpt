// SPDX-License-Identifier: MIT

//go:build linux

package dpt

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// gatewayIfaces: the interfaces (by index) with an IPv4 default route,
// from /proc/net/route.
func gatewayIfaces() map[int]bool {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[int]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(fl) < 8 || fl[1] != "00000000" || fl[7] != "00000000" || fl[2] == "00000000" {
			continue
		}
		if i, err := net.InterfaceByName(fl[0]); err == nil {
			out[i.Index] = true
		}
	}
	return out
}
