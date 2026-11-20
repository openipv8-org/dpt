// SPDX-License-Identifier: MIT

//go:build linux

package dpt

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
)

// gateways: the IPv4 default gateway of each interface (by index) that
// has one, from /proc/net/route.
func gateways() map[int]net.IP {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[int]net.IP{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(fl) < 8 || fl[1] != "00000000" || fl[7] != "00000000" || fl[2] == "00000000" {
			continue
		}
		g, err := strconv.ParseUint(fl[2], 16, 32)
		if err != nil {
			continue
		}
		if i, err := net.InterfaceByName(fl[0]); err == nil {
			// little-endian hex
			out[i.Index] = net.IPv4(byte(g), byte(g>>8), byte(g>>16), byte(g>>24)).To4()
		}
	}
	return out
}
