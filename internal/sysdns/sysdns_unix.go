// SPDX-License-Identifier: MIT

//go:build !windows

package sysdns

import (
	"net"
	"os"
	"strings"
)

func servers() []string { return parseResolvConf(readFile("/etc/resolv.conf")) }

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func parseResolvConf(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" {
			h := f[1]
			if i := strings.IndexByte(h, '%'); i >= 0 {
				h = h[:i] // a zone on a link-local address
			}
			if net.ParseIP(h) != nil {
				out = append(out, h)
			}
		}
	}
	return out
}
