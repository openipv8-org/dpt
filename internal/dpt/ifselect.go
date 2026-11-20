// SPDX-License-Identifier: MIT

package dpt

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Choosing an interface by hand (--select, the shell's interface
// command): every Ethernet interface that is up, with an address or not
// (a fresh port to test has none yet).

// DPTIfaceEntry is one interface in the list.
type DPTIfaceEntry struct {
	Name    string
	MAC     string
	Addrs   []string // IPv4, with prefix
	Gateway string
}

// DPTIfaceList is the interfaces to choose from, and the one dpt would
// choose by itself ("" when none).
func DPTIfaceList() ([]DPTIfaceEntry, string) {
	ifs, _ := net.Interfaces()
	gw := gateways()
	var out []DPTIfaceEntry
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 {
			continue
		}
		e := DPTIfaceEntry{Name: i.Name, MAC: i.HardwareAddr.String()}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				e.Addrs = append(e.Addrs, n.String())
			}
		}
		if g := gw[i.Index]; g != nil {
			e.Gateway = g.String()
		}
		out = append(out, e)
	}
	def, _ := DPTDefaultIface()
	return out, def
}

// RenderIfaceList writes the numbered list; the default is marked.
func RenderIfaceList(w io.Writer, list []DPTIfaceEntry, def string) {
	width := 0
	for _, e := range list {
		width = max(width, len(e.Name))
	}
	for k, e := range list {
		addr := "no IPv4 address"
		if len(e.Addrs) > 0 {
			addr = strings.Join(e.Addrs, " ")
		}
		if e.Gateway != "" {
			addr += "  gateway " + e.Gateway
		}
		mark := " "
		if e.Name == def {
			mark = "*"
		}
		fmt.Fprintf(w, " %s%2d  %-*s  %s  %s\n", mark, k+1, width, e.Name, e.MAC, addr)
	}
}

// DPTIfacePrompt is the question after the list.
func DPTIfacePrompt(list []DPTIfaceEntry, def string) string {
	for k, e := range list {
		if e.Name == def {
			return fmt.Sprintf("interface [%d %s]: ", k+1, def)
		}
	}
	return "interface: "
}

// DPTIfacePick reads the answer: a number from the list, a name, or
// nothing for the default.
func DPTIfacePick(list []DPTIfaceEntry, def, answer string) (string, error) {
	a := strings.TrimSpace(answer)
	if a == "" {
		if def == "" {
			return "", errors.New("no default interface: give a number or a name")
		}
		return def, nil
	}
	if n, err := strconv.Atoi(a); err == nil {
		if n < 1 || n > len(list) {
			return "", fmt.Errorf("%d is not in the list (1-%d)", n, len(list))
		}
		return list[n-1].Name, nil
	}
	for _, e := range list {
		if strings.EqualFold(e.Name, a) {
			return e.Name, nil
		}
	}
	return "", fmt.Errorf("%q is not in the list", Printable(a))
}
