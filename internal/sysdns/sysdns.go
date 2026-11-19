// SPDX-License-Identifier: MIT

// Package sysdns finds the system's DNS servers: the default server of
// dpt's shell, as nslookup starts with.
package sysdns

// Servers gives the system's DNS servers, first one first.
func Servers() []string { return servers() }
