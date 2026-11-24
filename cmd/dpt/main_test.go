// SPDX-License-Identifier: MIT
package main

import (
	"os"
	"runtime"
	"testing"

	"openipv8.org/dpt/internal/elevate"
)

// the exit codes: 0 OK, 1 a test failed, 2 MEL, 3 bad usage
func TestExitCodes(t *testing.T) {
	devnull, _ := os.Open(os.DevNull)
	so, se := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devnull, devnull
	defer func() { os.Stdout, os.Stderr = so, se }()
	type tc struct {
		args []string
		want int
	}
	cases := []tc{
		{[]string{"--help"}, exitOK},
		{[]string{"-h"}, exitOK},
		{[]string{"--version"}, exitOK},
		{[]string{"--bogus"}, exitUsage},
		{[]string{"a.test", "b.test"}, exitUsage},
	}
	if runtime.GOOS == "windows" {
		// Windows' own way, and --help and -h as people type them anyway
		cases = append(cases, []tc{
			{[]string{"/?"}, exitOK},
			{[]string{"/version"}, exitOK},
			{[]string{"/bogus"}, exitUsage},
			{[]string{"-c", "3", "a.test"}, exitUsage},
			{[]string{"/tdx", "a.test"}, exitUsage},
			{[]string{"dhcp", "/p"}, exitUsage},
			{[]string{"/c:0", "a.test"}, exitUsage},
			{[]string{"no-such-name.invalid", "/t"}, exitMEL},
		}...)
	} else {
		cases = append(cases, []tc{
			{[]string{"-tdx", "a.test"}, exitUsage},
			{[]string{"dhcp", "-p"}, exitUsage},
			{[]string{"-c", "0", "a.test"}, exitUsage},
			{[]string{"no-such-name.invalid", "-t"}, exitMEL},
		}...)
	}
	for _, c := range cases {
		if got := run(c.args); got != c.want {
			t.Errorf("%v: exit %d, want %d", c.args, got, c.want)
		}
	}
	// dhcp needs root (Administrator); the Windows runner already is one
	notRoot := os.Geteuid() != 0
	if runtime.GOOS == "windows" {
		notRoot = elevate.Possible()
	}
	if notRoot {
		if got := run([]string{"dhcp"}); got != exitMEL {
			t.Errorf("dhcp without root: exit %d, want %d", got, exitMEL)
		}
	}
}
