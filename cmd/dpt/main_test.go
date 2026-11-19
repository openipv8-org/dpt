// SPDX-License-Identifier: MIT
package main

import (
	"os"
	"testing"
)

// the exit codes: 0 OK, 1 a test failed, 2 MEL, 3 bad usage
func TestExitCodes(t *testing.T) {
	devnull, _ := os.Open(os.DevNull)
	so, se := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devnull, devnull
	defer func() { os.Stdout, os.Stderr = so, se }()
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"--help"}, exitOK},
		{[]string{"-h"}, exitOK},
		{[]string{"--version"}, exitOK},
		{[]string{"--bogus"}, exitUsage},
		{[]string{"a.test", "b.test"}, exitUsage},
		{[]string{"-tdx", "a.test"}, exitUsage},
		{[]string{"dhcp", "-p"}, exitUsage},
		{[]string{"-c", "0", "a.test"}, exitUsage},
		{[]string{"no-such-name.invalid", "-t"}, exitMEL},
	} {
		if got := run(c.args); got != c.want {
			t.Errorf("%v: exit %d, want %d", c.args, got, c.want)
		}
	}
	if os.Geteuid() != 0 {
		if got := run([]string{"dhcp"}); got != exitMEL {
			t.Errorf("dhcp without root: exit %d, want %d", got, exitMEL)
		}
	}
}
