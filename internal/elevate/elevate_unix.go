// SPDX-License-Identifier: MIT

//go:build linux || darwin

package elevate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Possible: not root already (root that still lacks it gains nothing).
func Possible() bool { return os.Geteuid() != 0 }

// Run replaces this process with sudo dpt <args>; it returns only when
// that could not start.
func Run(args []string, _ bool) (int, error) {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return 0, errors.New("sudo not found")
	}
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	fmt.Fprintln(os.Stderr, "dhcp needs sudo: running sudo dpt", joinArgs(args))
	argv := append([]string{"sudo", "--", self}, args...)
	return 0, syscall.Exec(sudo, argv, os.Environ())
}

func joinArgs(a []string) string {
	s := ""
	for i, x := range a {
		if i > 0 {
			s += " "
		}
		s += x
	}
	return s
}

// Relay is for the Windows copy; elsewhere there is none.
func Relay(string) (bool, error) { return false, nil }
