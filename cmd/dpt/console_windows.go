// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVT turns on escape-sequence handling in the console (colour, and
// the shell's line editing); false when this console has none (before
// Windows 10) or the output is not a console.
func enableVT() bool {
	ok := false
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		h := windows.Handle(f.Fd())
		var mode uint32
		if windows.GetConsoleMode(h, &mode) != nil {
			continue
		}
		if windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT) == nil && f == os.Stdout {
			ok = true
		}
	}
	return ok
}
