// SPDX-License-Identifier: MIT

// Package elevate runs dpt again with the privilege a mode needs, when a
// person typed the command: sudo on Linux and macOS (the password is asked
// in the same window), UAC on Windows (the elevated copy runs with no
// window and its output comes back here).  From a script (input or output
// not a terminal) nothing is asked: the caller says what is needed.
package elevate

import (
	"os"

	"golang.org/x/term"
)

// Interactive: both input and output are a terminal or a console.
func Interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// RelayFlag is the hidden first argument of the elevated copy on Windows:
// --dpt-relay=<pipe>,<color>.
const RelayFlag = "--dpt-relay="
