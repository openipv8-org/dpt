// SPDX-License-Identifier: MIT

//go:build !windows

package selfinstall

import "os"

// Dest is where dpt is installed.
func Dest() string { return "/usr/local/bin/dpt" }

func versionFlag() string { return "--version" }

// replace puts the new file in dest's place in one rename; a running dpt
// keeps the old file until it exits.
func replace(tmp, dest string) error { return os.Rename(tmp, dest) }

// AddToPath: /usr/local/bin is on the PATH already.
func AddToPath(string) (bool, error) { return false, nil }
