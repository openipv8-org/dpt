// SPDX-License-Identifier: MIT

//go:build darwin

package timenative

import "os/exec"

// Detect reads the system.
func Detect() Env { return Env{OS: "darwin"} }

func exactLine(*exec.Cmd, Step) {}
