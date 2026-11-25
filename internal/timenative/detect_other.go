// SPDX-License-Identifier: MIT

//go:build !windows && !darwin && !linux

package timenative

import "os/exec"

// Detect reads the system: time native is not for it.
func Detect() Env { return Env{} }

func exactLine(*exec.Cmd, Step) {}
