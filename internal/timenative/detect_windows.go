// SPDX-License-Identifier: MIT

//go:build windows

package timenative

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Detect reads the system: whether the PC is joined to a domain.
func Detect() Env {
	e := Env{OS: "windows"}
	var name *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &name, &status); err == nil {
		if status == windows.NetSetupDomainName {
			e.Domain = windows.UTF16PtrToString(name)
			if e.Domain == "" {
				e.Domain = "(unnamed)"
			}
		}
		windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	}
	return e
}

// exactLine runs the command line exactly as shown: w32tm reads its own
// quotes (/manualpeerlist:"a b").
func exactLine(c *exec.Cmd, s Step) {
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: s.Line}
}
