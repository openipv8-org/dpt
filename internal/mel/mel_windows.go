// SPDX-License-Identifier: MIT

//go:build windows

package mel

import "golang.org/x/sys/windows"

// dhcpPrivileged: the process runs elevated (Administrator).
func dhcpPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
