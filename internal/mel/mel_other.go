// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package mel

func dhcpPrivileged() bool { return false }
