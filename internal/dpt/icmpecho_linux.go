// SPDX-License-Identifier: MIT

//go:build linux

package dpt

import "golang.org/x/sys/unix"

func sockCloexec() int { return unix.SOCK_CLOEXEC }
