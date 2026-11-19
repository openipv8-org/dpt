// SPDX-License-Identifier: MIT

//go:build darwin

package dpt

// sockCloexec: macOS's socket() takes no SOCK_CLOEXEC; the program
// starts no children while a socket is open.
func sockCloexec() int { return 0 }
