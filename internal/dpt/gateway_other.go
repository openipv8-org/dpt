// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package dpt

func gatewayIfaces() map[int]bool { return nil }
