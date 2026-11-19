// SPDX-License-Identifier: MIT

//go:build linux

package dpt

// DHCPProbeNote is empty on Linux: the packet socket hears every offer.
const DHCPProbeNote = ""
