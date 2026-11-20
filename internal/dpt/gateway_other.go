// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package dpt

import "net"

func gateways() map[int]net.IP { return nil }
