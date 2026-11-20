// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package dpt

import "net"

func infoDNSSource() string                       { return "" }
func infoLease(net.Interface) (*DPTLease, string) { return nil, leaseNone }
func infoNTP() ([]string, string)                 { return nil, "" }
