// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package dpt

import (
	"context"
	"errors"
	"net"
	"time"
)

const DHCPProbeNote = ""

func dhcpProbe(ctx context.Context, ifi *net.Interface, xid uint32, discover []byte, listen time.Duration) ([]DHCPOfferSeen, error) {
	return nil, errors.New("the DHCP probe is not available on this system")
}
