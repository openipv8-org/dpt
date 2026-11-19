// SPDX-License-Identifier: MIT

//go:build darwin || windows

package dpt

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// macOS and Windows: a UDP socket on port 68 (SO_REUSEADDR, sharing it
// with the system's DHCP client), sending out of the interface asked.
// Offers come back broadcast (the flag is set), so the socket hears them
// unless the system's client takes them first: Windows gives a shared
// port's datagrams to one socket only.  The source MAC is not seen.

// DHCPProbeNote is what to tell the operator when no offer came on this
// platform: it may be the platform, not the segment.
const DHCPProbeNote = "no offers heard: the system's own DHCP client may have taken them, or a VPN blocked them"

func dhcpProbe(ctx context.Context, ifi *net.Interface, xid uint32, discover []byte, listen time.Duration) ([]DHCPOfferSeen, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) { serr = dhcpProbeSockopts(fd, ifi.Index) })
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:68")
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) {
			return nil, errDHCPProbePriv
		}
		return nil, err
	}
	defer pc.Close()
	start := time.Now()
	if _, err := pc.WriteTo(discover, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return nil, err
	}
	pc.SetReadDeadline(start.Add(listen))
	stop := context.AfterFunc(ctx, func() { pc.SetReadDeadline(time.Now()) })
	defer stop()
	var out []DHCPOfferSeen
	buf := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return out, nil
		}
		o := dhcpOfferFor(buf[:n], xid)
		if o == nil {
			continue
		}
		if ua, ok := from.(*net.UDPAddr); ok {
			o.SrcIP = ua.IP
		}
		o.After = time.Since(start)
		out = append(out, *o)
	}
}
