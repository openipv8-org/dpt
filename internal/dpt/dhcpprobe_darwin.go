// SPDX-License-Identifier: MIT

//go:build darwin

package dpt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS: the DISCOVER goes out and the offers come in on /dev/bpf (root),
// whole Ethernet frames, as on Linux's packet socket: port 68 belongs to
// the system's DHCP client, and a VPN's rules sit above BPF, so neither
// takes an offer first.  The socket sees each offer's source MAC.

func bpfOpen() (int, error) {
	for i := 0; i < 256; i++ {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			return fd, nil
		case err == unix.EBUSY:
			continue
		case err == unix.EACCES || err == unix.EPERM:
			return -1, errDHCPProbePriv
		default:
			return -1, fmt.Errorf("/dev/bpf%d: %w", i, err)
		}
	}
	return -1, errors.New("every /dev/bpf device is busy")
}

func bpfIoctl(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func dhcpProbe(ctx context.Context, ifi *net.Interface, xid uint32, discover []byte, listen time.Duration) ([]DHCPOfferSeen, error) {
	fd, err := bpfOpen()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	// the buffer size is set before the interface
	unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, 32768)
	var ifr [32]byte // struct ifreq: the name, then a union
	copy(ifr[:unix.IFNAMSIZ-1], ifi.Name)
	if err := bpfIoctl(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr[0])); err != nil {
		return nil, fmt.Errorf("bpf on %s: %w", ifi.Name, err)
	}
	for _, o := range []uint{unix.BIOCIMMEDIATE, unix.BIOCSHDRCMPLT} {
		if err := unix.IoctlSetPointerInt(fd, o, 1); err != nil {
			return nil, err
		}
	}
	unix.IoctlSetPointerInt(fd, unix.BIOCSSEESENT, 0) // not our own DISCOVER
	src := net.HardwareAddr(discover[28:34])
	if src.String() != ifi.HardwareAddr.String() {
		// a random client MAC: an offer sent to it is not for this card,
		// which drops it unless promiscuous
		if err := bpfIoctl(fd, unix.BIOCPROMISC, nil); err != nil {
			return nil, fmt.Errorf("promiscuous on %s: %w", ifi.Name, err)
		}
	}
	insns := make([]unix.BpfInsn, len(dhcpEtherFilter))
	for i, f := range dhcpEtherFilter {
		insns[i] = unix.BpfInsn{Code: uint16(f[0]), Jt: uint8(f[1]), Jf: uint8(f[2]), K: f[3]}
	}
	prog := unix.BpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}
	if err := bpfIoctl(fd, unix.BIOCSETF, unsafe.Pointer(&prog)); err != nil {
		return nil, err
	}
	tv := unix.Timeval{Usec: 200000} // a read returns every 200 ms: look at ctx
	if err := bpfIoctl(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return nil, err
	}
	blen, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil || blen <= 0 {
		return nil, errors.New("bpf buffer size")
	}
	// the frame's source is the probe's client MAC (chaddr)
	start := time.Now()
	if _, err := unix.Write(fd, dhcpEtherFrame(src, dhcpIPv4UDP(discover))); err != nil {
		return nil, fmt.Errorf("send on %s: %w", ifi.Name, err)
	}
	deadline := start.Add(listen)
	var out []DHCPOfferSeen
	buf := make([]byte, blen) // a read must ask for exactly the buffer size
	for ctx.Err() == nil && time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			return out, nil
		}
		for _, f := range bpfRecords(buf[:n]) {
			mac, ip, ok := dhcpEtherOffer(f)
			if !ok {
				continue
			}
			srcIP, body, ok := dhcpUDP(ip)
			if !ok {
				continue
			}
			o := dhcpOfferFor(body, xid)
			if o == nil {
				continue
			}
			o.SrcIP, o.SrcMAC, o.After = srcIP.IP, mac, time.Since(start)
			out = append(out, *o)
		}
	}
	return out, nil
}
