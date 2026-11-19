// SPDX-License-Identifier: MIT

package dpt

import (
	"encoding/binary"
	"net"
)

// Ethernet framing and BPF records for the macOS probe (/dev/bpf hands
// whole frames); kept free of build tags so Linux tests them too.

// dhcpEtherFrame is ipPkt in an Ethernet broadcast frame from src.
func dhcpEtherFrame(src net.HardwareAddr, ipPkt []byte) []byte {
	f := make([]byte, 14+len(ipPkt))
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	copy(f[14:], ipPkt)
	return f
}

// dhcpEtherOffer reads a frame: the source MAC and the IPv4 packet in it.
func dhcpEtherOffer(f []byte) (net.HardwareAddr, []byte, bool) {
	if len(f) < 14+20 || binary.BigEndian.Uint16(f[12:14]) != 0x0800 {
		return nil, nil, false
	}
	return append(net.HardwareAddr(nil), f[6:12]...), f[14:], true
}

// dhcpEtherFilter is the BPF program for whole frames: IPv4, UDP, not a
// fragment, destination port 68.  {code, jt, jf, k}.
var dhcpEtherFilter = [][4]uint32{
	{0x28, 0, 0, 12},     // ldh [12]: EtherType
	{0x15, 0, 8, 0x0800}, // jeq IPv4
	{0x30, 0, 0, 23},     // ldb [23]: protocol
	{0x15, 0, 6, 17},     // jeq udp
	{0x28, 0, 0, 20},     // ldh [20]: flags and fragment offset
	{0x45, 4, 0, 0x1fff}, // jset fragment offset: drop
	{0xb1, 0, 0, 14},     // ldxb 4*([14]&0xf): IP header length
	{0x48, 0, 0, 16},     // ldh [x+16]: destination port
	{0x15, 0, 1, 68},     // jeq 68
	{0x06, 0, 0, 0xffff}, // accept
	{0x06, 0, 0, 0},      // drop
}

// bpfRecords splits a read from macOS's /dev/bpf into its packets.  Each
// has a header (struct bpf_hdr: timeval32, caplen u32 at 8, datalen u32
// at 12, hdrlen u16 at 16) and the next starts word aligned (4).
func bpfRecords(buf []byte) [][]byte {
	var out [][]byte
	for off := 0; off+18 <= len(buf); {
		caplen := int(nativeU32(buf[off+8:]))
		hdrlen := int(uint16(buf[off+16]) | uint16(buf[off+17])<<8)
		if hdrlen < 18 || off+hdrlen+caplen > len(buf) {
			break
		}
		out = append(out, buf[off+hdrlen:off+hdrlen+caplen])
		off += (hdrlen + caplen + 3) &^ 3
	}
	return out
}

// nativeU32: little-endian, as on every system dpt is built for.
func nativeU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
