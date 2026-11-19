// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"net"
	"testing"
)

// bpfRecords reads macOS's /dev/bpf layout: header, packet, padding to 4.
func TestBPFRecords(t *testing.T) {
	rec := func(pkt []byte) []byte {
		h := make([]byte, 20) // sizeof(struct bpf_hdr) on macOS
		h[8], h[12], h[16] = byte(len(pkt)), byte(len(pkt)), 18
		b := append(h[:18], pkt...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	a, b := []byte{1, 2, 3, 4, 5}, []byte{6, 7, 8}
	got := bpfRecords(append(rec(a), rec(b)...))
	if len(got) != 2 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
		t.Fatalf("%v", got)
	}
	if len(bpfRecords([]byte{1, 2, 3})) != 0 {
		t.Error("short buffer")
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	f := dhcpEtherFrame(mac, make([]byte, 28))
	m, ip, ok := dhcpEtherOffer(f)
	if !ok || m.String() != mac.String() || len(ip) != 28 {
		t.Errorf("frame %v %d %v", m, len(ip), ok)
	}
}
