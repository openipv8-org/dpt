// SPDX-License-Identifier: MIT

//go:build !windows

package sysdns

import "testing"

func TestParseResolvConf(t *testing.T) {
	got := parseResolvConf("# comment\nsearch example.test\nnameserver 192.0.2.53\nnameserver fe80::1%eth0\nnameserver bogus\nnameserver 2001:db8::53\n")
	want := []string{"192.0.2.53", "fe80::1", "2001:db8::53"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%v, want %v", got, want)
		}
	}
	if parseResolvConf("") != nil {
		t.Error("empty file")
	}
}
