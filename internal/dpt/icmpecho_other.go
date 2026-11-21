// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package dpt

import (
	"errors"
	"time"
)

type icmpSys struct{}

func (c *ICMPConn) open() error {
	return errors.New("cannot open ICMP socket: not supported on this system")
}
func (c *ICMPConn) close() error { return nil }
func (c *ICMPConn) echo(seq, ttl int, timeout time.Duration) (EchoReply, error) {
	return EchoReply{Seq: seq}, errors.New("not supported")
}
