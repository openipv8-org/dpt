// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package elevate

import "errors"

func Possible() bool                  { return false }
func Run([]string, bool) (int, error) { return 0, errors.New("not on this system") }
func Relay(string) (bool, error)      { return false, nil }
