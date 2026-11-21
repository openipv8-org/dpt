// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !windows

package dpt

func clockRead(c *DPTClock) { c.Note = "how this system keeps its time is not read here" }
