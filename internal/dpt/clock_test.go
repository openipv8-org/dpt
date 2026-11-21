// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestClockReaders(t *testing.T) {
	c := &DPTClock{}
	clockFromTimedatectl(c, "Timezone=America/New_York\nLocalRTC=no\nCanNTP=yes\nNTP=yes\nNTPSynchronized=yes\n")
	clockFromChrony(c, `Reference ID    : D8EF2308 (216.239.35.8)
Stratum         : 2
Ref time (UTC)  : Fri Nov 20 23:55:10 2026
System time     : 0.000124529 seconds fast of NTP time
Leap status     : Normal
`)
	if c.Zone != "America/New_York" || c.Auto != "yes" || c.Synced != "yes" || c.Source != "216.239.35.8" ||
		c.Offset != "0.125 ms fast" || c.Last == nil || c.Last.Hour() != 23 {
		t.Errorf("linux: %+v", c)
	}

	c = &DPTClock{}
	clockFromTimedatectl(c, "NTP=no\nNTPSynchronized=no\n")
	if c.Auto != "no" || c.Synced != "no" {
		t.Errorf("NTP off: %+v", c)
	}

	// Windows with no time server: its own clock
	c = &DPTClock{Auto: "no"}
	clockFromW32tm(c, "Leap Indicator: 3(not synchronized)\r\nStratum: 0 (unspecified)\r\nLast Successful Sync Time: unspecified\r\nSource: Local CMOS Clock\r\nPhase Offset: 0.0000000s\r\n")
	if c.Synced != "no" || !strings.Contains(c.Source, "own clock") || c.Last != nil || c.Offset != "" {
		t.Errorf("windows unsynced: %+v", c)
	}
	var b bytes.Buffer
	c.Now = time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	renderClock(newOut(&b, false), c)
	if !strings.Contains(b.String(), "NO: set by hand") || !strings.Contains(b.String(), "own clock") {
		t.Errorf("render:\n%s", b.String())
	}

	c = &DPTClock{}
	clockFromW32tm(c, "Leap Indicator: 0(no warning)\r\nLast Successful Sync Time: 11/20/2026 6:01:12 PM\r\nSource: time.windows.com,0x9\r\nPhase Offset: -0.0021000s\r\n")
	if c.Synced != "yes" || c.Source != "time.windows.com" || c.Offset != "-2.100 ms" || c.Last == nil || c.Last.Hour() != 18 {
		t.Errorf("windows synced: %+v", c)
	}
}
