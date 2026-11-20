// SPDX-License-Identifier: MIT

package dpt

import (
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Live is the status line a person sees while dpt works: one line,
// redrawn in place on a terminal, with a spinner and what is still
// running ("ping 3/5   dns 4/5   time 1/3").  It is cleared before any
// result is printed, so the results read exactly as without it.  A nil
// *Live is off: every method is then a no-op (scripts, pipes, --json).
type Live struct {
	mu    sync.Mutex
	w     io.Writer
	width int
	parts []livePart
	drawn int // runes on the line now
	spin  int
	stop  chan struct{}
	done  chan struct{}
}

type livePart struct{ key, text string }

var liveSpinner = []string{"|", "/", "-", `\`}

// NewLive starts a status line on w (a terminal, width columns).
func NewLive(w io.Writer, width int) *Live {
	if width <= 0 {
		width = 80
	}
	l := &Live{w: w, width: width, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		t := time.NewTicker(120 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				l.mu.Lock()
				l.spin++
				l.draw()
				l.mu.Unlock()
			}
		}
	}()
	return l
}

// Set shows text for key, in place of what key showed before.
func (l *Live) Set(key, text string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.parts {
		if l.parts[i].key == key {
			l.parts[i].text = text
			l.draw()
			return
		}
	}
	l.parts = append(l.parts, livePart{key, text})
	l.draw()
}

// Drop takes key off the line.
func (l *Live) Drop(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.parts {
		if l.parts[i].key == key {
			l.parts = append(l.parts[:i], l.parts[i+1:]...)
			break
		}
	}
	l.draw()
}

// Out clears the line, runs print (which writes the results) and draws
// the line again under them.
func (l *Live) Out(print func()) {
	if l == nil {
		print()
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clear()
	print()
	l.draw()
}

// Stop clears the line for good.
func (l *Live) Stop() {
	if l == nil {
		return
	}
	select {
	case <-l.stop:
		return
	default:
	}
	close(l.stop)
	<-l.done
	l.mu.Lock()
	l.parts = nil
	l.clear()
	l.mu.Unlock()
}

// clear blanks the line; plain \r and spaces work on every console.
func (l *Live) clear() {
	if l.drawn > 0 {
		io.WriteString(l.w, "\r"+strings.Repeat(" ", l.drawn)+"\r")
		l.drawn = 0
	}
}

func (l *Live) draw() {
	if len(l.parts) == 0 {
		l.clear()
		return
	}
	var b []string
	for _, p := range l.parts {
		b = append(b, p.text)
	}
	s := liveSpinner[l.spin%len(liveSpinner)] + " " + strings.Join(b, "   ")
	if n := l.width - 1; utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n])
	}
	n := utf8.RuneCountInString(s)
	pad := ""
	if l.drawn > n {
		pad = strings.Repeat(" ", l.drawn-n)
	}
	io.WriteString(l.w, "\r"+s+pad)
	l.drawn = n + len(pad)
}
