// SPDX-License-Identifier: MIT
package shell

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openipv8.org/dpt/internal/dpt"
)

// fakeDNS answers on loopback UDP: A 192.0.2.7 for anything under
// example.test, MX for mail.example.test, NXDOMAIN otherwise.  It gives
// the address and the port.
func fakeDNS(t *testing.T) (string, int) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			if n < 12 {
				continue
			}
			name, off, err := readName(q, 12)
			if err != nil || off+4 > n {
				continue
			}
			qtype := binary.BigEndian.Uint16(q[off:])
			out := append([]byte{}, q[:off+4]...)
			out[2] |= 0x80 // QR
			out[3] = 0x80  // RA, NOERROR
			binary.BigEndian.PutUint16(out[6:], 0)
			binary.BigEndian.PutUint16(out[8:], 0)
			binary.BigEndian.PutUint16(out[10:], 0)
			rr := func(typ uint16, data []byte) {
				out = append(out, 0xc0, 12)
				out = binary.BigEndian.AppendUint16(out, typ)
				out = append(out, 0, 1, 0, 0, 0, 60)
				out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
				out = append(out, data...)
				binary.BigEndian.PutUint16(out[6:], binary.BigEndian.Uint16(out[6:])+1)
			}
			switch {
			case !strings.HasSuffix(name, "example.test"):
				out[3] = 0x83 // NXDOMAIN
			case qtype == dpt.DNSTypeA:
				rr(qtype, []byte{192, 0, 2, 7})
			case qtype == dpt.DNSTypeMX:
				w, _ := dpt.DNSWireName("mx.example.test")
				rr(qtype, append([]byte{0, 10}, w...))
			}
			pc.WriteTo(out, from)
		}
	}()
	a := pc.LocalAddr().(*net.UDPAddr)
	return a.IP.String(), a.Port
}

func readName(b []byte, off int) (string, int, error) {
	var labels []string
	for off < len(b) && b[off] != 0 {
		l := int(b[off])
		if off+1+l > len(b) {
			return "", 0, io.ErrUnexpectedEOF
		}
		labels = append(labels, string(b[off+1:off+1+l]))
		off += 1 + l
	}
	return strings.Join(labels, "."), off + 1, nil
}

func newTestShell(t *testing.T) (*Shell, *bytes.Buffer) {
	srv, port := fakeDNS(t)
	var out bytes.Buffer
	s := New(&out, []string{srv}, dpt.DPTDHCPOptions{})
	s.port = port
	return s, &out
}

func TestLookup(t *testing.T) {
	s, out := newTestShell(t)
	s.Do("www.example.test")
	if !strings.Contains(out.String(), "Name:\twww.example.test\nAddress: 192.0.2.7\n") || !strings.Contains(out.String(), "Non-authoritative answer:") {
		t.Errorf("A lookup:\n%s", out)
	}
	out.Reset()
	s.Do("set type=mx")
	s.Do("mail.example.test")
	if !strings.Contains(out.String(), "mail.example.test\tmail exchanger = 10 mx.example.test.") {
		t.Errorf("MX lookup:\n%s", out)
	}
	out.Reset()
	s.Do("set q=a")
	s.Do("nothing.invalid")
	if !strings.Contains(out.String(), "** server can't find nothing.invalid: NXDOMAIN") {
		t.Errorf("NXDOMAIN:\n%s", out)
	}
}

func TestSearchList(t *testing.T) {
	s, out := newTestShell(t)
	s.Do("set srchlist=example.test/other.test")
	s.Do("www")
	if !strings.Contains(out.String(), "Name:\twww.example.test") {
		t.Errorf("search list:\n%s", out)
	}
	if c := s.candidates("www"); strings.Join(c, " ") != "www.example.test. www.other.test. www." {
		t.Errorf("no dot: %v", c)
	}
	if c := s.candidates("a.b"); c[0] != "a.b." {
		t.Errorf("with a dot the name is tried first: %v", c)
	}
	if c := s.candidates("a.b."); len(c) != 1 {
		t.Errorf("a final dot is the name only: %v", c)
	}
	s.Do("set nosearch")
	s.Do("set nodefname")
	if c := s.candidates("www"); strings.Join(c, " ") != "www." {
		t.Errorf("nosearch nodefname: %v", c)
	}
}

func TestSettings(t *testing.T) {
	s, out := newTestShell(t)
	for _, l := range []string{"set type=caa", "set class=ch", "set timeout=5", "set retry=3", "set norecurse", "set vc", "set d2", "ntpd=time.example.test"} {
		s.Do(l)
	}
	if dpt.DNSTypeString(s.qtype) != "CAA" || s.qclass != dpt.DNSClassCH || s.timeout.Seconds() != 5 || s.retry != 3 ||
		s.recurse || !s.vc || !s.d2 || !s.debug || s.ntpd != "time.example.test" {
		t.Errorf("%+v", s)
	}
	s.Do("set ntpd=")
	if s.ntpd != "" {
		t.Error("set ntpd= clears it")
	}
	out.Reset()
	s.Do("set all")
	for _, w := range []string{"querytype = CAA", "class = CH", "novc", "ntpd = (the server)"} {
		if w == "novc" {
			if strings.Contains(out.String(), "novc") {
				t.Error("vc is on: set all shows novc")
			}
			continue
		}
		if !strings.Contains(out.String(), w) {
			t.Errorf("set all lacks %q:\n%s", w, out)
		}
	}
	out.Reset()
	for _, l := range []string{"set type=nonsense", "set bogus", "set timeout=0"} {
		s.Do(l)
	}
	if strings.Count(out.String(), "***") != 3 {
		t.Errorf("bad settings:\n%s", out)
	}
}

func TestCommands(t *testing.T) {
	s, out := newTestShell(t)
	if !s.Do("exit") {
		t.Error("exit")
	}
	if s.Do("") || s.Do("# a comment") {
		t.Error("empty line ends the shell")
	}
	s.Do("finger")
	s.Do("view x")
	s.Do("bogus a b")
	s.Do("help")
	for _, w := range []string{"finger: not supported", "view: not supported", "*** unknown command: bogus", "trydhcp [iface]", "ntpd=<server>"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("lacks %q:\n%s", w, out)
		}
	}
	out.Reset()
	s.Do("server 192.0.2.99")
	if s.server != "192.0.2.99" || !strings.Contains(out.String(), "Default server: 192.0.2.99") {
		t.Errorf("server:\n%s", out)
	}
	s.Do("root")
	if s.server != rootServer || s.prompt() != "dpt [a.root-servers.net]> " {
		t.Errorf("root: %s %q", s.server, s.prompt())
	}
}

// the line editor: arrows, history, Ctrl keys
func TestLineEditor(t *testing.T) {
	r := &lineReader{out: io.Discard, hist: []string{"first", "second"}}
	for _, c := range []struct{ keys, want string }{
		{"ab\x1b[Dc\r", "acb"},              // left arrow, insert
		{"abc\x7f\x7fx\r", "ax"},            // backspace
		{"hello\x01X\r", "Xhello"},          // Ctrl-A
		{"one two\x17three\r", "one three"}, // Ctrl-W
		{"xyz\x15abc\r", "abc"},             // Ctrl-U
		{"\x1b[A\r", "second"},              // up: the newest
		{"\x1b[A\x1b[A\r", "first"},         // up twice
		{"typed\x1b[A\x1b[B\r", "typed"},    // up and back down: the line being typed
		{"abc\x1b[H\x1b[3~\r", "bc"},        // Home, Delete
	} {
		r.plain = bufio.NewReader(strings.NewReader(c.keys))
		got, err := r.edit("> ")
		if err != nil || got != c.want {
			t.Errorf("%q: %q %v, want %q", c.keys, got, err, c.want)
		}
	}
	r.plain = bufio.NewReader(strings.NewReader("\x03"))
	if _, err := r.edit("> "); err != errInterrupt {
		t.Errorf("Ctrl-C: %v", err)
	}
	r.plain = bufio.NewReader(strings.NewReader("\x04"))
	if _, err := r.edit("> "); err != io.EOF {
		t.Errorf("Ctrl-D: %v", err)
	}
}

func TestComplete(t *testing.T) {
	s, _ := newTestShell(t)
	for _, c := range []struct{ before, add string }{
		{"sw", "eep "},
		{"out", "side-ip "},
		{"sweep ", "ports "},
		{"sweep p", "orts "},
		{"smtp mail.test ", "test "},
		{"smtp t", "est "},
		{"set norec", "urse "},
		{"set ty", "pe="},
		{"set type=aa", "AA "},
		{"nt", "pd="},
	} {
		add, _ := completeWord(c.before, s.complete)
		if add != c.add {
			t.Errorf("%q: %q, want %q", c.before, add, c.add)
		}
	}
	// several with nothing more in common: the list, nothing added
	if add, list := completeWord("s", s.complete); add != "" || len(list) < 4 {
		t.Errorf("s: %q %v", add, list)
	}
	if add, _ := completeWord("p", s.complete); add != "" { // ping, ports
		t.Errorf("p: %q", add)
	}
	if add, _ := completeWord("po", s.complete); add != "rts " {
		t.Errorf("po: %q", add)
	}
}

func TestNoPasswordKept(t *testing.T) {
	for in, want := range map[string]string{
		"smtp mail.test test jamie s3cret": "smtp mail.test test jamie",
		"smtp test jamie s3cret":           "smtp test jamie",
		"smtp mail.test test jamie":        "smtp mail.test test jamie",
		"ping test x y":                    "ping test x y",
	} {
		if got, _ := withoutPassword(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	dir := t.TempDir()
	r := newLineReader(os.Stdin, io.Discard, filepath.Join(dir, "h"))
	r.redact = withoutPassword
	r.remember("smtp m test u s3cret")
	b, _ := os.ReadFile(filepath.Join(dir, "h"))
	if strings.Contains(string(b), "s3cret") || len(r.hist) != 1 || strings.Contains(r.hist[0], "s3cret") {
		t.Errorf("history: %q %v", b, r.hist)
	}
}

func TestNetCommands(t *testing.T) {
	s, out := newTestShell(t)
	s.Do("smtp test")
	s.Do("smtp h test u") // no terminal to ask at
	s.Do("sweep 10.0.0.0/8")
	s.Do("ports a b")
	s.Do("help")
	for _, w := range []string{"usage: smtp [host] [test <user> [<password>]]", "give the password", "more than 1024 addresses", "usage: ports [host]", "outside-ip", "sweep [ports] [network]"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("lacks %q:\n%s", w, out)
		}
	}
}
