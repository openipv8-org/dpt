// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// connect <host> <port> [tls]: what telnet is used for.  Does the port
// take a connection, how fast, with what TLS and certificate, and what
// does the server say first (SSH's version, a mail server's greeting, a
// device's login prompt)?  Then, at a terminal, what is typed goes to
// the server, a line at a time, and what it sends back is shown.

// ConnectTLSPorts start TLS from the first byte: connect speaks TLS on
// them without being asked.
var ConnectTLSPorts = map[int]bool{443: true, 465: true, 563: true, 636: true, 853: true, 989: true, 990: true,
	992: true, 993: true, 994: true, 995: true, 5061: true, 8443: true}

// connectTLSPort: a known TLS port, or one ending in 443 (1443 ... 14443).
func connectTLSPort(p int) bool { return ConnectTLSPorts[p] || p > 1000 && p%1000 == 443 }

// ConnectOptions is one connect.
type ConnectOptions struct {
	Port     int
	TLS      bool          // TLS even on a port not known for it
	NoTLS    bool          // plain even on a TLS port
	Timeout  time.Duration // connect, handshake; 0: 5 s
	Wait     time.Duration // how long to wait for the server to speak first; 0: 2 s
	Family   int
	Resolver *net.Resolver
	Roots    *x509.CertPool // nil: the system's
	Live     *Live
}

// ConnectReport is a connect.
type ConnectReport struct {
	Target  DPTTarget `json:"target"`
	Port    int       `json:"port"`
	Connect Ms        `json:"connect_ms,omitempty"`
	TLS     *SMTPTLS  `json:"tls,omitempty"`
	Banner  string    `json:"banner,omitempty"` // what the server said first
	Kind    string    `json:"kind,omitempty"`   // what the banner shows it to be: SSH, SMTP...
	Telnet  bool      `json:"telnet,omitempty"` // it negotiated telnet options
	Note    string    `json:"note,omitempty"`
	Error   string    `json:"error,omitempty"`
	Status  string    `json:"status"`
}

// RunConnect connects and reads what the server says first; the
// connection is given open (nil on failure) for Talk.
func RunConnect(ctx context.Context, target string, o ConnectOptions) (*ConnectReport, *ConnectConn, error) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Wait <= 0 {
		o.Wait = 2 * time.Second
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Port < 1 || o.Port > 65535 {
		return nil, nil, fmt.Errorf("port %d: 1 to 65535", o.Port)
	}
	rep := &ConnectReport{Target: DPTTarget{Input: target}, Port: o.Port, Status: DPTFail}
	o.Live.Set("connect", "looking up "+Safe(target))
	defer o.Live.Drop("connect")
	look, cancel := context.WithTimeout(ctx, o.Timeout)
	ips, err := DPTResolve(look, target, o.Family, o.Resolver)
	cancel()
	if err != nil {
		return nil, nil, err
	}
	for _, ip := range ips {
		rep.Target.Addresses = append(rep.Target.Addresses, ip.String())
	}
	ip := ips[0].String()
	rep.Target.Tested = []string{ip}
	addr := net.JoinHostPort(ip, strconv.Itoa(o.Port))
	o.Live.Set("connect", "connecting to "+addr)
	start := time.Now()
	d := net.Dialer{Timeout: o.Timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		rep.Error = smtpErr(err, o.Timeout)
		if strings.Contains(rep.Error, "refused") {
			rep.Status, rep.Error = DPTNone, "refused: nothing listens on "+strconv.Itoa(o.Port)
		}
		return rep, nil, nil
	}
	rep.Connect = ms(time.Since(start))
	var conn net.Conn = raw
	if (o.TLS || connectTLSPort(o.Port)) && !o.NoTLS {
		o.Live.Set("connect", "TLS with "+addr)
		name := strings.Trim(target, "[]")
		cfg := &tls.Config{ServerName: name, InsecureSkipVerify: true, RootCAs: o.Roots}
		if net.ParseIP(name) != nil {
			cfg.ServerName = ""
		}
		tc := tls.Client(raw, cfg)
		raw.SetDeadline(time.Now().Add(o.Timeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			rep.Error = "TLS: " + smtpErr(err, o.Timeout)
			return rep, nil, nil
		}
		raw.SetDeadline(time.Time{})
		rep.TLS = smtpTLSInfo(tc.ConnectionState(), name, o.Roots)
		conn = tc
	}
	c := newConnectConn(conn)
	o.Live.Set("connect", "waiting for "+addr+" to speak")
	rep.Banner = strings.TrimRight(SafeLines(string(c.first(o.Wait))), " \n")
	rep.Telnet = c.telnet
	rep.Kind, rep.Note = connectKind(rep.Banner, o.Port, rep.TLS != nil)
	rep.Status = DPTOK
	switch {
	case rep.TLS != nil && !rep.TLS.Trusted:
		rep.Status = DPTWarn
		rep.Note = strings.TrimSuffix("certificate not trusted; "+rep.Note, "; ")
	case rep.TLS != nil && CertExpiring(rep.TLS.NotAfter):
		rep.Status = DPTWarn
		rep.Note = strings.TrimSuffix("the certificate "+CertExpiryWords(rep.TLS.NotAfter)+"; "+rep.Note, "; ")
	case rep.Kind == "telnet":
		rep.Status = DPTWarn
	}
	return rep, c, nil
}

// SafeLines is s with its line breaks kept (CRLF as LF) and every other
// control character, escape sequences too, taken out: what a server
// sends is shown, never acted on by the terminal.
func SafeLines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	ls := strings.Split(s, "\n")
	for i, l := range ls {
		ls[i] = Safe(strings.ToValidUTF8(l, "?"))
	}
	return strings.Join(ls, "\n")
}

// connectKind names the server from its first words.
func connectKind(banner string, port int, isTLS bool) (kind, note string) {
	b := strings.ToUpper(banner)
	switch {
	case strings.HasPrefix(b, "SSH-"):
		return "SSH", "an SSH server: log in with ssh; this shows only that it answers, and its version"
	case strings.HasPrefix(b, "220") && (strings.Contains(b, "SMTP") || strings.Contains(b, "MAIL") || port == 25 || port == 587 || port == 465):
		return "SMTP", "a mail server: smtp tests it fully"
	case strings.HasPrefix(b, "220"):
		return "FTP", "FTP: logins go in the clear unless it offers AUTH TLS"
	case strings.HasPrefix(b, "+OK"):
		return "POP3", ""
	case strings.HasPrefix(b, "* OK"):
		return "IMAP", ""
	case strings.HasPrefix(b, "RFB "):
		return "VNC", ""
	case port == 23 || strings.Contains(strings.ToLower(banner), "login:"):
		return "telnet", "a telnet login: the password would go in the clear"
	case banner == "" && (port == 80 || port == 443 || port == 8080 || port == 8000 || port%1000 == 443):
		return "", "it waits for the client to speak first, as web servers do: try  GET / HTTP/1.0  and an empty line"
	case banner == "":
		return "", "it said nothing first: it waits for the client to speak"
	}
	return "", ""
}

// ConnectConn is a connection being talked over: telnet negotiation is
// answered (refused) and kept out of what is shown.
type ConnectConn struct {
	conn   net.Conn
	telnet bool
	mu     sync.Mutex
}

func newConnectConn(c net.Conn) *ConnectConn { return &ConnectConn{conn: c} }

// Close closes the connection.
func (c *ConnectConn) Close() error { return c.conn.Close() }

// first reads what the server says on its own within wait, stopping
// 300 ms after it last said something.
func (c *ConnectConn) first(wait time.Duration) []byte {
	var out []byte
	buf := make([]byte, 4096)
	deadline := time.Now().Add(wait)
	for len(out) < 8192 {
		c.conn.SetReadDeadline(deadline)
		n, err := c.conn.Read(buf)
		out = append(out, c.filter(buf[:n])...)
		if err != nil {
			break
		}
		if d := time.Now().Add(300 * time.Millisecond); d.Before(deadline) {
			deadline = d
		}
	}
	c.conn.SetReadDeadline(time.Time{})
	return out
}

// Telnet commands.
const (
	telIAC  = 255
	telDONT = 254
	telDO   = 253
	telWONT = 252
	telWILL = 251
	telSB   = 250
	telSE   = 240
)

// filter takes telnet negotiation out of b, refusing each option: we
// will not, and we ask the server not to.  (A telnet server then falls
// back to plain lines, which is all connect shows.)
func (c *ConnectConn) filter(b []byte) []byte {
	if bytes.IndexByte(b, telIAC) < 0 {
		return b
	}
	var out, reply []byte
	for i := 0; i < len(b); i++ {
		if b[i] != telIAC || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		c.telnet = true
		switch cmd := b[i+1]; {
		case cmd == telIAC: // an escaped 255
			out = append(out, telIAC)
			i++
		case (cmd == telDO || cmd == telDONT || cmd == telWILL || cmd == telWONT) && i+2 < len(b):
			opt := b[i+2]
			if cmd == telDO {
				reply = append(reply, telIAC, telWONT, opt)
			} else if cmd == telWILL {
				reply = append(reply, telIAC, telDONT, opt)
			}
			i += 2
		case cmd == telSB:
			for i += 2; i+1 < len(b) && !(b[i] == telIAC && b[i+1] == telSE); i++ {
			}
			i++
		default:
			i++
		}
	}
	if len(reply) > 0 {
		c.mu.Lock()
		c.conn.Write(reply)
		c.mu.Unlock()
	}
	return out
}

// Talk sends each line read (with CRLF) and copies what the server sends
// to out, until read fails (Ctrl-D, Ctrl-C) or the server closes.  It
// says which.  With linger, when the lines run out (a pipe's end) it
// waits that long for the server to answer and close.
func (c *ConnectConn) Talk(read func() (string, error), out io.Writer, linger time.Duration) string {
	closed := make(chan struct{})
	var wmu sync.Mutex
	go func() {
		defer close(closed)
		buf := make([]byte, 4096)
		for {
			n, err := c.conn.Read(buf)
			if n > 0 {
				wmu.Lock()
				out.Write([]byte(SafeLines(string(c.filter(buf[:n])))))
				wmu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	lines := make(chan string)
	done := make(chan struct{})
	go func() {
		defer close(lines)
		for {
			l, err := read()
			if err != nil {
				return
			}
			select {
			case lines <- l:
			case <-done:
				return
			}
		}
	}()
	defer close(done)
	for {
		select {
		case <-closed:
			return "the server closed the connection"
		case l, ok := <-lines:
			if !ok {
				if linger > 0 {
					select {
					case <-closed:
						return "the server closed the connection"
					case <-time.After(linger):
					}
				}
				c.conn.Close()
				<-closed
				return "closed"
			}
			c.mu.Lock()
			_, err := c.conn.Write([]byte(l + "\r\n"))
			c.mu.Unlock()
			if err != nil {
				return "the connection broke: " + err.Error()
			}
		}
	}
}

// RenderConnect writes a connect.
//
//	TARGET    mail.example.com  (192.0.2.25)
//
//	CONNECT   port 25   connected in 23.1 ms
//
//	SAYS      220 mail.example.com ESMTP Postfix
//	          a mail server: smtp tests it fully
func RenderConnect(w io.Writer, r *ConnectReport, color bool) {
	o := newOut(w, color)
	s := o.bold(r.Target.Input)
	if ip := r.Target.Tested[0]; ip != r.Target.Input {
		s += "  (" + ip + ")"
	}
	o.line("TARGET", s)
	if r.Error != "" {
		o.line("CONNECT", fmt.Sprintf("port %d   ", r.Port)+o.by(r.Status, r.Error))
		return
	}
	o.line("CONNECT", fmt.Sprintf("port %d   connected in %s ms", r.Port, fms(r.Connect)))
	if r.TLS != nil {
		renderTLS(o, r.TLS)
	}
	if r.Banner != "" {
		for i, l := range strings.Split(strings.ReplaceAll(r.Banner, "\r\n", "\n"), "\n") {
			sec := ""
			if i == 0 {
				sec = "SAYS"
			}
			o.line(sec, l)
		}
	}
	note := r.Note
	if r.Kind != "" && !strings.Contains(strings.ToLower(note), strings.ToLower(r.Kind)) {
		note = strings.TrimSuffix(r.Kind+"; "+note, "; ")
	}
	if note != "" {
		sec := ""
		if r.Banner == "" {
			sec = "SAYS"
		}
		o.line(sec, o.by(r.Status, note))
	}
}
