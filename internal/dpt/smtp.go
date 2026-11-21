// SPDX-License-Identifier: MIT

package dpt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SMTP: does the address take mail, on which ports, and does each one
// start TLS?
//
//	25   smtp: server to server, STARTTLS
//	465  submissions: TLS from the first byte (RFC 8314)
//	587  submission: STARTTLS, then AUTH
//
// With a user it then logs in (AUTH PLAIN or LOGIN) where the password
// is safest: TLS with a trusted certificate, else TLS with one that is
// not, else in the clear when that is all the server works with.  A
// login that is not over trusted TLS is WARN, and says why.

// SMTPPortSpec is a port and how it starts TLS.
type SMTPPortSpec struct {
	Port     int
	Implicit bool   // TLS from the first byte; else STARTTLS
	Name     string // smtp, submissions, submission
}

// SMTPPorts are the ports tested, in order.
var SMTPPorts = []SMTPPortSpec{
	{25, false, "smtp"},
	{465, true, "submissions"},
	{587, false, "submission"},
}

// smtpLoginOrder is where a login is tried first: the submission ports.
var smtpLoginOrder = []int{587, 465, 25}

// SMTPOptions is one smtp run.
type SMTPOptions struct {
	Timeout  time.Duration // each step (connect, greeting, a command); 0: 10 s
	Family   int           // 4, 6 or 0
	Resolver *net.Resolver // nil: the system's
	// User and Password, when User is set, log in after the ports are
	// tested.  The password is in no report.
	User, Password string
	// To, when set, is sent a test message from From (after the login,
	// on its connection; with no User, on port 25 as any server would).
	// Agent names the sender in it (dpt v0.2.1).
	From, To, Agent string
	Live            *Live
	// OnTarget gets the target once resolved; OnPort each port when it
	// is done, in the order of Ports; OnLogin the login.
	OnTarget func(r *SMTPReport)
	OnPort   func(p *SMTPPort)
	OnLogin  func(l *SMTPLogin)
	OnSend   func(m *SMTPSend)
	// Ports; nil: SMTPPorts.
	Ports []SMTPPortSpec
	// Roots the certificates are checked against; nil: the system's.
	Roots *x509.CertPool
}

func (o *SMTPOptions) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Ports == nil {
		o.Ports = SMTPPorts
	}
}

// SMTPTLS is what TLS a port gave.
type SMTPTLS struct {
	Version     string    `json:"version"`
	Cipher      string    `json:"cipher"`
	Subject     string    `json:"subject,omitempty"`
	Names       []string  `json:"names,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotAfter    time.Time `json:"not_after"`
	Trusted     bool      `json:"trusted"`
	VerifyError string    `json:"verify_error,omitempty"`
}

// SMTPPort is one port's test.
type SMTPPort struct {
	Port       int      `json:"port"`
	Name       string   `json:"name"`
	Implicit   bool     `json:"implicit_tls"`
	Connect    Ms       `json:"connect_ms,omitempty"`
	Banner     string   `json:"banner,omitempty"`
	StartTLS   bool     `json:"starttls_offered"`
	TLS        *SMTPTLS `json:"tls,omitempty"`
	Extensions []string `json:"extensions,omitempty"` // EHLO's, after TLS when there was TLS
	Auth       []string `json:"auth,omitempty"`
	AuthPlain  bool     `json:"auth_before_tls,omitempty"` // Auth was offered with no TLS
	authClear  []string // AUTH offered before STARTTLS
	Error      string   `json:"error,omitempty"`
	Note       string   `json:"note,omitempty"` // why it is WARN
	NoService  bool     `json:"no_service,omitempty"`
	Status     string   `json:"status"`
}

// SMTPLogin is the login.
type SMTPLogin struct {
	User      string `json:"user"`
	Port      int    `json:"port,omitempty"`
	Mechanism string `json:"mechanism,omitempty"`
	Security  string `json:"security,omitempty"` // TLS, TLS with a certificate not trusted, in the clear
	Note      string `json:"note,omitempty"`     // why it is WARN
	Reply     string `json:"reply,omitempty"`
	Error     string `json:"error,omitempty"`
	Status    string `json:"status"`
}

// SMTPSend is the test message.
type SMTPSend struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Port    int    `json:"port,omitempty"`
	Step    string `json:"step,omitempty"` // MAIL, RCPT or DATA: where it was refused
	Reply   string `json:"reply,omitempty"`
	Error   string `json:"error,omitempty"`
	Status  string `json:"status"`
}

// SMTPReport is an smtp run.
type SMTPReport struct {
	Target  DPTTarget  `json:"target"`
	MX      []string   `json:"mx,omitempty"` // the name's MX hosts, when it has any
	Ports   []SMTPPort `json:"ports"`
	Login   *SMTPLogin `json:"login,omitempty"`
	Send    *SMTPSend  `json:"send,omitempty"`
	Started time.Time  `json:"started"`
}

// Failed: a port failed, the login or the test message failed, or no
// port took mail.
func (r *SMTPReport) Failed() bool {
	if r.Send != nil && r.Send.Status == DPTFail {
		return true
	}
	any := false
	for _, p := range r.Ports {
		if p.Status == DPTFail {
			return true
		}
		if p.Status == DPTOK || p.Status == DPTWarn {
			any = true
		}
	}
	return !any || r.Login != nil && r.Login.Status == DPTFail
}

// RunSMTP tests target's SMTP ports and, with a user, logs in.
func RunSMTP(ctx context.Context, target string, o SMTPOptions) (*SMTPReport, error) {
	o.defaults()
	rep := &SMTPReport{Target: DPTTarget{Input: target}, Started: time.Now()}
	o.Live.Set("resolve", "looking up "+Safe(target))
	look, cancel := context.WithTimeout(ctx, o.Timeout)
	ips, err := DPTResolve(look, target, o.Family, o.Resolver)
	if err == nil && net.ParseIP(strings.Trim(target, "[]")) == nil {
		if mx, err := o.Resolver.LookupMX(look, target); err == nil {
			for _, m := range mx {
				rep.MX = append(rep.MX, Safe(strings.TrimSuffix(m.Host, ".")))
			}
		}
	}
	cancel()
	o.Live.Drop("resolve")
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		rep.Target.Addresses = append(rep.Target.Addresses, ip.String())
	}
	ip := ips[0].String()
	rep.Target.Tested = []string{ip}
	if o.OnTarget != nil {
		o.OnTarget(rep)
	}
	// the certificate is checked against the name typed
	name := strings.Trim(target, "[]")

	rep.Ports = make([]SMTPPort, len(o.Ports))
	done := make([]chan struct{}, len(o.Ports))
	for i, spec := range o.Ports {
		done[i] = make(chan struct{})
		go func() {
			defer close(done[i])
			p := &rep.Ports[i]
			c := smtpOpen(ctx, ip, name, spec, &o, p, false)
			if c != nil {
				c.quit()
			}
		}()
	}
	for i := range o.Ports {
		<-done[i]
		if o.OnPort != nil {
			o.OnPort(&rep.Ports[i])
		}
	}
	var send func(c *smtpConn, port int)
	if o.To != "" {
		send = func(c *smtpConn, port int) { rep.Send = smtpSend(c, port, &o) }
	}
	switch {
	case ctx.Err() != nil:
	case o.User != "":
		rep.Login = smtpLogin(ctx, ip, name, rep.Ports, &o, send)
		if o.OnLogin != nil {
			o.OnLogin(rep.Login)
		}
		if o.To != "" && rep.Send == nil {
			rep.Send = &SMTPSend{From: Safe(o.From), To: Safe(o.To), Status: DPTFail, Error: "not sent: the login failed"}
		}
	case send != nil:
		// no login: port 25, as a server delivering to this one would
		rep.Send = &SMTPSend{From: Safe(o.From), To: Safe(o.To), Port: 25, Status: DPTFail, Error: "not sent: port 25 does not take mail"}
		for _, spec := range o.Ports {
			if spec.Port != 25 {
				continue
			}
			var p SMTPPort
			if c := smtpOpen(ctx, ip, name, spec, &o, &p, false); c != nil {
				send(c, 25)
				c.quit()
			}
		}
	}
	if rep.Send != nil && o.OnSend != nil {
		o.OnSend(rep.Send)
	}
	return rep, nil
}

// smtpSend sends the test message on c: MAIL, RCPT, DATA.
func smtpSend(c *smtpConn, port int, o *SMTPOptions) *SMTPSend {
	from := o.From
	if from == "" {
		from = o.User
	}
	ip := "this machine"
	if a, ok := c.raw.LocalAddr().(*net.TCPAddr); ok {
		ip = a.IP.String()
	}
	m := &SMTPSend{From: Safe(from), To: Safe(o.To), Port: port, Status: DPTFail,
		Subject: "test from dpt at " + ip}
	o.Live.Set("send", "sending the test message to "+m.To)
	defer o.Live.Drop("send")
	step := func(name string, want int, format string, args ...any) bool {
		code, msg, err := c.cmd(format, args...)
		if err != nil {
			m.Step, m.Error = name, smtpErr(err, c.timeout)
			return false
		}
		m.Reply = smtpReply(code, msg)
		if code != want {
			m.Step, m.Error = name, name+" refused"
			return false
		}
		return true
	}
	if !step("MAIL", 250, "MAIL FROM:<%s>", from) || !step("RCPT", 250, "RCPT TO:<%s>", o.To) && !acceptedRcpt(m) ||
		!step("DATA", 354, "DATA") {
		return m
	}
	host, _ := os.Hostname()
	agent := o.Agent
	if agent == "" {
		agent = "dpt"
	}
	now := time.Now()
	body := strings.Join([]string{
		"From: <" + from + ">",
		"To: <" + o.To + ">",
		"Subject: " + m.Subject,
		"Date: " + now.Format(time.RFC1123Z),
		fmt.Sprintf("Message-ID: <dpt.%d@%s>", now.UnixNano(), mailDomain(from)),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"This is a test message sent by " + agent + ".",
		"",
		"  from      " + Safe(host) + " (" + ip + ")",
		"  through   " + c.server + fmt.Sprintf(" port %d", port),
		"  as        " + Safe(o.User),
		"  at        " + now.Format("2006-01-02 15:04:05 MST"),
		"",
		"If it reached you, sending through this server works.",
	}, "\r\n")
	if o.User == "" {
		body = strings.Replace(body, "  as        \r\n", "  as        (no login)\r\n", 1)
	}
	c.raw.SetDeadline(time.Now().Add(c.timeout))
	w := c.tp.DotWriter()
	_, err := w.Write([]byte(body + "\r\n"))
	if err == nil {
		err = w.Close()
	}
	if err != nil {
		m.Step, m.Error = "DATA", smtpErr(err, c.timeout)
		return m
	}
	code, msg, err := c.read()
	if err != nil {
		m.Step, m.Error = "DATA", smtpErr(err, c.timeout)
		return m
	}
	m.Reply = smtpReply(code, msg)
	if code != 250 {
		m.Step, m.Error = "DATA", "the message was refused"
		return m
	}
	m.Status = DPTOK
	return m
}

// mailDomain is the domain of an address, for a Message-ID.
func mailDomain(addr string) string {
	if _, d, ok := strings.Cut(addr, "@"); ok && d != "" && !strings.ContainsAny(d, "<> \r\n") {
		return d
	}
	return "dpt.invalid"
}

// acceptedRcpt: 251 (will forward) is a yes too.
func acceptedRcpt(m *SMTPSend) bool {
	if strings.HasPrefix(m.Reply, "251") {
		m.Step, m.Error = "", ""
		return true
	}
	return false
}

// SMTPUse is the smtp command's words.
const SMTPUse = "smtp <host> [test <user> [<password>]] [from <address>] [to <address>]"

// ParseSMTPWords reads what follows the host: [test <user>
// [<password>]] [from <address>] [to <address>].  A from with no to is
// an error; from defaults to the user when that is an address.
func ParseSMTPWords(w []string) (user, pass, from, to string, err error) {
	kw := func(s string) bool {
		return strings.EqualFold(s, "test") || strings.EqualFold(s, "from") || strings.EqualFold(s, "to")
	}
	for len(w) > 0 {
		k := strings.ToLower(w[0])
		if len(w) < 2 || kw(w[1]) {
			return "", "", "", "", errors.New(SMTPUse)
		}
		switch {
		case k == "test" && user == "":
			user, w = w[1], w[2:]
			if len(w) > 0 && !kw(w[0]) {
				pass, w = w[0], w[1:]
			}
		case k == "from" && from == "":
			from, w = w[1], w[2:]
		case k == "to" && to == "":
			to, w = w[1], w[2:]
		default:
			return "", "", "", "", errors.New(SMTPUse)
		}
	}
	for _, a := range []string{from, to} {
		if a != "" && !MailAddr(a) {
			return "", "", "", "", fmt.Errorf("%q is not a mail address (name@domain)", Printable(a))
		}
	}
	if to == "" && from != "" {
		return "", "", "", "", errors.New("from goes with to: the address the test message is sent to")
	}
	if to != "" && from == "" {
		if !MailAddr(user) {
			return "", "", "", "", errors.New("give from <address>: the user is not a mail address")
		}
		from = user
	}
	return user, pass, from, to, nil
}

// MailAddr: s is name@domain with nothing that could break a header or
// a command.
func MailAddr(s string) bool {
	l, d, ok := strings.Cut(s, "@")
	return ok && l != "" && strings.Contains(d, ".") && !strings.ContainsAny(s, "<>()[],;: \t\r\n\"\\") &&
		strings.Count(s, "@") == 1 && len(s) <= 254
}

// smtpConn is one SMTP session.
type smtpConn struct {
	raw     net.Conn
	tp      *textproto.Conn
	timeout time.Duration
	stop    func() bool
	server  string // the name typed, for the test message
}

// cmd sends a command and reads the reply (any code).
func (c *smtpConn) cmd(format string, args ...any) (int, string, error) {
	c.raw.SetDeadline(time.Now().Add(c.timeout))
	id, err := c.tp.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.tp.StartResponse(id)
	defer c.tp.EndResponse(id)
	return c.tp.ReadResponse(0)
}

func (c *smtpConn) read() (int, string, error) {
	c.raw.SetDeadline(time.Now().Add(c.timeout))
	return c.tp.ReadResponse(0)
}

func (c *smtpConn) close() {
	c.stop()
	c.tp.Close()
	c.raw.Close()
}

func (c *smtpConn) quit() {
	c.cmd("QUIT")
	c.close()
}

// smtpReply is a reply as shown: its lines on one, code first (535 5.7.8
// Username and Password not accepted. Learn more at https://...).
func smtpReply(code int, msg string) string {
	var parts []string
	prev := ""
	for _, l := range strings.Split(msg, "\n") {
		l = strings.TrimSpace(Safe(l))
		// the enhanced status code repeats on every line: keep the first
		if f, rest, ok := strings.Cut(l, " "); ok && f == prev {
			l = rest
		} else if ok && len(parts) == 0 && strings.Count(f, ".") == 2 {
			prev = f
		}
		parts = append(parts, l)
	}
	s := strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return strconv.Itoa(code) + " " + s
}

// smtpErr is a network error as shown.
func smtpErr(err error, timeout time.Duration) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Sprintf("no answer in %s", timeout)
	}
	if errors.Is(err, context.Canceled) {
		return "interrupted"
	}
	return Safe(err.Error())
}

// smtpOpen connects to spec's port, reads the greeting, says EHLO and
// starts TLS, filling p as it goes.  It gives the session (after EHLO,
// over TLS when there was TLS), or nil with p's status set.
// With clear, a STARTTLS port stays plain: the session is given after
// the first EHLO.
func smtpOpen(ctx context.Context, ip, name string, spec SMTPPortSpec, o *SMTPOptions, p *SMTPPort, clear bool) *smtpConn {
	*p = SMTPPort{Port: spec.Port, Name: spec.Name, Implicit: spec.Implicit}
	key := "smtp" + strconv.Itoa(spec.Port)
	defer o.Live.Drop(key)
	live := func(s string) { o.Live.Set(key, strconv.Itoa(spec.Port)+" "+s) }
	fail := func(s string) *smtpConn { p.Error, p.Status = s, DPTFail; return nil }

	live("connecting")
	start := time.Now()
	d := net.Dialer{Timeout: o.Timeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(spec.Port)))
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			p.Error, p.NoService, p.Status = "refused: nothing listens", true, DPTNone
			return nil
		}
		s := smtpErr(err, o.Timeout)
		if strings.HasPrefix(s, "no answer") {
			s = "no connection: " + s + " (a firewall drops it"
			if spec.Port == 25 {
				s += "; many ISPs and clouds block outgoing 25"
			}
			s += ")"
		}
		return fail(s)
	}
	p.Connect = ms(time.Since(start))
	c := &smtpConn{raw: raw, timeout: o.Timeout, stop: context.AfterFunc(ctx, func() { raw.Close() }), server: Safe(name)}
	c.tp = textproto.NewConn(raw)
	fail = func(s string) *smtpConn {
		c.close()
		p.Error, p.Status = s, DPTFail
		return nil
	}

	tlsStart := func(conn net.Conn) error {
		cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
		if net.ParseIP(name) == nil {
			cfg.ServerName = name
		}
		tc := tls.Client(conn, cfg)
		raw.SetDeadline(time.Now().Add(o.Timeout))
		if err := tc.HandshakeContext(ctx); err != nil {
			return err
		}
		p.TLS = smtpTLSInfo(tc.ConnectionState(), name, o.Roots)
		c.raw = tc
		c.tp = textproto.NewConn(tc)
		return nil
	}
	if spec.Implicit {
		live("TLS")
		if err := tlsStart(raw); err != nil {
			return fail("TLS handshake: " + smtpErr(err, o.Timeout))
		}
	}

	live("greeting")
	code, msg, err := c.read()
	if err != nil {
		return fail("greeting: " + smtpErr(err, o.Timeout))
	}
	first, _, _ := strings.Cut(msg, "\n")
	p.Banner = smtpReply(code, first)
	if code != 220 {
		return fail("greeting refused: " + p.Banner)
	}

	ehlo := func() error {
		host := "[127.0.0.1]"
		if a, ok := raw.LocalAddr().(*net.TCPAddr); ok {
			if a.IP.To4() != nil {
				host = "[" + a.IP.String() + "]"
			} else {
				host = "[IPv6:" + a.IP.String() + "]"
			}
		}
		code, msg, err := c.cmd("EHLO %s", host)
		if err != nil {
			return errors.New(smtpErr(err, o.Timeout))
		}
		if code != 250 {
			return errors.New(smtpReply(code, msg))
		}
		p.Extensions, p.Auth, p.StartTLS = nil, nil, false
		lines := strings.Split(msg, "\n")
		for _, l := range lines[1:] {
			l = Safe(strings.TrimSpace(l))
			p.Extensions = append(p.Extensions, l)
			kw, rest, _ := strings.Cut(strings.ToUpper(l), " ")
			switch {
			case kw == "STARTTLS":
				p.StartTLS = true
			case kw == "AUTH":
				p.Auth = smtpMechs(p.Auth, rest)
			case strings.HasPrefix(kw, "AUTH="): // old servers
				p.Auth = smtpMechs(p.Auth, kw[5:]+" "+rest)
			}
		}
		return nil
	}
	live("EHLO")
	if err := ehlo(); err != nil {
		return fail("EHLO: " + err.Error())
	}
	if !spec.Implicit {
		p.authClear = slices.Clone(p.Auth)
		if clear {
			p.AuthPlain = len(p.Auth) > 0
			p.Status = DPTWarn
			return c
		}
		if !p.StartTLS {
			p.AuthPlain = len(p.Auth) > 0
			p.Status, p.Note = DPTWarn, "no STARTTLS: everything goes in the clear"
			return c
		}
		live("STARTTLS")
		code, msg, err := c.cmd("STARTTLS")
		if err != nil {
			return fail("STARTTLS: " + smtpErr(err, o.Timeout))
		}
		if code != 220 {
			return fail("STARTTLS refused: " + smtpReply(code, msg))
		}
		if err := tlsStart(raw); err != nil {
			return fail("STARTTLS handshake: " + smtpErr(err, o.Timeout))
		}
		live("EHLO over TLS")
		if err := ehlo(); err != nil {
			return fail("EHLO over TLS: " + err.Error())
		}
		p.StartTLS = true
	}
	p.Status = DPTOK
	switch t := p.TLS; {
	case !t.Trusted:
		p.Status, p.Note = DPTWarn, "certificate not trusted"
	case t.Version == "TLS 1.0" || t.Version == "TLS 1.1":
		p.Status, p.Note = DPTWarn, t.Version+" is obsolete"
	case time.Until(t.NotAfter) < 14*24*time.Hour:
		p.Status, p.Note = DPTWarn, "certificate expires in under 14 days"
	}
	return c
}

// smtpMechs adds the AUTH mechanisms in s to have.
func smtpMechs(have []string, s string) []string {
	for _, m := range strings.Fields(s) {
		if !slices.Contains(have, m) {
			have = append(have, m)
		}
	}
	return have
}

// smtpTLSInfo is the connection's TLS and its certificate checked
// against name.
func smtpTLSInfo(cs tls.ConnectionState, name string, roots *x509.CertPool) *SMTPTLS {
	t := &SMTPTLS{Version: tls.VersionName(cs.Version), Cipher: tls.CipherSuiteName(cs.CipherSuite)}
	if len(cs.PeerCertificates) == 0 {
		t.VerifyError = "no certificate"
		return t
	}
	leaf := cs.PeerCertificates[0]
	t.Subject = Safe(leaf.Subject.CommonName)
	for _, n := range leaf.DNSNames {
		t.Names = append(t.Names, Safe(n))
	}
	if t.Subject == "" && len(t.Names) > 0 {
		t.Subject = t.Names[0]
	}
	t.Issuer = Safe(leaf.Issuer.CommonName)
	if t.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		t.Issuer = Safe(leaf.Issuer.Organization[0])
	}
	t.NotAfter = leaf.NotAfter
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Intermediates: inter, Roots: roots})
	if err != nil {
		t.VerifyError = Safe(err.Error())
	} else {
		t.Trusted = true
	}
	return t
}

// How a login's password travels, best first.
const (
	smtpTrusted   = iota // TLS, the certificate trusted
	smtpUntrusted        // TLS, the certificate not trusted
	smtpClear            // no TLS: all the server works with
)

var smtpSecurity = []string{"TLS", "TLS with a certificate not trusted", "in the clear"}

// smtpMech is the password AUTH to use of those offered: PLAIN, LOGIN or "".
func smtpMech(auth []string) string {
	for _, m := range []string{"PLAIN", "LOGIN"} {
		if slices.Contains(auth, m) {
			return m
		}
	}
	return ""
}

// smtpTier is how well a port can take a password (smtpTrusted ...),
// or -1 and why it cannot.
func smtpTier(p SMTPPort) (int, string) {
	if p.NoService || p.Banner == "" {
		return -1, ""
	}
	if p.TLS != nil && p.Status != DPTFail && smtpMech(p.Auth) != "" {
		if p.TLS.Trusted {
			return smtpTrusted, ""
		}
		return smtpUntrusted, ""
	}
	// no TLS, or TLS that failed: the AUTH offered before it
	if !p.Implicit && smtpMech(p.authClear) != "" {
		return smtpClear, ""
	}
	all := p.Auth
	if len(all) == 0 {
		all = p.authClear
	}
	if len(all) == 0 {
		return -1, fmt.Sprintf("%d offers no AUTH", p.Port)
	}
	return -1, fmt.Sprintf("%d offers only %s", p.Port, strings.Join(all, " "))
}

// smtpLogin logs in on the port that keeps the password safest: TLS
// with a trusted certificate, else TLS with one not trusted, else in the
// clear when that is all the server works with; among equals 587, 465,
// then 25.
func smtpLogin(ctx context.Context, ip, name string, ports []SMTPPort, o *SMTPOptions, send func(c *smtpConn, port int)) *SMTPLogin {
	l := &SMTPLogin{User: Safe(o.User), Status: DPTFail}
	var use *SMTPPort
	best := -1
	var why []string
	for _, n := range smtpLoginOrder {
		for i := range ports {
			p := &ports[i]
			if p.Port != n {
				continue
			}
			t, reason := smtpTier(*p)
			if t < 0 {
				if reason != "" {
					why = append(why, reason)
				}
				continue
			}
			if best < 0 || t < best {
				use, best = p, t
			}
		}
	}
	if use == nil {
		l.Error = "no port offers AUTH PLAIN or LOGIN: the password was not sent"
		if len(why) > 0 {
			l.Error += " (" + strings.Join(why, ", ") + ")"
		}
		return l
	}
	for _, spec := range o.Ports {
		if spec.Port != use.Port {
			continue
		}
		var p SMTPPort
		o.Live.Set("login", fmt.Sprintf("logging in on %d", spec.Port))
		defer o.Live.Drop("login")
		c := smtpOpen(ctx, ip, name, spec, o, &p, best == smtpClear)
		if c == nil {
			l.Port, l.Error = spec.Port, p.Error
			return l
		}
		defer c.quit()
		// checked again on this connection: it is the one the password
		// goes over, and it must be no worse than the test's
		t, _ := smtpTier(p)
		auth := p.Auth
		if best == smtpClear {
			auth = p.authClear
		}
		if t < 0 || t > best || smtpMech(auth) == "" {
			l.Port, l.Error = spec.Port, "the password was not sent: this connection's TLS or AUTH was worse than the test's"
			return l
		}
		l.Port, l.Mechanism, l.Security = spec.Port, smtpMech(auth), smtpSecurity[best]
		code, msg, err := smtpAuth(c, l.Mechanism, o.User, o.Password)
		if err != nil {
			l.Error = smtpErr(err, o.Timeout)
			return l
		}
		l.Reply = smtpReply(code, msg)
		if code == 235 {
			if send != nil {
				send(c, spec.Port)
			}
			l.Status = DPTOK
			switch best {
			case smtpUntrusted:
				l.Status, l.Note = DPTWarn, "the certificate was not trusted: a machine in the path could have read the password"
			case smtpClear:
				l.Status, l.Note = DPTWarn, "the password went in the clear: anyone on the path could read it"
				if why := smtpWhyClear(ports); why != "" {
					l.Note += " (" + why + ")"
				}
			}
		}
		return l
	}
	l.Error = "no port to log in on"
	return l
}

// smtpWhyClear says why no port gave TLS to log in over.
func smtpWhyClear(ports []SMTPPort) string {
	var w []string
	for _, p := range ports {
		switch {
		case p.NoService:
		case p.Error != "":
			w = append(w, fmt.Sprintf("%d: %s", p.Port, p.Error))
		case p.TLS == nil:
			w = append(w, fmt.Sprintf("%d: no STARTTLS", p.Port))
		}
	}
	return strings.Join(w, "; ")
}

// smtpAuth is AUTH PLAIN or AUTH LOGIN; it gives the last reply.
func smtpAuth(c *smtpConn, mech, user, pass string) (int, string, error) {
	b64 := base64.StdEncoding.EncodeToString
	if mech == "PLAIN" {
		code, msg, err := c.cmd("AUTH PLAIN %s", b64([]byte("\x00"+user+"\x00"+pass)))
		if err == nil && code == 334 { // wants the response on its own line
			return c.cmd("%s", b64([]byte("\x00"+user+"\x00"+pass)))
		}
		return code, msg, err
	}
	code, msg, err := c.cmd("AUTH LOGIN")
	if err != nil || code != 334 {
		return code, msg, err
	}
	if code, msg, err = c.cmd("%s", b64([]byte(user))); err != nil || code != 334 {
		return code, msg, err
	}
	return c.cmd("%s", b64([]byte(pass)))
}
