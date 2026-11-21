// SPDX-License-Identifier: MIT

package dpt

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// SMTPPrinter writes an smtp run as it comes:
//
//	TARGET    smtp.example.com  (192.0.2.25)
//
//	PORT 25   smtp, STARTTLS                connected in 21.3 ms
//	          220 mx.example.com ESMTP
//	          TLS 1.3  TLS_AES_128_GCM_SHA256
//	          certificate mx.example.com  issued by R11  until 2027-01-12  trusted
//	          AUTH PLAIN LOGIN
//
//	LOGIN     jamie on 587, AUTH PLAIN   235 2.7.0 Accepted
type SMTPPrinter struct {
	o       dptOut
	verbose bool
}

// NewSMTPPrinter writes to w; verbose adds every EHLO extension.
func NewSMTPPrinter(w io.Writer, color, verbose bool) *SMTPPrinter {
	return &SMTPPrinter{o: newOut(w, color), verbose: verbose}
}

// Target writes the TARGET section, and the name's MX hosts.
func (p *SMTPPrinter) Target(r *SMTPReport) {
	t := r.Target
	s := p.o.bold(Safe(t.Input))
	if len(t.Addresses) > 0 && t.Addresses[0] != t.Input {
		s += "  (" + t.Tested[0] + ")"
	}
	p.o.line("TARGET", s)
	if len(r.MX) > 0 && !slices.Contains(r.MX, strings.TrimSuffix(t.Input, ".")) {
		mx := r.MX[0]
		if len(r.MX) > 1 {
			mx += fmt.Sprintf(" and %d more", len(r.MX)-1)
		}
		p.o.line("", p.o.dim("mail for "+Safe(t.Input)+" goes to "+mx+": dpt smtp "+r.MX[0]+" tests that"))
	}
}

var smtpHow = map[bool]string{true: "TLS from the start", false: "STARTTLS"}

// Port writes one PORT section.
func (p *SMTPPrinter) Port(x *SMTPPort) {
	o := p.o
	head := fmt.Sprintf("%-34s", x.Name+", "+smtpHow[x.Implicit])
	sec := "PORT " + strconv.Itoa(x.Port)
	if x.Connect > 0 {
		head += "connected in " + fms(x.Connect) + " ms"
	}
	if x.Error != "" && x.Banner == "" && x.TLS == nil {
		o.line(sec, head)
		o.line("", o.by(x.Status, x.Error))
		return
	}
	o.line(sec, head)
	if x.Banner != "" {
		o.line("", x.Banner)
	}
	if x.TLS != nil {
		renderTLS(o, x.TLS)
	}
	switch {
	case len(x.Auth) > 0 && x.AuthPlain:
		o.line("", "AUTH "+strings.Join(x.Auth, " ")+"  "+o.yellow("(with no TLS)"))
	case len(x.Auth) > 0:
		o.line("", "AUTH "+strings.Join(x.Auth, " "))
	case x.Banner != "" && x.Error == "":
		o.line("", o.dim("no AUTH offered"))
	}
	if p.verbose {
		for _, e := range x.Extensions {
			o.line("", o.dim("  "+e))
		}
	}
	if x.Error != "" {
		o.line("", o.by(x.Status, x.Error))
	} else if x.Note != "" {
		o.line("", o.by(x.Status, x.Note))
	}
}

// Login writes the LOGIN section.
func (p *SMTPPrinter) Login(l *SMTPLogin) {
	o := p.o
	s := o.bold(l.User)
	if l.Mechanism != "" {
		s += fmt.Sprintf(" on %d, AUTH %s", l.Port, l.Mechanism)
		if l.Security != "" && l.Security != smtpSecurity[smtpTrusted] {
			s += ", " + o.yellow(l.Security)
		}
	}
	if l.Reply != "" {
		s += "   " + o.by(l.Status, l.Reply)
	}
	o.line("LOGIN", s)
	if l.Error != "" {
		o.line("", o.by(l.Status, l.Error))
	}
	if l.Note != "" {
		o.line("", o.by(l.Status, l.Note))
	}
}

// Send writes the SEND section.
//
//	SEND      jamie@example.com -> them@example.org on 587
//	          "test from dpt at 192.168.178.20"   250 2.0.0 OK queued as 4F2A
func (p *SMTPPrinter) Send(m *SMTPSend) {
	o := p.o
	s := o.bold(m.From) + " -> " + o.bold(m.To)
	if m.Port != 0 {
		s += fmt.Sprintf(" on %d", m.Port)
	}
	o.line("SEND", s)
	if m.Subject != "" {
		r := ""
		if m.Reply != "" {
			r = "   " + o.by(m.Status, m.Reply)
		}
		o.line("", fmt.Sprintf("%q", m.Subject)+r)
	}
	if m.Error != "" {
		o.line("", o.by(m.Status, m.Error))
	}
}

// Summary writes the rule and 25/smtp OK   465/submissions NONE ...
func (p *SMTPPrinter) Summary(r *SMTPReport) {
	var names, st []string
	for _, x := range r.Ports {
		names, st = append(names, fmt.Sprintf("%d/%s", x.Port, x.Name)), append(st, x.Status)
	}
	if r.Login != nil {
		names, st = append(names, "LOGIN"), append(st, r.Login.Status)
	}
	if r.Send != nil {
		names, st = append(names, "SEND"), append(st, r.Send.Status)
	}
	p.o.summary([][2][]string{{names, st}})
}

// RenderSMTP writes a whole report.
func RenderSMTP(w io.Writer, r *SMTPReport, color, verbose bool) {
	p := NewSMTPPrinter(w, color, verbose)
	p.Target(r)
	for i := range r.Ports {
		p.Port(&r.Ports[i])
	}
	if r.Login != nil {
		p.Login(r.Login)
	}
	if r.Send != nil {
		p.Send(r.Send)
	}
	p.Summary(r)
}

// renderTLS writes a connection's TLS and its certificate.
func renderTLS(o dptOut, t *SMTPTLS) {
	o.line("", t.Version+"  "+t.Cipher)
	c := "certificate " + t.Subject
	if t.Issuer != "" {
		c += "  issued by " + t.Issuer
	}
	if !t.NotAfter.IsZero() {
		u := "until " + t.NotAfter.Format("2006-01-02")
		if CertExpiring(t.NotAfter) {
			u = o.yellow(fmt.Sprintf("until %s (%d days)", t.NotAfter.Format("2006-01-02"), max(CertDaysLeft(t.NotAfter), 0)))
		}
		c += "  " + u
	}
	if t.Trusted {
		c += "  trusted"
		o.line("", c)
	} else {
		o.line("", c)
		o.line("", o.yellow("not trusted: "+t.VerifyError))
	}
}
