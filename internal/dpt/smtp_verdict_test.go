// SPDX-License-Identifier: MIT

package dpt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// a firewall rewriting SMTP (Cisco ASA's inspection): the greeting
// masked, STARTTLS turned into XXXXXXXA
func TestSMTPInspection(t *testing.T) {
	for _, c := range []struct {
		banner string
		ext    []string
		want   string
	}{
		{"220 mail.example.com ESMTP", []string{"PIPELINING", "STARTTLS", "AUTH PLAIN"}, ""},
		{"220 ****************************2*0*0****2***0*0", []string{"PIPELINING"}, "the greeting is masked"},
		{"220 mail.example.com ESMTP", []string{"PIPELINING", "XXXXXXXA", "AUTH PLAIN"}, "extensions are masked (XXXXXXXA)"},
		{"220 ******", []string{"XXXXXXXB"}, "masked with *, extensions"},
	} {
		got := smtpInspection(c.banner, c.ext)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%q %v: %q, want %q", c.banner, c.ext, got, c.want)
		}
	}
}

// why a connection failed, in plain words
func TestSMTPDialWhy(t *testing.T) {
	for _, c := range []struct {
		err     string
		port    int
		want    string
		refused bool
	}{
		{"dial tcp 1.2.3.4:25: connect: connection refused", 25, "refused: nothing listening", true},
		{"dial tcp 1.2.3.4:25: connectex: No connection could be made because the target machine actively refused it.", 25, "refused: nothing listening", true},
		{"dial tcp 1.2.3.4:587: connect: no route to host", 587, "unreachable: a router or firewall", false},
		{"dial tcp 1.2.3.4:587: connect: network is unreachable", 587, "no route from this machine", false},
	} {
		got, refused := smtpDialWhy(errors.New(c.err), c.port, time.Second)
		if !strings.HasPrefix(got, c.want) || refused != c.refused {
			t.Errorf("%s: %q %v", c.err, got, refused)
		}
	}
	got, _ := smtpDialWhy(timeoutErr{}, 25, 10*time.Second)
	if !strings.HasPrefix(got, "timed out: a firewall is dropping it") || !strings.Contains(got, "block outgoing 25") {
		t.Errorf("timeout: %q", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func trustedTLS(names ...string) *SMTPTLS {
	return &SMTPTLS{Version: "TLS 1.3", Subject: names[0], Names: names, Trusted: true}
}

// an ISP answering 25 in the server's place: its greeting names another
// domain than the server's other ports and certificates
func TestSMTPIntercepts(t *testing.T) {
	r := &SMTPReport{Ports: []SMTPPort{
		{Port: 25, Banner: "220 smtp.isp.example.net ESMTP", Status: DPTWarn},
		{Port: 587, Banner: "220 mail.example.com ESMTP", TLS: trustedTLS("mail.example.com"), Status: DPTOK},
	}}
	smtpIntercepts(r, "mail.example.com", nil)
	if r.Ports[0].Intercept == "" || r.Ports[1].Intercept != "" {
		t.Errorf("25 %q, 587 %q", r.Ports[0].Intercept, r.Ports[1].Intercept)
	}
	// a provider's own hosts: no alarm
	r = &SMTPReport{Ports: []SMTPPort{
		{Port: 587, Banner: "220 mail.smtp2go.com ESMTP Exim", TLS: trustedTLS("*.smtp2go.com"), Status: DPTOK},
		{Port: 25, Banner: "220 ab12.outbound.smtp2go.net ESMTP", TLS: trustedTLS("*.smtp2go.com", "*.smtp2go.net"), Status: DPTOK},
	}}
	smtpIntercepts(r, "mail.smtp2go.com", nil)
	for _, p := range r.Ports {
		if p.Intercept != "" {
			t.Errorf("%d: %q", p.Port, p.Intercept)
		}
	}
	if baseDomain("mail.example.co.uk") != "example.co.uk" || baseDomain("a.b.example.com") != "example.com" {
		t.Error("baseDomain")
	}
}

// what mail can and cannot do from here, and the verdict
func TestSMTPVerdict(t *testing.T) {
	r := &SMTPReport{Ports: []SMTPPort{
		{Port: 25, Banner: "220 mail.example.com", StartTLS: true, TLS: trustedTLS("mail.example.com"), Auth: []string{"PLAIN", "LOGIN"}, Status: DPTOK},
		{Port: 465, Implicit: true, Error: "refused: nothing listening", NoService: true, Status: DPTNone},
		{Port: 587, Error: "timed out: a firewall is dropping it (no answer in 10s)", Status: DPTFail},
		{Port: 2525, Banner: "220 mail.example.com", StartTLS: true, TLS: trustedTLS("mail.example.com"), Auth: []string{"PLAIN"}, Status: DPTOK},
	}}
	smtpVerdict(r)
	if len(r.Possible) != 2 || len(r.NotPossible) != 2 || r.Possible[0].Port != 25 || r.NotPossible[1].Port != 587 {
		t.Fatalf("possible %v, not %v", r.Possible, r.NotPossible)
	}
	if r.Verdict != "mail from here works on 25 or 2525 with STARTTLS" {
		t.Errorf("verdict %q", r.Verdict)
	}
	var b strings.Builder
	NewSMTPPrinter(&b, false, false).FromHere(r)
	for _, w := range []string{"FROM HERE possible      25    STARTTLS, trusted; login PLAIN LOGIN",
		"          not possible  465   refused: nothing listening", "VERDICT   mail from here works on 25 or 2525"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("render lacks %q:\n%s", w, b.String())
		}
	}
	// every port dropped
	r = &SMTPReport{Ports: []SMTPPort{{Port: 25, Error: "timed out: x", Status: DPTFail}, {Port: 587, Error: "timed out: y", Status: DPTFail}}}
	smtpVerdict(r)
	if !strings.Contains(r.Verdict, "every port timed out") {
		t.Errorf("verdict %q", r.Verdict)
	}
}
