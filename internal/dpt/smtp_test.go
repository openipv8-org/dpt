// SPDX-License-Identifier: MIT

package dpt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// a certificate for 127.0.0.1, and the pool that trusts it
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"mail.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

type fakeSMTP struct {
	implicit, starttls bool
	brokenTLS          bool   // STARTTLS is offered, its handshake fails
	auth               string // the AUTH line's mechanisms
	authSeen           atomic.Bool
}

// serve runs a scripted SMTP server; user "u" password "p" logs in.
func (f *fakeSMTP) serve(t *testing.T, cert tls.Certificate) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.session(c, cfg)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func (f *fakeSMTP) session(c net.Conn, cfg *tls.Config) {
	defer func() { c.Close() }()
	if f.implicit {
		c = tls.Server(c, cfg)
	}
	inTLS := f.implicit
	r := bufio.NewReader(c)
	say := func(s string) { c.Write([]byte(s + "\r\n")) }
	say("220 mail.test ESMTP fake")
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return
		}
		l = strings.TrimRight(l, "\r\n")
		up := strings.ToUpper(l)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			lines := []string{"250-mail.test", "250-SIZE 1000"}
			if f.starttls && !inTLS {
				lines = append(lines, "250-STARTTLS")
			}
			if f.auth != "" {
				lines = append(lines, "250-AUTH "+f.auth)
			}
			lines = append(lines, "250 8BITMIME")
			say(strings.Join(lines, "\r\n"))
		case up == "STARTTLS" && f.brokenTLS:
			say("220 go ahead")
			c.Write([]byte("this is not TLS\r\n"))
			return
		case up == "STARTTLS":
			say("220 go ahead")
			c = tls.Server(c, cfg)
			r = bufio.NewReader(c)
			inTLS = true
		case strings.HasPrefix(up, "AUTH PLAIN "):
			f.authSeen.Store(true)
			b, _ := base64.StdEncoding.DecodeString(l[11:])
			if string(b) == "\x00u\x00p" {
				say("235 2.7.0 Accepted")
			} else {
				say("535 5.7.8 Bad credentials")
			}
		case up == "AUTH LOGIN":
			f.authSeen.Store(true)
			say("334 VXNlcm5hbWU6")
			u, _ := r.ReadString('\n')
			say("334 UGFzc3dvcmQ6")
			p, _ := r.ReadString('\n')
			ub, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
			pb, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
			if string(ub) == "u" && string(pb) == "p" {
				say("235 2.7.0 Accepted")
			} else {
				say("535 5.7.8 Bad credentials")
			}
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("502 no")
		}
	}
}

// a port nothing listens on
func closedPort(t *testing.T) int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestSMTP(t *testing.T) {
	cert, pool := testCert(t)
	s25 := &fakeSMTP{starttls: true}
	s465 := &fakeSMTP{implicit: true, auth: "PLAIN LOGIN"}
	s587 := &fakeSMTP{starttls: true, auth: "LOGIN PLAIN XOAUTH2"}
	ports := []SMTPPortSpec{
		{s25.serve(t, cert), false, "smtp"},
		{s465.serve(t, cert), true, "submissions"},
		{s587.serve(t, cert), false, "submission"},
		{closedPort(t), false, "closed"},
	}
	smtpLoginOrder = []int{ports[2].Port, ports[1].Port, ports[0].Port}
	defer func() { smtpLoginOrder = []int{587, 465, 25} }()
	run := func(user, pass string, roots *x509.CertPool) *SMTPReport {
		r, err := RunSMTP(context.Background(), "127.0.0.1", SMTPOptions{Ports: ports, Roots: roots, User: user, Password: pass, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	r := run("u", "p", pool)
	p := r.Ports
	if p[0].Status != DPTOK || !p[0].StartTLS || p[0].TLS == nil || !p[0].TLS.Trusted || p[0].Banner != "220 mail.test ESMTP fake" || len(p[0].Auth) != 0 {
		t.Errorf("25: %+v", p[0])
	}
	if p[1].Status != DPTOK || !p[1].Implicit || p[1].TLS == nil || strings.Join(p[1].Auth, " ") != "PLAIN LOGIN" {
		t.Errorf("465: %+v", p[1])
	}
	if p[2].Status != DPTOK || p[2].TLS.Subject != "mail.test" {
		t.Errorf("587: %+v", p[2])
	}
	if p[3].Status != DPTNone || !p[3].NoService {
		t.Errorf("closed: %+v", p[3])
	}
	if l := r.Login; l == nil || l.Status != DPTOK || l.Port != ports[2].Port || l.Mechanism != "PLAIN" || l.Reply != "235 2.7.0 Accepted" {
		t.Errorf("login: %+v", r.Login)
	}
	if r.Failed() {
		t.Error("failed")
	}
	var b bytes.Buffer
	RenderSMTP(&b, r, false, false)
	for _, w := range []string{"PORT ", "submissions, TLS from the start", "STARTTLS", "certificate mail.test", "trusted", "AUTH PLAIN LOGIN", "LOGIN     u on", "235 2.7.0 Accepted", "refused: nothing listens", "LOGIN OK"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("render lacks %q:\n%s", w, b.String())
		}
	}
	if strings.Contains(b.String(), "\"p\"") || bytes.Contains(b.Bytes(), []byte(" p ")) {
		t.Errorf("the password is shown:\n%s", b.String())
	}

	// a wrong password: the server's answer, FAIL
	r = run("u", "wrong", pool)
	if l := r.Login; l.Status != DPTFail || !strings.HasPrefix(l.Reply, "535") || !r.Failed() {
		t.Errorf("wrong password: %+v", l)
	}

	// no certificate trusted: it logs in over that TLS, and says so: WARN
	r = run("u", "p", x509.NewCertPool())
	if r.Ports[1].Status != DPTWarn || r.Ports[1].TLS.Trusted || r.Ports[1].TLS.VerifyError == "" {
		t.Errorf("untrusted: %+v", r.Ports[1])
	}
	if l := r.Login; l.Status != DPTWarn || l.Reply != "235 2.7.0 Accepted" || l.Security != "TLS with a certificate not trusted" || !strings.Contains(l.Note, "not trusted") {
		t.Errorf("untrusted login: %+v", l)
	}
	b.Reset()
	RenderSMTP(&b, r, false, false)
	if !strings.Contains(b.String(), "AUTH PLAIN, TLS with a certificate not trusted") || !strings.Contains(b.String(), "LOGIN WARN") {
		t.Errorf("untrusted render:\n%s", b.String())
	}
}

func TestSMTPLoginAndPlain(t *testing.T) {
	cert, pool := testCert(t)
	login := &fakeSMTP{starttls: true, auth: "LOGIN"}
	plain := &fakeSMTP{auth: "PLAIN LOGIN"} // no STARTTLS
	ports := []SMTPPortSpec{{plain.serve(t, cert), false, "smtp"}, {login.serve(t, cert), false, "submission"}}
	smtpLoginOrder = []int{ports[1].Port, ports[0].Port}
	defer func() { smtpLoginOrder = []int{587, 465, 25} }()
	r, err := RunSMTP(context.Background(), "127.0.0.1", SMTPOptions{Ports: ports, Roots: pool, User: "u", Password: "p", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Ports[0]; p.Status != DPTWarn || p.StartTLS || !p.AuthPlain || !strings.Contains(p.Note, "no STARTTLS") {
		t.Errorf("no STARTTLS: %+v", p)
	}
	if l := r.Login; l.Status != DPTOK || l.Mechanism != "LOGIN" {
		t.Errorf("AUTH LOGIN: %+v", l)
	}
	if plain.authSeen.Load() {
		t.Error("the password went in the clear with TLS on another port")
	}
	// only the plain port: that is all the server works with, so the
	// password goes in the clear, WARN
	r, _ = RunSMTP(context.Background(), "127.0.0.1", SMTPOptions{Ports: ports[:1], Roots: pool, User: "u", Password: "p", Timeout: 2 * time.Second})
	if l := r.Login; l.Status != DPTWarn || l.Security != "in the clear" || !strings.Contains(l.Note, "in the clear") || !plain.authSeen.Load() {
		t.Errorf("plain only: %+v", l)
	}
	// a wrong password in the clear is still FAIL
	r, _ = RunSMTP(context.Background(), "127.0.0.1", SMTPOptions{Ports: ports[:1], Roots: pool, User: "u", Password: "x", Timeout: 2 * time.Second})
	if l := r.Login; l.Status != DPTFail {
		t.Errorf("plain, wrong password: %+v", l)
	}
	// STARTTLS offered but broken: the port FAILs, the login goes in the
	// clear on it
	broken := &fakeSMTP{starttls: true, brokenTLS: true, auth: "LOGIN"}
	bp := []SMTPPortSpec{{broken.serve(t, cert), false, "submission"}}
	smtpLoginOrder = []int{bp[0].Port}
	r, _ = RunSMTP(context.Background(), "127.0.0.1", SMTPOptions{Ports: bp, Roots: pool, User: "u", Password: "p", Timeout: 2 * time.Second})
	if r.Ports[0].Status != DPTFail || !strings.Contains(r.Ports[0].Error, "STARTTLS handshake") {
		t.Errorf("broken TLS: %+v", r.Ports[0])
	}
	if l := r.Login; l.Status != DPTWarn || l.Security != "in the clear" || l.Mechanism != "LOGIN" || !strings.Contains(l.Note, "STARTTLS handshake") {
		t.Errorf("broken TLS login: %+v", l)
	}
	// no password AUTH anywhere: nothing sent
	none := &fakeSMTP{starttls: true, auth: "XOAUTH2"}
	np := []SMTPPortSpec{{none.serve(t, cert), false, "submission"}}
	smtpLoginOrder = []int{np[0].Port}
	r, _ = RunSMTP(context.Background(), "127.0.0.1", SMTPOptions{Ports: np, Roots: pool, User: "u", Password: "p", Timeout: 2 * time.Second})
	if l := r.Login; l.Status != DPTFail || !strings.Contains(l.Error, "offers only XOAUTH2") || none.authSeen.Load() {
		t.Errorf("XOAUTH2 only: %+v", l)
	}
}
