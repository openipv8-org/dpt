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
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// listen serves each connection with serve, on 127.0.0.1.
func listen(t *testing.T, serve func(c net.Conn)) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); serve(c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestConnectBanner(t *testing.T) {
	ssh := listen(t, func(c net.Conn) { io.WriteString(c, "SSH-2.0-OpenSSH_9.6\r\n"); time.Sleep(time.Second) })
	r, conn, err := RunConnect(context.Background(), "127.0.0.1", ConnectOptions{Port: ssh, Wait: 500 * time.Millisecond})
	if err != nil || conn == nil {
		t.Fatal(err)
	}
	conn.Close()
	if r.Banner != "SSH-2.0-OpenSSH_9.6" || r.Kind != "SSH" || r.Status != DPTOK || r.TLS != nil {
		t.Errorf("%+v", r)
	}
	var b bytes.Buffer
	RenderConnect(&b, r, false)
	if !strings.Contains(b.String(), "SAYS      SSH-2.0-OpenSSH_9.6") || !strings.Contains(b.String(), "connected in") {
		t.Errorf("%s", b.String())
	}

	// nothing listens: NONE
	r, conn, _ = RunConnect(context.Background(), "127.0.0.1", ConnectOptions{Port: closedPort(t)})
	if conn != nil || r.Status != DPTNone || !strings.Contains(r.Error, "nothing listens") {
		t.Errorf("closed: %+v", r)
	}

	// a server that waits: no banner, says so
	quiet := listen(t, func(c net.Conn) { time.Sleep(time.Second) })
	r, conn, _ = RunConnect(context.Background(), "127.0.0.1", ConnectOptions{Port: quiet, Wait: 300 * time.Millisecond})
	conn.Close()
	if r.Banner != "" || !strings.Contains(r.Note, "waits for the client") {
		t.Errorf("quiet: %+v", r)
	}
}

func TestConnectTLSAndTalk(t *testing.T) {
	// a TLS echo server whose certificate expires in 10 days
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "soon.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(10*24*time.Hour + time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	port := listen(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		io.WriteString(tc, "* OK IMAP ready\r\n")
		s := bufio.NewScanner(tc)
		for s.Scan() {
			io.WriteString(tc, "echo "+s.Text()+"\r\n")
			if s.Text() == "bye" {
				return
			}
		}
	})
	r, conn, err := RunConnect(context.Background(), "127.0.0.1", ConnectOptions{Port: port, TLS: true, Roots: pool, Wait: 500 * time.Millisecond})
	if err != nil || conn == nil {
		t.Fatalf("%v %+v", err, r)
	}
	if r.TLS == nil || !r.TLS.Trusted || r.Kind != "IMAP" || r.Status != DPTWarn || !strings.Contains(r.Note, "expires in 10 days") {
		t.Errorf("%+v %+v", r, r.TLS)
	}
	lines := []string{"hello", "bye"}
	var out bytes.Buffer
	why := conn.Talk(func() (string, error) {
		if len(lines) == 0 {
			time.Sleep(2 * time.Second) // the server closes first
			return "", io.EOF
		}
		l := lines[0]
		lines = lines[1:]
		return l, nil
	}, &out, 0)
	if !strings.Contains(out.String(), "echo hello\necho bye\n") || !strings.Contains(why, "server closed") {
		t.Errorf("talk: %q %q", out.String(), why)
	}
}

func TestConnectTelnet(t *testing.T) {
	got := make(chan []byte, 1)
	port := listen(t, func(c net.Conn) {
		// DO echo, WILL suppress-go-ahead, a subnegotiation, then a login prompt
		c.Write([]byte{telIAC, telDO, 1, telIAC, telWILL, 3, telIAC, telSB, 24, 1, telIAC, telSE})
		io.WriteString(c, "router login: ")
		c.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 16)
		n, _ := c.Read(b)
		got <- b[:n]
	})
	r, conn, _ := RunConnect(context.Background(), "127.0.0.1", ConnectOptions{Port: port, Wait: 500 * time.Millisecond})
	conn.Close()
	if r.Banner != "router login:" || !r.Telnet || r.Kind != "telnet" || r.Status != DPTWarn {
		t.Errorf("%+v", r)
	}
	// each option refused: WONT echo, DONT suppress-go-ahead
	if b := <-got; !bytes.Equal(b, []byte{telIAC, telWONT, 1, telIAC, telDONT, 3}) {
		t.Errorf("replies % x", b)
	}
}

func TestSafeLines(t *testing.T) {
	if s := SafeLines("220 hi\r\n\x1b[31mred\x07\r\nok"); s != "220 hi\n[31mred\nok" {
		t.Errorf("%q", s)
	}
}
