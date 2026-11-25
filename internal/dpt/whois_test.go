// SPDX-License-Identifier: MIT

package dpt

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseWhoisQuery(t *testing.T) {
	for _, c := range []struct{ in, kind, asked string }{
		{"1.1.1.1", "address", "1.1.1.1"},
		{"2001:4860::8888", "address", "2001:4860::8888"},
		{"8.8.8.0/24", "network", "8.8.8.0/24"},
		{"8.8.8.9/24", "network", "8.8.8.0/24"},
		{"AS13335", "asn", "AS13335"},
		{"as13335", "asn", "AS13335"},
		{"13335", "asn", "AS13335"},
		{"Example.COM.", "domain", "example.com"},
		{"www.bbc.co.uk", "domain", "www.bbc.co.uk"},
	} {
		q, err := ParseWhoisQuery(c.in)
		if err != nil || q.kind != c.kind || q.asked() != c.asked {
			t.Errorf("%q: %+v %v, want %s %s", c.in, q, err, c.kind, c.asked)
		}
	}
	for _, bad := range []string{"", "localhost", "bad name!", "AS", "-1", "münchen.de"} {
		if _, err := ParseWhoisQuery(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	if _, err := ParseWhoisQuery("münchen.de"); err == nil || !strings.Contains(err.Error(), "xn--") {
		t.Errorf("an IDN: %v, want the xn-- hint", err)
	}
}

func TestCheckWhoisServer(t *testing.T) {
	for _, ok := range []string{"whois.godaddy.com", "whois.example.net:4343", "192.0.2.1", "https://rdap.arin.net/registry/"} {
		if err := CheckWhoisServer(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"bad server!", "host:99999", "https://"} {
		if err := CheckWhoisServer(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestBootMatch(t *testing.T) {
	q, _ := ParseWhoisQuery("1.1.1.1")
	if n, ok := bootMatch(q, "1.0.0.0/8"); !ok || n != 8 {
		t.Errorf("1.0.0.0/8: %d %v", n, ok)
	}
	if _, ok := bootMatch(q, "2.0.0.0/8"); ok {
		t.Error("2.0.0.0/8 matched 1.1.1.1")
	}
	n, _ := ParseWhoisQuery("1.0.0.0/7") // wider than the entry: not in it
	if _, ok := bootMatch(n, "1.0.0.0/8"); ok {
		t.Error("1.0.0.0/7 matched 1.0.0.0/8")
	}
	a, _ := ParseWhoisQuery("AS13335")
	if _, ok := bootMatch(a, "13312-18431"); !ok {
		t.Error("AS13335 not in 13312-18431")
	}
	if _, ok := bootMatch(a, "13335"); !ok {
		t.Error("AS13335 not 13335")
	}
	d, _ := ParseWhoisQuery("www.example.co.uk")
	if n, ok := bootMatch(d, "uk"); !ok || n != 1 {
		t.Errorf("uk: %d %v", n, ok)
	}
	if _, ok := bootMatch(d, "k"); ok {
		t.Error("k matched .uk")
	}
}

func TestWhoisSpecial(t *testing.T) {
	r, err := RunWhois(context.Background(), "192.168.1.1", WhoisOptions{})
	if err != nil || !strings.Contains(r.Special, "RFC 1918") || r.Found {
		t.Fatalf("%+v %v", r, err)
	}
	var b bytes.Buffer
	RenderWhois(&b, r, false, false, "--verbose")
	if !strings.Contains(b.String(), "no registry holds it") {
		t.Error(b.String())
	}
}

// fakeRDAP is IANA's bootstrap and a registry, in one server.
func fakeRDAP(t *testing.T) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := srv.URL + "/reg/"
		switch r.URL.Path {
		case "/boot/ipv4.json":
			fmt.Fprintf(w, `{"services":[[["198.0.0.0/8"],["%s"]],[["198.51.0.0/16"],["%s"]]]}`, srv.URL+"/wrong/", base)
		case "/boot/dns.json":
			fmt.Fprintf(w, `{"services":[[["test"],["%s"]]]}`, base)
		case "/boot/asn.json":
			fmt.Fprintf(w, `{"services":[[["64496-64511"],["%s"]]]}`, base)
		case "/boot/ipv6.json":
			fmt.Fprint(w, `{"services":[]}`)
		case "/reg/ip/198.51.200.7":
			w.Header().Set("Content-Type", "application/rdap+json")
			fmt.Fprint(w, `{"objectClassName":"ip network","handle":"NET-1","name":"EXAMPLE-NET",
				"startAddress":"198.51.200.0","endAddress":"198.51.200.255","country":"NZ",
				"cidr0_cidrs":[{"v4prefix":"198.51.200.0","length":24}],
				"events":[{"eventAction":"last changed","eventDate":"2024-03-01T00:00:00Z"},
				          {"eventAction":"registration","eventDate":"2011-08-10T23:12:35Z"},
				          {"eventAction":"last update of RDAP database","eventDate":"2026-01-01T00:00:00Z"}],
				"remarks":[{"description":["An example \u001b[31mnetwork"]}],
				"entities":[{"roles":["registrant"],"handle":"ORG-1","vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Org"]]],
				  "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","abuse@example.test"],["tel",{"type":"fax"},"text","+1 555"]]]}]}]}`)
		case "/reg/domain/www.dpt.test":
			http.Error(w, "bad request", 400) // as Public Interest Registry answers for www.
		case "/reg/domain/dpt.test":
			fmt.Fprintf(w, `{"objectClassName":"domain","ldhName":"DPT.TEST","status":["active"],
				"nameservers":[{"ldhName":"NS1.DPT.TEST."}],"secureDNS":{"delegationSigned":true},
				"entities":[{"roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"9"}],
				  "vcardArray":["vcard",[["fn",{},"text","Registrar Ltd"]]]}],
				"links":[{"rel":"related","type":"application/rdap+json","href":"%s/registrar/domain/dpt.test"}]}`, srv.URL)
		case "/registrar/domain/dpt.test":
			fmt.Fprint(w, `{"objectClassName":"domain","entities":[{"roles":["registrant"],
				"vcardArray":["vcard",[["fn",{},"text","REDACTED FOR PRIVACY"]]]}]}`)
		case "/reg/autnum/64500":
			fmt.Fprint(w, `{"objectClassName":"autnum","startAutnum":64500,"endAutnum":64500,"name":"DPT-AS"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fakeWhois answers whois questions with answer(question), on a port of
// its own; it gives host:port.
func fakeWhois(t *testing.T, answer func(q string) string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				l, _ := bufio.NewReader(c).ReadString('\n')
				fmt.Fprint(c, answer(strings.TrimRight(l, "\r\n")))
			}()
		}
	}()
	return ln.Addr().String()
}

func withFakes(t *testing.T, boot, iana string) {
	oldB, oldI := RDAPBootstrapURL, WhoisIANA
	RDAPBootstrapURL, WhoisIANA = boot, iana
	t.Cleanup(func() { RDAPBootstrapURL, WhoisIANA = oldB, oldI })
}

func TestRunWhoisRDAP(t *testing.T) {
	srv := fakeRDAP(t)
	withFakes(t, srv.URL+"/boot/", "127.0.0.1:1")
	ctx := context.Background()

	r, err := RunWhois(ctx, "198.51.200.7", WhoisOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "RDAP" || !r.Found || r.Holder != "Example Org" || r.Range != "198.51.200.0 - 198.51.200.255" ||
		len(r.CIDRs) != 1 || r.CIDRs[0] != "198.51.200.0/24" || r.Country != "NZ" {
		t.Errorf("%+v", r)
	}
	if len(r.Abuse) != 1 || r.Abuse[0] != "abuse@example.test" {
		t.Errorf("abuse %v (a fax is no abuse contact)", r.Abuse)
	}
	if len(r.Events) != 2 || r.Events[0] != (WhoisEvent{"registered", "2011-08-10"}) || r.Events[1].Action != "changed" {
		t.Errorf("events %v", r.Events)
	}
	if len(r.Remarks) != 1 || strings.Contains(r.Remarks[0], "\x1b") {
		t.Errorf("remarks %q: escapes from the network must go", r.Remarks)
	}
	var b bytes.Buffer
	RenderWhois(&b, r, false, false, "--verbose")
	for _, want := range []string{"SOURCE    RDAP", "HOLDER    Example Org", "NETWORK   EXAMPLE-NET  198.51.200.0 - 198.51.200.255  198.51.200.0/24  NZ",
		"ABUSE     abuse@example.test", "registered 2011-08-10   changed 2024-03-01", "(--verbose: every contact and remark)"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("no %q in\n%s", want, b.String())
		}
	}

	// a domain: www. is not held, the shorter name is; then the registrar
	d, err := RunWhois(ctx, "www.dpt.test", WhoisOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if d.Asked != "dpt.test" || d.Name != "dpt.test" || d.Registrar != "Registrar Ltd (IANA 9)" || d.DNSSEC != "signed (DNSSEC)" ||
		len(d.NameServers) != 1 || d.NameServers[0] != "ns1.dpt.test" || d.Related == "" || d.RelatedWhy != "" ||
		d.Holder != "redacted by the registrar (privacy)" {
		t.Errorf("%+v", d)
	}

	// not registered: an answer, not a reason to ask whois
	n, err := RunWhois(ctx, "free.test", WhoisOptions{Timeout: 5 * time.Second})
	if err != nil || n.Found || n.Source != "RDAP" {
		t.Fatalf("%+v %v", n, err)
	}
	b.Reset()
	RenderWhois(&b, n, false, false, "")
	if !strings.Contains(b.String(), "free.test is not registered") {
		t.Error(b.String())
	}

	a, err := RunWhois(ctx, "AS64500", WhoisOptions{Timeout: 5 * time.Second})
	if err != nil || a.ASNs != "AS64500" || a.Name != "DPT-AS" {
		t.Errorf("%+v %v", a, err)
	}
}

func TestRunWhoisFallback(t *testing.T) {
	srv := fakeRDAP(t)
	var asked []string
	reg := fakeWhois(t, func(q string) string {
		asked = append(asked, "reg:"+q)
		return "% a comment: OrgName: not this\r\nOrgName:   Fallback Org\r\nNetRange:  2001:db8:1:: - 2001:db8:1:ffff::\r\n" +
			"OrgAbuseEmail: abuse@fallback.test\r\nRegDate: 2001-02-03\r\nUpdated: 2020-01-02T10:00:00Z\r\n"
	})
	iana := fakeWhois(t, func(q string) string {
		asked = append(asked, "iana:"+q)
		return "refer:        " + reg + "\n"
	})
	withFakes(t, srv.URL+"/boot/", iana)

	// IPv6: the fake bootstrap lists no server, so whois
	r, err := RunWhois(context.Background(), "2600::1", WhoisOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "whois" || !strings.Contains(r.NoRDAP, "no RDAP server") || r.Holder != "Fallback Org" ||
		r.Range != "2001:db8:1:: - 2001:db8:1:ffff::" || len(r.Abuse) != 1 || !r.Found {
		t.Errorf("%+v", r)
	}
	if len(r.Events) != 2 || r.Events[0] != (WhoisEvent{"registered", "2001-02-03"}) || r.Events[1] != (WhoisEvent{"changed", "2020-01-02"}) {
		t.Errorf("events %v", r.Events)
	}
	if len(asked) != 2 || asked[0] != "iana:2600::1" || asked[1] != "reg:2600::1" || len(r.Asks) != 2 {
		t.Errorf("asked %v, asks %v", asked, r.Asks)
	}
	var b bytes.Buffer
	RenderWhois(&b, r, false, true, "")
	for _, want := range []string{"SOURCE    whois", "not in RDAP: no RDAP server", "read from the text", "TEXT      % a comment"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("no %q in\n%s", want, b.String())
		}
	}

	// a server given: that one only, not IANA
	asked = nil
	c, err := RunWhois(context.Background(), "dpt.test", WhoisOptions{Timeout: 5 * time.Second, Server: reg})
	if err != nil || !c.Chosen || c.Source != "whois" || len(asked) != 1 || asked[0] != "reg:dpt.test" {
		t.Errorf("%+v %v, asked %v", c, err, asked)
	}
}

func TestWhoisReferral(t *testing.T) {
	for in, want := range map[string]string{
		"refer:        whois.arin.net\n":                "whois.arin.net:43",
		"ReferralServer:  whois://whois.ripe.net\n":     "whois.ripe.net:43",
		"ReferralServer:  rwhois://rwhois.x.net:4321":   "",
		"Registrar WHOIS Server: whois.markmonitor.com": "whois.markmonitor.com:43",
		"nothing here": "",
	} {
		if got := whoisReferral(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestRegisteredGuess(t *testing.T) {
	for in, want := range map[string]string{"www.example.com": "example.com", "example.com": "example.com",
		"www.bbc.co.uk": "bbc.co.uk", "a.b.example.de": "example.de"} {
		if got := registeredGuess(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestLDAPBindResponse(t *testing.T) {
	ok := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	long := []byte{0x30, 0x84, 0, 0, 0, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	if !isLDAPBindResponse(ok) || !isLDAPBindResponse(long) {
		t.Error("a BindResponse not seen")
	}
	if isLDAPBindResponse([]byte("HTTP/1.1 400 Bad Request\r\n")) || isLDAPBindResponse(nil) {
		t.Error("not LDAP, seen as LDAP")
	}
}
