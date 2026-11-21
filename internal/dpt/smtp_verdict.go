// SPDX-License-Identifier: MIT

package dpt

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

// What the smtp test makes of its ports: whether something other than the
// server answers, and what mail can and cannot do from here.

// baseDomain is the domain a name belongs to: example.com of
// mx1.example.com, example.co.uk of mail.example.co.uk.
func baseDomain(name string) string {
	l := strings.Split(strings.ToLower(strings.Trim(name, ".")), ".")
	if len(l) < 2 {
		return ""
	}
	n := 2
	// a country's second level: co.uk, com.au, org.nz, ...
	if len(l) >= 3 && len(l[len(l)-1]) == 2 &&
		slices.Contains([]string{"co", "com", "net", "org", "gov", "ac", "edu", "govt", "ne", "or", "geek", "school"}, l[len(l)-2]) {
		n = 3
	}
	return strings.Join(l[len(l)-n:], ".")
}

// greetingName is the host name a greeting gives (220 mx.example.com
// ESMTP): "" when it gives none.
func greetingName(banner string) string {
	f := strings.Fields(banner)
	if len(f) < 2 {
		return ""
	}
	n := strings.TrimSuffix(f[1], ".")
	if !strings.Contains(n, ".") || strings.ContainsAny(n, "*[]()") || net.ParseIP(n) != nil {
		return ""
	}
	return n
}

// smtpIntercepts marks the ports where something other than the server
// seems to answer: the greeting names another domain than the server, its
// certificates and its MX hosts do, or the certificate is for another
// name than the one other ports prove.
func smtpIntercepts(r *SMTPReport, name string, mx []string) {
	known := map[string]bool{}
	add := func(n string) {
		if d := baseDomain(strings.TrimPrefix(n, "*.")); d != "" {
			known[d] = true
		}
	}
	isName := net.ParseIP(name) == nil
	if isName {
		add(name)
	}
	for _, m := range mx {
		add(m)
	}
	trusted := false
	for _, p := range r.Ports {
		if p.TLS != nil && p.TLS.Trusted && p.Inspected == "" {
			trusted = true
			add(p.TLS.Subject)
			for _, n := range p.TLS.Names {
				add(n)
			}
		}
	}
	// the greetings' domains: where one port's differs from the others'
	count := map[string]int{}
	for _, p := range r.Ports {
		if d := baseDomain(greetingName(p.Banner)); d != "" {
			count[d]++
		}
	}
	for i := range r.Ports {
		p := &r.Ports[i]
		if p.Banner == "" {
			continue
		}
		var why string
		g := greetingName(p.Banner)
		d := baseDomain(g)
		switch {
		case p.TLS != nil && !p.TLS.Trusted && trusted && isName && strings.Contains(p.TLS.VerifyError, "valid for"):
			why = "its certificate is for " + p.TLS.Subject + ", not " + Safe(name) + ", while other ports' are"
		case d != "" && len(known) > 0 && !known[d] && (len(count) > 1 || isName):
			why = "the greeting names " + g + ", not " + Safe(name)
			if len(count) > 1 {
				why += " as the other ports' do"
			}
		}
		if why == "" {
			continue
		}
		p.Intercept = why + ": something in the path (an ISP or firewall) may be answering in its place"
		if p.Status == DPTOK {
			p.Status = DPTWarn
		}
	}
}

// smtpPortWorks: the port took a session (a greeting and EHLO).
func smtpPortWorks(p SMTPPort) bool {
	return p.Banner != "" && p.Status != DPTFail
}

// smtpHowSafe is how a working port carries mail: TLS from the start,
// STARTTLS, or in the clear; and whether the certificate is trusted.
func smtpHowSafe(p SMTPPort) string {
	switch {
	case p.TLS == nil:
		return "in the clear (no TLS)"
	case !p.TLS.Trusted:
		return smtpHow[p.Implicit] + ", certificate not trusted"
	}
	return smtpHow[p.Implicit] + ", trusted"
}

// smtpVerdict fills in what mail can and cannot do from here.
func smtpVerdict(r *SMTPReport) {
	r.Possible, r.NotPossible = nil, nil
	for _, p := range r.Ports {
		if !smtpPortWorks(p) {
			why := p.Error
			if why == "" {
				why = "no session"
			}
			r.NotPossible = append(r.NotPossible, SMTPCan{p.Port, why})
			continue
		}
		w := smtpHowSafe(p)
		switch t, _ := smtpTier(p); {
		case t == smtpClear:
			w += "; login " + strings.Join(p.authClear, " ") + " (in the clear)"
		case t >= 0:
			w += "; login " + strings.Join(p.Auth, " ")
		default:
			w += "; no login offered"
		}
		if r.Login != nil && r.Login.Port == p.Port {
			if r.Login.Status == DPTFail {
				w += "; the login failed"
			} else {
				w += "; the login worked"
			}
		}
		if r.Send != nil && r.Send.Port == p.Port {
			if r.Send.Status == DPTOK {
				w += "; the test message was taken"
			} else {
				w += "; the test message was refused"
			}
		}
		if p.Inspected != "" {
			w += "; a firewall is inspecting it"
		}
		if p.Intercept != "" {
			w += "; something else may be answering"
		}
		r.Possible = append(r.Possible, SMTPCan{p.Port, w})
	}
	r.Verdict = smtpVerdictLine(r)
}

// smtpVerdictLine is the verdict in one line.
func smtpVerdictLine(r *SMTPReport) string {
	if len(r.Possible) == 0 {
		timedOut, refused := 0, 0
		for _, p := range r.Ports {
			switch {
			case strings.HasPrefix(p.Error, "timed out"):
				timedOut++
			case p.NoService:
				refused++
			}
		}
		switch {
		case timedOut == len(r.Ports):
			return "no mail from here: every port timed out; a firewall between here and the server is dropping them"
		case refused == len(r.Ports):
			return "no mail from here: nothing listens on any mail port; is this the mail server?"
		}
		return "no mail from here: no port gave a mail session"
	}
	// the safest ports that work
	best := 99
	var ports []SMTPPort
	for _, p := range r.Ports {
		if !smtpPortWorks(p) || p.Intercept != "" {
			continue
		}
		t := smtpClear
		if p.TLS != nil {
			t = smtpUntrusted
			if p.TLS.Trusted && p.Inspected == "" {
				t = smtpTrusted
			}
		}
		if t < best {
			best, ports = t, nil
		}
		if t == best {
			ports = append(ports, p)
		}
	}
	var v string
	if len(ports) == 0 {
		v = "mail from here only reaches something that may not be the server"
	} else {
		var nums []string
		implicit, starttls := false, false
		for _, p := range ports {
			nums = append(nums, fmt.Sprint(p.Port))
			if p.Implicit {
				implicit = true
			} else {
				starttls = true
			}
		}
		list := nums[0]
		if n := len(nums); n > 1 {
			list = strings.Join(nums[:n-1], ", ") + " or " + nums[n-1]
		}
		switch {
		case best == smtpClear:
			v = "mail from here works only in the clear, on " + list
		case implicit && starttls:
			v = "mail from here works on " + list + " over TLS"
		case implicit:
			v = "mail from here works on " + list + " with TLS from the start"
		default:
			v = "mail from here works on " + list + " with STARTTLS"
		}
		if best == smtpUntrusted {
			v += " (certificate not trusted)"
		}
	}
	if l := r.Login; l != nil {
		if l.Status == DPTFail {
			v += "; the login failed"
		} else {
			v += fmt.Sprintf("; logging in works on %d", l.Port)
		}
	}
	if m := r.Send; m != nil {
		if m.Status == DPTOK {
			v += "; the test message was taken"
		} else {
			v += "; the test message was not sent"
		}
	}
	for _, p := range r.Ports {
		if p.Inspected != "" {
			v += fmt.Sprintf("; a firewall is inspecting SMTP on %d", p.Port)
			break
		}
	}
	return v
}
