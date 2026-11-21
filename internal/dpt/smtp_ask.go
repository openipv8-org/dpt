// SPDX-License-Identifier: MIT

package dpt

import (
	"errors"
	"strings"
)

// SMTPAsked is what the smtp questions gave.
type SMTPAsked struct {
	Host, User, Password, From, To string
}

// Command is the same test as one line, without the password.
func (a SMTPAsked) Command() string {
	c := "smtp " + a.Host
	if a.User != "" {
		c += " test " + a.User
	}
	if a.To != "" {
		if a.From != "" && a.From != a.User {
			c += " from " + a.From
		}
		c += " to " + a.To
	}
	return c
}

// ErrSMTPAskStopped: the questions were left (Ctrl-C, Ctrl-D).
var ErrSMTPAskStopped = errors.New("nothing tested")

// SMTPAsk asks, a line at a time, what smtp is to test: the server
// (host: the default shown), a user to log in as (none: no login), the
// password, an address to send a test message to (none: no message), and
// who it is from.  ask shows a prompt and gives the line; secret reads
// one without echoing it; say writes a line.  A wrong answer is asked
// again.
func SMTPAsk(host string, ask, secret func(prompt string) (string, error), say func(string)) (SMTPAsked, error) {
	var a SMTPAsked
	q := func(prompt string) (string, error) {
		l, err := ask(prompt)
		if err != nil {
			return "", ErrSMTPAskStopped
		}
		return strings.TrimSpace(l), nil
	}
	for a.Host == "" {
		p := "mail server: "
		if host != "" {
			p = "mail server [" + host + "]: "
		}
		l, err := q(p)
		if err != nil {
			return a, err
		}
		switch {
		case l != "" && strings.ContainsAny(l, " \t"):
			say("  one name or address, like smtp.example.com")
		case l != "":
			a.Host = l
		case host != "":
			a.Host = host
		default:
			say("  the server's name or address, like smtp.example.com")
		}
	}
	l, err := q("log in as (Enter: no login): ")
	if err != nil {
		return a, err
	}
	a.User = l
	for a.User != "" && a.Password == "" {
		p, err := secret("password for " + Printable(a.User) + ": ")
		if err != nil {
			return a, ErrSMTPAskStopped
		}
		if p == "" {
			say("  a password is needed to log in (Ctrl-C to stop)")
		}
		a.Password = p
	}
	for {
		l, err := q("send a test message to (Enter: none): ")
		if err != nil {
			return a, err
		}
		if l == "" || MailAddr(l) {
			a.To = l
			break
		}
		say("  an address like name@example.com")
	}
	if a.To == "" {
		return a, nil
	}
	if a.User == "" {
		say("  with no login it goes on port 25, as another mail server would deliver it:")
		say("  to an address this server takes mail for")
	}
	for {
		p := "from: "
		if MailAddr(a.User) {
			p = "from [" + a.User + "]: "
		}
		l, err := q(p)
		if err != nil {
			return a, err
		}
		if l == "" && MailAddr(a.User) {
			l = a.User
		}
		if MailAddr(l) {
			a.From = l
			break
		}
		say("  the sender's address, like name@example.com")
	}
	return a, nil
}
