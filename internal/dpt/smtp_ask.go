// SPDX-License-Identifier: MIT

package dpt

import (
	"errors"
	"fmt"
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
		if a.From != a.User {
			c += " from " + a.From
		}
		c += " to " + a.To
	}
	return c
}

// SMTPAskTitle is the first line of the questions.
const SMTPAskTitle = "Utility mail test"

// smtpPrompt is a question with its colon at column w, in line with the
// others'.
func smtpPrompt(label string, w int) string {
	return fmt.Sprintf("%-*s : ", w, label)
}

// ErrSMTPAskStopped: the questions were left (Ctrl-C, Ctrl-D).
var ErrSMTPAskStopped = errors.New("nothing tested")

// SMTPAsk asks, a line at a time, what smtp is to test: the server, a
// username (none: no login, the server knows this machine by its
// address), the password, who a test message is from (none: no message),
// and who it is to.  host is offered for the server; last holds the
// answers of the time before, offered again: blank takes what is offered,
// "-" takes none.  ask shows a prompt and gives the line; secret reads one
// without echoing it; say writes a line.  A wrong answer is asked again.
func SMTPAsk(host string, last SMTPAsked, ask, secret func(prompt string) (string, error), say func(string)) (SMTPAsked, error) {
	var a SMTPAsked
	say(SMTPAskTitle)
	if last.Host != "" {
		host = last.Host
	}
	offer := func(what, v, none string) string {
		if v == "" {
			return what + " (blank " + none + ")"
		}
		return what + " (blank uses <" + v + ">, - for none)"
	}
	hostQ := "hostname"
	if host != "" {
		hostQ = "hostname (blank uses <" + host + ">)"
	}
	// the colons in one column, past the longest question
	const fromUser = "from (blank uses the username, - for none)"
	w := max(len("username (blank is unauthenticated)"), len(hostQ), len(offer("username", last.User, "")),
		len(offer("from", last.From, "")), len(offer("to", last.To, "")), len(fromUser))
	pr := func(label string) string { return smtpPrompt(label, w) }
	q := func(prompt string) (string, error) {
		l, err := ask(prompt)
		if err != nil {
			return "", ErrSMTPAskStopped
		}
		return strings.TrimSpace(l), nil
	}
	// pick: what was typed; blank, what was offered; "-", none
	pick := func(l, offered string) string {
		switch l {
		case "":
			return offered
		case "-":
			return ""
		}
		return l
	}
	for a.Host == "" {
		l, err := q(pr(hostQ))
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
	l, err := q(pr(offer("username", last.User, "is unauthenticated")))
	if err != nil {
		return a, err
	}
	a.User = pick(l, last.User)
	if a.User == "" {
		say("  unauthenticated: the server must know this machine by its address (smtp2go's IP authentication)")
	}
	for a.User != "" && a.Password == "" {
		label := "password"
		again := a.User == last.User && last.Password != ""
		if again {
			label = "password (blank uses the last one)"
		}
		p, err := secret(pr(label))
		if err != nil {
			return a, ErrSMTPAskStopped
		}
		if p == "" && again {
			p = last.Password
		}
		if p == "" {
			say("  a password is needed to log in (Ctrl-C to stop)")
		}
		a.Password = p
	}
	// the test message: from, then to; none at either sends none
	fromOffer, fromQ := last.From, offer("from", last.From, "sends no test message")
	if fromOffer == "" && MailAddr(a.User) {
		// the username just typed: named, not shown, so the colons stay
		// in their column
		fromOffer, fromQ = a.User, fromUser
	}
	for {
		l, err := q(pr(fromQ))
		if err != nil {
			return a, err
		}
		if l = pick(l, fromOffer); l == "" {
			return a, nil
		}
		if MailAddr(l) {
			a.From = l
			break
		}
		say("  the sender's address, like name@example.com")
	}
	for {
		l, err := q(pr(offer("to", last.To, "sends no test message")))
		if err != nil {
			return a, err
		}
		if l = pick(l, last.To); l == "" {
			a.From = ""
			return a, nil
		}
		if MailAddr(l) {
			a.To = l
			break
		}
		say("  an address like name@example.com")
	}
	return a, nil
}
