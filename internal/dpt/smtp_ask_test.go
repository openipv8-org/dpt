// SPDX-License-Identifier: MIT

package dpt

import (
	"errors"
	"strings"
	"testing"
)

// scripted answers the questions in turn; secret answers count too.
func scripted(answers ...string) (ask, secret func(string) (string, error), prompts *[]string) {
	var ps []string
	next := func(p string) (string, error) {
		ps = append(ps, p)
		if len(answers) == 0 {
			return "", errors.New("EOF")
		}
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	return next, next, &ps
}

func TestSMTPAsk(t *testing.T) {
	var said []string
	say := func(l string) { said = append(said, l) }

	// Enter for the server takes the default; the user is an address,
	// so Enter for from takes it
	ask, secret, ps := scripted("", "me@example.com", "pw", "not an address", "you@example.org", "")
	a, err := SMTPAsk("mail.smtp2go.com", ask, secret, say)
	if err != nil || a != (SMTPAsked{"mail.smtp2go.com", "me@example.com", "pw", "me@example.com", "you@example.org"}) {
		t.Fatalf("%+v %v", a, err)
	}
	want := []string{"mail server [mail.smtp2go.com]: ", "log in as (Enter: no login): ", "password for me@example.com: ",
		"send a test message to (Enter: none): ", "send a test message to (Enter: none): ", "from [me@example.com]: "}
	if strings.Join(*ps, "|") != strings.Join(want, "|") {
		t.Errorf("prompts:\n%q", *ps)
	}
	if a.Command() != "smtp mail.smtp2go.com test me@example.com to you@example.org" || strings.Contains(a.Command(), "pw") {
		t.Errorf("command %q", a.Command())
	}

	// no login, no message: just the server
	ask, secret, _ = scripted("smtp.example.com", "", "")
	if a, err := SMTPAsk("", ask, secret, say); err != nil || a != (SMTPAsked{Host: "smtp.example.com"}) {
		t.Errorf("%+v %v", a, err)
	}

	// a user that is no address: from must be given
	ask, secret, ps = scripted("smtp.example.com", "jamie", "pw", "you@example.org", "", "me@example.com")
	a, err = SMTPAsk("", ask, secret, say)
	if err != nil || a.From != "me@example.com" || (*ps)[4] != "from: " || !strings.Contains(a.Command(), " from me@example.com to ") {
		t.Errorf("%+v %v %q", a, err, *ps)
	}

	// Ctrl-D part way: nothing tested
	ask, secret, _ = scripted("smtp.example.com")
	if _, err := SMTPAsk("", ask, secret, say); err != ErrSMTPAskStopped {
		t.Errorf("stopped: %v", err)
	}
}
