// SPDX-License-Identifier: MIT

package dpt

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	ask, secret, ps := scripted("", "me@example.com", "pw", "", "not an address", "you@example.org")
	a, err := SMTPAsk("mail.smtp2go.com", SMTPAsked{}, ask, secret, say)
	if err != nil || a != (SMTPAsked{"mail.smtp2go.com", "me@example.com", "pw", "me@example.com", "you@example.org"}) {
		t.Fatalf("%+v %v", a, err)
	}
	want := []string{
		"hostname (blank uses <mail.smtp2go.com>)   : ",
		"username (blank is unauthenticated)        : ",
		"password                                   : ",
		"from (blank uses the username, - for none) : ",
		"to (blank sends no test message)           : ",
		"to (blank sends no test message)           : ",
	}
	if strings.Join(*ps, "|") != strings.Join(want, "|") {
		t.Errorf("prompts:\n%q", *ps)
	}
	if a.Command() != "smtp mail.smtp2go.com test me@example.com to you@example.org" || strings.Contains(a.Command(), "pw") {
		t.Errorf("command %q", a.Command())
	}

	if said[0] != "Utility mail test" {
		t.Errorf("first line %q", said[0])
	}

	// no username, no password: sent with no login (smtp2go knows this
	// machine by its address)
	said = nil
	ask, secret, ps = scripted("mail.smtp2go.com", "", "me@example.com", "you@example.org")
	a, err = SMTPAsk("", SMTPAsked{}, ask, secret, say)
	if err != nil || a != (SMTPAsked{Host: "mail.smtp2go.com", From: "me@example.com", To: "you@example.org"}) ||
		a.Command() != "smtp mail.smtp2go.com from me@example.com to you@example.org" || !strings.Contains(strings.Join(said, " "), "by its address") {
		t.Errorf("no login: %+v %v %q %q", a, err, *ps, said)
	}
	for _, p := range *ps {
		if strings.HasPrefix(p, "password") {
			t.Errorf("asked for a password with no username: %q", *ps)
		}
	}

	// no login, no message: just the server
	ask, secret, _ = scripted("smtp.example.com", "", "")
	if a, err := SMTPAsk("", SMTPAsked{}, ask, secret, say); err != nil || a != (SMTPAsked{Host: "smtp.example.com"}) {
		t.Errorf("%+v %v", a, err)
	}

	// a user that is no address: from is asked with no default
	ask, secret, ps = scripted("smtp.example.com", "jamie", "pw", "me@example.com", "you@example.org")
	a, err = SMTPAsk("", SMTPAsked{}, ask, secret, say)
	if err != nil || a.From != "me@example.com" || (*ps)[3] != "from (blank sends no test message)         : " ||
		!strings.Contains(a.Command(), " from me@example.com to ") {
		t.Errorf("%+v %v %q", a, err, *ps)
	}

	// again: the last answers offered; blank takes them, the password
	// too; "-" takes none
	last := SMTPAsked{"mail.smtp2go.com", "me@example.com", "pw", "me@example.com", "you@example.org"}
	ask, secret, ps = scripted("", "", "", "", "")
	a, err = SMTPAsk("other.example.com", last, ask, secret, say)
	if err != nil || a != last {
		t.Errorf("again: %+v %v", a, err)
	}
	if !strings.HasPrefix((*ps)[0], "hostname (blank uses <mail.smtp2go.com>)") || !strings.Contains((*ps)[2], "the last one") ||
		!strings.Contains((*ps)[4], "<you@example.org>, - for none") {
		t.Errorf("again prompts: %q", *ps)
	}
	cols := map[int]bool{}
	for _, p := range *ps {
		cols[strings.Index(p, ": ")] = true
	}
	if len(cols) != 1 {
		t.Errorf("colons not in one column: %q", *ps)
	}
	ask, secret, _ = scripted("", "-", "-")
	if a, err := SMTPAsk("", last, ask, secret, say); err != nil || a != (SMTPAsked{Host: "mail.smtp2go.com"}) {
		t.Errorf("none: %+v %v", a, err)
	}

	// Ctrl-D part way: nothing tested
	ask, secret, _ = scripted("smtp.example.com")
	if _, err := SMTPAsk("", SMTPAsked{}, ask, secret, say); err != ErrSMTPAskStopped {
		t.Errorf("stopped: %v", err)
	}
}

// the smtp prompt's answers kept in .dpt, private, the file's other lines
// left as they were
func TestSMTPAskedSaved(t *testing.T) {
	dir := t.TempDir()
	old := SettingsFile
	defer func() { SettingsFile = old }()
	path := filepath.Join(dir, ".dpt")
	SettingsFile = func() string { return path }
	if a := LoadSMTPAsked(); a != (SMTPAsked{}) {
		t.Fatalf("no file: %+v", a)
	}
	os.WriteFile(path, []byte("other=kept\nsmtp.host=old.example.com\n"), 0o644)
	a := SMTPAsked{Host: "mail.example.com", User: "me@example.com", Password: "p=w ord", From: "me@example.com", To: "you@example.org"}
	if err := SaveSMTPAsked(a); err != nil {
		t.Fatal(err)
	}
	if got := LoadSMTPAsked(); got != a {
		t.Errorf("got %+v, want %+v", got, a)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "other=kept\n") || strings.Contains(string(b), "old.example.com") {
		t.Errorf("file:\n%s", b)
	}
	if st, err := os.Stat(path); err != nil || runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", st.Mode(), err)
	}
}
