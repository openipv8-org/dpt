// SPDX-License-Identifier: MIT

package dpt

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The .dpt file keeps what dpt remembers between runs: for now the last
// smtp prompt's answers, so the next one offers them.  It is key=value
// lines, readable by its owner only (it holds the mail password).

// SettingsFile is the .dpt file: ~/.dpt, on Windows %APPDATA%\dpt\.dpt;
// "" when there is no home folder.
var SettingsFile = func() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "dpt", ".dpt")
		}
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".dpt")
}

// the smtp prompt's answers, as they are kept
var smtpKeys = []struct {
	key string
	val func(a *SMTPAsked) *string
}{
	{"smtp.host", func(a *SMTPAsked) *string { return &a.Host }},
	{"smtp.user", func(a *SMTPAsked) *string { return &a.User }},
	{"smtp.password", func(a *SMTPAsked) *string { return &a.Password }},
	{"smtp.from", func(a *SMTPAsked) *string { return &a.From }},
	{"smtp.to", func(a *SMTPAsked) *string { return &a.To }},
}

// readSettings is the .dpt file's lines; none when there is no file.
func readSettings(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
	}
	return lines
}

// LoadSMTPAsked is the last smtp prompt's answers from the .dpt file;
// empty when there are none.
func LoadSMTPAsked() SMTPAsked {
	var a SMTPAsked
	path := SettingsFile()
	if path == "" {
		return a
	}
	for _, l := range readSettings(path) {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		for _, s := range smtpKeys {
			if strings.TrimSpace(k) == s.key {
				*s.val(&a) = v
			}
		}
	}
	return a
}

// SaveSMTPAsked keeps a in the .dpt file, in place of the answers before
// it; the file's other lines stay.
func SaveSMTPAsked(a SMTPAsked) error {
	path := SettingsFile()
	if path == "" {
		return errors.New("no home folder to keep .dpt in")
	}
	var out []string
	for _, l := range readSettings(path) {
		k, _, _ := strings.Cut(l, "=")
		if !strings.HasPrefix(strings.TrimSpace(k), "smtp.") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = append(out, "# dpt remembers these between runs; it holds a password: keep it private")
	}
	for _, s := range smtpKeys {
		v := strings.NewReplacer("\r", "", "\n", "").Replace(*s.val(&a))
		out = append(out, s.key+"="+v)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dpt-save-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(strings.Join(out, "\n") + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
