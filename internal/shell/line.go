// SPDX-License-Identifier: MIT

// Package shell is dpt's interactive mode: nslookup's commands and dpt's
// own, with line editing and a history file.
package shell

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// errInterrupt is Ctrl-C at the prompt; io.EOF is Ctrl-D on an empty line.
var errInterrupt = errors.New("interrupt")

// lineReader reads lines: edited in raw mode on a terminal, plain
// otherwise (a pipe or a file).
type lineReader struct {
	in       *os.File
	out      io.Writer
	tty      bool
	plain    *bufio.Reader
	hist     []string
	histFile string
	// redact takes a secret out of a line before it is kept or echoed
	redact func(string) (string, bool)
	// complete gives the words that can end the line before the cursor
	complete func(before string) []string
	asking   bool // an answer to a question: not kept in the history
}

const histMax = 1000

// HistoryFile is ~/.dpt_history, or %APPDATA%\dpt\history on Windows.
func HistoryFile() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "dpt", "history")
		}
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".dpt_history")
}

func newLineReader(in *os.File, out io.Writer, histFile string) *lineReader {
	r := &lineReader{in: in, out: out, histFile: histFile}
	r.tty = term.IsTerminal(int(in.Fd()))
	r.plain = bufio.NewReader(in) // one reader for the whole session: typed-ahead input is kept
	if histFile != "" {
		if b, err := os.ReadFile(histFile); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimRight(l, "\r"); l != "" {
					r.hist = append(r.hist, l)
				}
			}
			if len(r.hist) > histMax {
				r.hist = r.hist[len(r.hist)-histMax:]
			}
		}
	}
	return r
}

func (r *lineReader) remember(l string) {
	if r.redact != nil {
		l, _ = r.redact(l)
	}
	if l == "" || len(r.hist) > 0 && r.hist[len(r.hist)-1] == l {
		return
	}
	r.hist = append(r.hist, l)
	if r.histFile == "" {
		return
	}
	os.MkdirAll(filepath.Dir(r.histFile), 0o700)
	if f, err := os.OpenFile(r.histFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		f.WriteString(l + "\n")
		f.Close()
	}
}

// ReadLine shows prompt and gives the line typed.
func (r *lineReader) ReadLine(prompt string) (string, error) {
	if !r.tty {
		io.WriteString(r.out, prompt)
		l, err := r.plain.ReadString('\n')
		if err != nil && l == "" {
			return "", err
		}
		l = strings.TrimRight(l, "\r\n")
		shown := l
		if r.redact != nil {
			if t, cut := r.redact(l); cut {
				shown = t + " ********"
			}
		}
		io.WriteString(r.out, shown+"\n")
		return l, nil
	}
	fd := int(r.in.Fd())
	st, err := term.MakeRaw(fd)
	if err != nil {
		r.tty = false
		return r.ReadLine(prompt)
	}
	defer term.Restore(fd, st)
	l, err := r.edit(prompt)
	io.WriteString(r.out, "\r\n")
	if err == nil && !r.asking {
		r.remember(strings.TrimSpace(l))
	}
	return l, err
}

// Ask reads an answer to a question: like ReadLine, with no completion
// and nothing kept in the history.
func (r *lineReader) Ask(prompt string) (string, error) {
	r.asking = true
	complete := r.complete
	r.complete = nil
	defer func() { r.asking, r.complete = false, complete }()
	return r.ReadLine(prompt)
}

// edit is the raw-mode editor: Emacs keys and the arrows.
func (r *lineReader) edit(prompt string) (string, error) {
	var buf []rune
	pos := 0
	hi := len(r.hist)
	saved := ""
	redraw := func() {
		var b strings.Builder
		b.WriteString("\r" + prompt + string(buf) + "\x1b[K")
		if back := len(buf) - pos; back > 0 {
			b.WriteString("\x1b[" + itoa(back) + "D")
		}
		io.WriteString(r.out, b.String())
	}
	setLine := func(s string) {
		buf = []rune(s)
		pos = len(buf)
	}
	redraw()
	in := r.plain
	for {
		c, _, err := in.ReadRune()
		if err != nil {
			return "", err
		}
		switch c {
		case '\r', '\n':
			return string(buf), nil
		case 3: // Ctrl-C
			io.WriteString(r.out, "^C")
			return "", errInterrupt
		case '\t':
			if r.complete == nil {
				continue
			}
			word, list := completeWord(string(buf[:pos]), r.complete)
			if word != "" {
				buf = append(buf[:pos], append([]rune(word), buf[pos:]...)...)
				pos += len([]rune(word))
			} else if len(list) > 1 {
				// nothing more in common: show the choices under the line
				io.WriteString(r.out, "\r\n"+strings.Join(list, "  ")+"\r\n")
			}
		case 4: // Ctrl-D
			if len(buf) == 0 {
				return "", io.EOF
			}
			if pos < len(buf) {
				buf = append(buf[:pos], buf[pos+1:]...)
			}
		case 1: // Ctrl-A
			pos = 0
		case 5: // Ctrl-E
			pos = len(buf)
		case 2: // Ctrl-B
			if pos > 0 {
				pos--
			}
		case 6: // Ctrl-F
			if pos < len(buf) {
				pos++
			}
		case 11: // Ctrl-K
			buf = buf[:pos]
		case 21: // Ctrl-U
			buf, pos = append([]rune{}, buf[pos:]...), 0
		case 23: // Ctrl-W
			k := pos
			for k > 0 && buf[k-1] == ' ' {
				k--
			}
			for k > 0 && buf[k-1] != ' ' {
				k--
			}
			buf, pos = append(buf[:k], buf[pos:]...), k
		case 12: // Ctrl-L
			io.WriteString(r.out, "\x1b[H\x1b[2J")
		case 16, 14: // Ctrl-P, Ctrl-N
			hi, saved = r.histMove(c == 16, hi, saved, string(buf), setLine)
		case 127, 8: // Backspace
			if pos > 0 {
				buf = append(buf[:pos-1], buf[pos:]...)
				pos--
			}
		case 27: // escape sequences
			b1, _ := in.ReadByte()
			if b1 != '[' && b1 != 'O' {
				continue
			}
			seq := ""
			for {
				b, err := in.ReadByte()
				if err != nil {
					break
				}
				seq += string(b)
				if b >= 0x40 && b <= 0x7e {
					break
				}
			}
			switch seq {
			case "A":
				hi, saved = r.histMove(true, hi, saved, string(buf), setLine)
			case "B":
				hi, saved = r.histMove(false, hi, saved, string(buf), setLine)
			case "C":
				if pos < len(buf) {
					pos++
				}
			case "D":
				if pos > 0 {
					pos--
				}
			case "H", "1~", "7~":
				pos = 0
			case "F", "4~", "8~":
				pos = len(buf)
			case "3~":
				if pos < len(buf) {
					buf = append(buf[:pos], buf[pos+1:]...)
				}
			}
		default:
			if c >= ' ' && c != utf8.RuneError {
				buf = append(buf[:pos], append([]rune{c}, buf[pos:]...)...)
				pos++
			}
		}
		redraw()
	}
}

// histMove steps through the history; the line being typed is kept as
// the newest entry.
func (r *lineReader) histMove(up bool, hi int, saved, cur string, set func(string)) (int, string) {
	if hi == len(r.hist) {
		saved = cur
	}
	if up && hi > 0 {
		hi--
		set(r.hist[hi])
	} else if !up && hi < len(r.hist) {
		hi++
		if hi == len(r.hist) {
			set(saved)
		} else {
			set(r.hist[hi])
		}
	}
	return hi, saved
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// completeWord is what Tab adds to the word before the cursor: the rest
// of the one candidate (and a space), or what all the candidates have in
// common; list is the candidates when there are several.
func completeWord(before string, complete func(string) []string) (add string, list []string) {
	word := before[strings.LastIndexByte(before, ' ')+1:]
	for _, c := range complete(before) {
		if strings.HasPrefix(strings.ToLower(c), strings.ToLower(word)) {
			list = append(list, c)
		}
	}
	if len(list) == 0 {
		return "", nil
	}
	if len(list) == 1 {
		add = list[0][len(word):]
		if !strings.HasSuffix(list[0], "=") {
			add += " "
		}
		return add, list
	}
	common := list[0]
	for _, c := range list[1:] {
		for !strings.HasPrefix(strings.ToLower(c), strings.ToLower(common)) {
			common = common[:len(common)-1]
		}
	}
	return common[len(word):], list
}

// ReadSecret reads a line with no echo: a password.
func (r *lineReader) ReadSecret(prompt string) (string, error) {
	io.WriteString(r.out, prompt)
	if !r.tty {
		l, err := r.plain.ReadString('\n')
		io.WriteString(r.out, "\n")
		if err != nil && l == "" {
			return "", err
		}
		return strings.TrimRight(l, "\r\n"), nil
	}
	fd := int(r.in.Fd())
	st, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer term.Restore(fd, st)
	defer io.WriteString(r.out, "\r\n")
	var buf []rune
	for {
		c, _, err := r.plain.ReadRune()
		if err != nil {
			return "", err
		}
		switch c {
		case '\r', '\n':
			return string(buf), nil
		case 3, 4: // Ctrl-C, Ctrl-D
			return "", errInterrupt
		case 21: // Ctrl-U
			buf = buf[:0]
		case 127, 8:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		default:
			if c >= ' ' && c != utf8.RuneError {
				buf = append(buf, c)
			}
		}
	}
}
