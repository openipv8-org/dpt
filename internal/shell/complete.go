// SPDX-License-Identifier: MIT

package shell

import (
	"strings"

	"openipv8.org/dpt/internal/dpt"
)

// shellCommands are the commands Tab completes, as help lists them.
var shellCommands = []string{
	"server", "lserver", "fallback=", "root", "set", "ls", "exit", "quit", "help",
	"ping", "time", "ntpd=", "trydhcp", "info", "interface", "dpt", "features",
	"smtp", "sweep", "ports", "connect", "trace", "outside-ip", "whois", "rdap",
}

// setOptions are set's options.
var setOptions = []string{
	"all", "type=", "q=", "class=", "port=", "timeout=", "retry=",
	"recurse", "norecurse", "vc", "novc", "debug", "nodebug", "d2", "nod2",
	"domain=", "srchlist=", "search", "nosearch", "defname", "nodefname", "ntpd=",
	"fallback=",
}

// complete gives the words that can stand where the cursor is: the
// command, then its own words.
func (s *Shell) complete(before string) []string {
	f := strings.Fields(before)
	// the words before the one being typed
	done := f
	if !strings.HasSuffix(before, " ") && len(f) > 0 {
		done = f[:len(f)-1]
	}
	if len(done) == 0 {
		return shellCommands
	}
	cmd := strings.ToLower(done[0])
	n := len(done) // the word being typed is the n-th (0 is the command)
	switch cmd {
	case "set":
		word := ""
		if len(f) > len(done) {
			word = f[len(f)-1]
		}
		k, _, eq := strings.Cut(word, "=")
		switch kl := strings.ToLower(k); {
		case eq && (kl == "type" || kl == "q" || kl == "querytype"):
			var out []string
			for _, t := range dpt.DNSTypeNames() {
				out = append(out, k+"="+t)
			}
			return out
		case eq && (kl == "class" || kl == "cl"):
			return []string{k + "=IN", k + "=CH", k + "=HS"}
		}
		return setOptions
	case "interface", "trydhcp":
		if n != 1 {
			return nil
		}
		list, _ := dpt.DPTIfaceList()
		var out []string
		if cmd == "interface" {
			out = append(out, "auto")
		}
		for _, e := range list {
			out = append(out, e.Name)
		}
		return out
	case "sweep":
		for _, w := range done[1:] {
			if strings.EqualFold(w, "ports") {
				return nil
			}
		}
		return []string{"ports"}
	case "smtp":
		// smtp <host> test, or smtp test
		if n == 1 || n == 2 && !strings.EqualFold(done[1], "test") {
			return []string{"test"}
		}
	case "help":
		if n == 1 {
			return shellCommands
		}
	}
	return nil
}
