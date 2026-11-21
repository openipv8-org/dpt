// SPDX-License-Identifier: MIT
package dpt

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// dpt's command line:
//
//	dpt [dhcp|<address>|<dnsname>] [tests] [options]
//
// The tests are letters written together: t time, d DNS, p ping
// (/tdp on Windows, -tdp or --tdp on Linux and macOS); none given runs
// all three.  Options are one set, written the way the system writes
// them: /c:3 /w:2 on Windows, -c 3 -w 2 on Linux and macOS (--count 3,
// --timeout=2s).

// DPTArgStyle is how options are written.
type DPTArgStyle int

const (
	DPTStyleWindows DPTArgStyle = iota // /c:3, /count:3
	DPTStyleUnix                       // -c 3, --count 3, --count=3
)

// DPTCommand is a parsed dpt command line.
type DPTCommand struct {
	Mode   string // "dpt", "dhcp", "info", "install", "upgrade", "smtp", "sweep", "ports", "outside-ip", "shell", "help", "version"
	Target string // dpt, smtp, ports: the address or name
	// smtp <host> test <user> [<password>]: log in as User (Password ""
	// is asked for)
	SMTPUser, SMTPPassword string
	// sweep [ports] [<network>]
	SweepPorts   bool
	SweepNetwork string
	// ports <host> [<list>]: nil is DPTDefaultPorts
	PortList []DPTPortName
	Opts     DPTDHCPOptions
	JSON     bool
	NoColor  bool
	Verbose  bool
	Select   bool // choose the interface from a list
}

type dptOpt struct {
	long, short string
	value       bool // takes a value
	help        string
}

var dptOpts = []dptOpt{
	{"count", "c", true, "pings and DNS lookups per run (5)"},
	{"timeout", "w", true, "how long to wait for each answer, seconds or 500ms (2)"},
	{"names", "", true, "names to resolve, a,b,c (google.com,microsoft.com,cloudflare.com,ietf.org,github.com)"},
	{"ntp", "", true, "reference NTP servers, a,b (time.google.com,time.windows.com)"},
	{"all", "", false, "test every address a name resolves to"},
	{"iface", "", true, "dhcp, sweep: the interface to probe (the Ethernet one with the LAN gateway)"},
	{"listen", "", true, "dhcp: how long to collect offers (5)"},
	{"select", "", false, "dhcp, info, sweep: list the interfaces and choose one"},
	{"random-mac", "", false, "dhcp: probe with a random MAC instead of the interface's (some routers' offers then never arrive)"},
	{"4", "", false, "IPv4 only"},
	{"6", "", false, "IPv6 only"},
	{"json", "", false, "one JSON document"},
	{"verbose", "", false, "a line per echo and per lookup"},
	{"no-color", "", false, "no ANSI colour"},
	{"help", "h", false, "this help"},
	{"version", "", false, "the version"},
}

// dptOptName writes an option in style.
func dptOptName(st DPTArgStyle, name string) string {
	if st == DPTStyleWindows {
		return "/" + name
	}
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// DPTUsage is the help text in style; prog is the command's name.
func DPTUsage(st DPTArgStyle, prog string) string {
	var b strings.Builder
	val := func(o dptOpt) string {
		if !o.value {
			return ""
		}
		if st == DPTStyleWindows {
			return ":<v>"
		}
		return " <v>"
	}
	tests := "-tdp"
	if st == DPTStyleWindows {
		tests = "/tdp"
	}
	fmt.Fprintf(&b, "usage: %s [dhcp|<address>|<dnsname>] [%s] [options]\n", prog, tests)
	fmt.Fprintf(&b, "       %s info             this machine's DHCP lease, gateway, DNS and NTP servers, clock (sends only NTP requests)\n", prog)
	fmt.Fprintf(&b, "       %s smtp <host> [test <user> [<password>]]\n", prog)
	fmt.Fprintf(&b, "                            ports 25, 465 and 587: greeting, STARTTLS or TLS, the certificate, AUTH;\n")
	fmt.Fprintf(&b, "                            test: log in (the password is asked for when not given)\n")
	fmt.Fprintf(&b, "       %s sweep [ports] [<network>]\n", prog)
	fmt.Fprintf(&b, "                            ping every address on this network (or <network>, 10.0.0.0/24; an address: its /24),\n")
	fmt.Fprintf(&b, "                            25 at a time; ports: then the common ports of each that answers\n")
	fmt.Fprintf(&b, "       %s ports <host> [<ports>]\n", prog)
	fmt.Fprintf(&b, "                            the %d common TCP ports and %d UDP services (DNS, NTP, QUIC, SNMP...) of host,\n", len(DPTTopPorts), len(DPTUDPPorts))
	fmt.Fprintf(&b, "                            or <ports>: 587,2525,8000-8010,53/udp (TCP unless /udp)\n")
	fmt.Fprintf(&b, "       %s outside-ip       the address the internet sees (asks %s)\n", prog, OutsideIPURL)
	fmt.Fprintf(&b, "       %s install          put this dpt where the system finds it (%s)\n", prog, map[DPTArgStyle]string{DPTStyleWindows: `C:\Program Files\dpt, added to PATH`}[st]+map[bool]string{true: "/usr/local/bin"}[st != DPTStyleWindows])
	fmt.Fprintf(&b, "       %s upgrade          download the newest release and install it\n", prog)
	fmt.Fprintf(&b, "       %s                  interactive shell (nslookup and more)\n", prog)
	fmt.Fprintf(&b, "\ntests (letters together, any of them; none: all three):\n")
	fmt.Fprintf(&b, "  t  time: NTP against %s, and this machine's clock checked against them\n", strings.Join(DPTDefaultNTP, ", "))
	fmt.Fprintf(&b, "  d  DNS: use the address as a resolver\n")
	fmt.Fprintf(&b, "  p  ping: ICMP echo\n")
	fmt.Fprintf(&b, "  dhcp: every DHCP server on the segment and its offer; t and d test the NTP and DNS servers offered\n")
	if st == DPTStyleUnix {
		b.WriteString("  --tdp works as well as -tdp\n")
	}
	b.WriteString("\noptions:\n")
	for _, o := range dptOpts {
		name := ""
		if o.short != "" {
			name = dptOptName(st, o.short) + val(o) + ", "
		}
		name += dptOptName(st, o.long) + val(o)
		fmt.Fprintf(&b, "  %-26s %s\n", name, o.help)
	}
	if st == DPTStyleWindows {
		b.WriteString("  /?                         this help\n")
	}
	b.WriteString("\nexit codes: 0 all OK, 1 a test failed, 2 minimum execution level not met, 3 bad usage\n")
	b.WriteString("\n" + DPTAuthors + "\n")
	return b.String()
}

// DPTAuthors is shown with every help.
const DPTAuthors = "Authors: Jamie Thain and Claude Opus 5.5 (Anthropic).  MIT licence.  https://github.com/openipv8-org/dpt"

func dptFind(name string) (dptOpt, bool) {
	for _, o := range dptOpts {
		if o.long == name || o.short != "" && o.short == name {
			return o, true
		}
	}
	return dptOpt{}, false
}

// dptTestLetters reads a word of test letters (tdp, or t/d/p as Windows
// may write it); ok is false when it is not one.
func dptTestLetters(s string) (DPTTests, bool) {
	var t DPTTests
	s = strings.ReplaceAll(s, "/", "")
	if s == "" {
		return t, false
	}
	for _, c := range strings.ToLower(s) {
		switch c {
		case 't':
			t.Time = true
		case 'd':
			t.DNS = true
		case 'p':
			t.Ping = true
		default:
			return DPTTests{}, false
		}
	}
	return t, true
}

// ParseDPTArgs reads a dpt command line (without the program name).
func ParseDPTArgs(args []string, st DPTArgStyle) (*DPTCommand, error) {
	c := &DPTCommand{Mode: "dpt"}
	if len(args) == 0 {
		c.Mode = "shell"
		return c, nil
	}
	var pos []string // the words that are not options
	for i := 0; i < len(args); i++ {
		a := args[i]
		body, val, hasVal, isOpt, long := "", "", false, false, false
		if st == DPTStyleWindows {
			if a == "/?" || a == "-?" {
				c.Mode = "help"
				return c, nil
			}
			if strings.HasPrefix(a, "/") && len(a) > 1 {
				isOpt, body = true, a[1:]
				if k := strings.IndexByte(body, ':'); k >= 0 {
					body, val, hasVal = body[:k], body[k+1:], true
				}
			}
		} else {
			if strings.HasPrefix(a, "--") && len(a) > 2 {
				isOpt, long, body = true, true, a[2:]
				if k := strings.IndexByte(body, '='); k >= 0 {
					body, val, hasVal = body[:k], body[k+1:], true
				}
			} else if strings.HasPrefix(a, "-") && len(a) > 1 {
				isOpt, body = true, a[1:]
			}
		}
		if !isOpt {
			pos = append(pos, a)
			continue
		}
		body = strings.ToLower(body)
		o, found := dptFind(body)
		// -c 3 is the count, but a word of test letters is tests: the
		// letters (t, d, p) are no option's
		if !found || (st == DPTStyleUnix && !long && len(body) > 1 && o.long == body) {
			if t, ok := dptTestLetters(body); ok && !hasVal {
				c.Opts.Tests = c.Opts.Tests.Or(t)
				continue
			}
			if !found {
				return nil, fmt.Errorf("unknown option %s", Printable(a))
			}
			if st == DPTStyleUnix {
				return nil, fmt.Errorf("unknown option %s (long options take two dashes: -%s)", Printable(a), Printable(a))
			}
		}
		if o.value && !hasVal {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s needs a value", dptOptName(st, body))
			}
			if st == DPTStyleWindows {
				return nil, fmt.Errorf("%s needs a value: %s:<value>", dptOptName(st, body), dptOptName(st, body))
			}
			i++
			val = args[i]
		} else if !o.value && hasVal {
			return nil, fmt.Errorf("%s takes no value", dptOptName(st, body))
		}
		if err := c.set(o.long, val, st); err != nil {
			return nil, err
		}
	}
	// version and help alone are the command, not a host to look up: a
	// one-word name with no dot is never a target anyone means here
	if len(pos) == 1 {
		if l := strings.ToLower(pos[0]); l == "version" || l == "help" {
			c.Mode = l
		}
	}
	switch c.Mode {
	case "help", "version":
		return c, nil
	}
	if err := c.words(pos); err != nil {
		return nil, err
	}
	if c.Select && c.Mode != "dhcp" && c.Mode != "info" && c.Mode != "sweep" {
		return nil, errors.New(dptOptName(st, "select") + " goes with dhcp, info or sweep")
	}
	if c.Opts.Iface != "" && c.Mode != "dhcp" && c.Mode != "info" && c.Mode != "sweep" {
		return nil, errors.New(dptOptName(st, "iface") + " goes with dhcp, info or sweep")
	}
	if c.Select && c.Opts.Iface != "" {
		return nil, fmt.Errorf("%s or %s, not both", dptOptName(st, "select"), dptOptName(st, "iface"))
	}
	switch c.Mode {
	case "install", "upgrade":
		if c.Opts.Tests != (DPTTests{}) || c.Opts.Iface != "" || c.Select {
			return nil, errors.New(c.Mode + " takes no tests and no interface")
		}
	case "info":
		if c.Opts.Tests != (DPTTests{}) {
			return nil, errors.New("info only reads this machine: it takes no tests")
		}
	case "smtp", "sweep", "ports", "outside-ip":
		if c.Opts.Tests != (DPTTests{}) {
			return nil, errors.New(c.Mode + " takes no test letters")
		}
	case "dhcp":
		if c.Opts.Tests.Ping {
			return nil, errors.New("dhcp takes t and d (the NTP and DNS servers offered): p does not apply")
		}
	default:
		if c.Target == "" {
			return nil, errors.New("give " + dptModeList + ", an address or a name")
		}
	}
	return c, nil
}

// dptModes are the words that choose a mode instead of naming a target.
var dptModes = []string{"dhcp", "info", "install", "upgrade", "smtp", "sweep", "ports", "outside-ip"}

const dptModeList = "dhcp, info, smtp, sweep, ports, outside-ip, install, upgrade"

// words reads the words that are not options: a mode and its arguments,
// or the target.
func (c *DPTCommand) words(pos []string) error {
	if len(pos) == 0 {
		return nil
	}
	if l := strings.ToLower(pos[0]); slices.Contains(dptModes, l) {
		c.Mode = l
	} else {
		c.Target = pos[0]
	}
	rest := pos[1:]
	extra := func() error {
		return fmt.Errorf("one of %s, an address or a name: not %q as well", dptModeList, Printable(rest[0]))
	}
	switch c.Mode {
	case "smtp":
		const use = "smtp <host> [test <user> [<password>]]"
		if len(rest) == 0 || slices.Contains(dptModes, strings.ToLower(rest[0])) {
			return errors.New(use)
		}
		c.Target, rest = rest[0], rest[1:]
		if len(rest) == 0 {
			return nil
		}
		if !strings.EqualFold(rest[0], "test") || len(rest) < 2 || len(rest) > 3 {
			return errors.New(use)
		}
		c.SMTPUser = rest[1]
		if len(rest) == 3 {
			c.SMTPPassword = rest[2]
		}
	case "sweep":
		for _, w := range rest {
			switch {
			case strings.EqualFold(w, "ports") && !c.SweepPorts:
				c.SweepPorts = true
			case c.SweepNetwork == "":
				if _, err := ParseSweepNetwork(w); err != nil {
					return err
				}
				c.SweepNetwork = w
			default:
				return errors.New("sweep [ports] [<network>]")
			}
		}
		if c.SweepNetwork != "" && c.Opts.Iface != "" {
			return errors.New("sweep: a network or an interface, not both")
		}
	case "ports":
		if len(rest) < 1 || len(rest) > 2 {
			return errors.New("ports <host> [<ports>]: 587,2525,8000-8010,53/udp")
		}
		c.Target = rest[0]
		if len(rest) == 2 {
			l, err := ParsePortList(rest[1])
			if err != nil {
				return err
			}
			c.PortList = l
		}
	default:
		if len(rest) > 0 {
			return extra()
		}
	}
	return nil
}

func (c *DPTCommand) set(long, v string, st DPTArgStyle) error {
	dur := func() (time.Duration, error) {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			d := time.Duration(n * float64(time.Second)) // a bare number is seconds
			if d > 0 && d <= time.Hour {
				return d, nil
			}
		} else if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= time.Hour {
			return d, nil
		}
		return 0, fmt.Errorf("%s: seconds (2) or a duration (500ms), at most 1h", dptOptName(st, long))
	}
	list := func() []string {
		var out []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var err error
	switch long {
	case "count":
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 1000 {
			return fmt.Errorf("%s: 1-1000", dptOptName(st, long))
		}
		c.Opts.Count = n
	case "timeout":
		c.Opts.Timeout, err = dur()
	case "listen":
		c.Opts.Listen, err = dur()
	case "names":
		if c.Opts.Names = list(); len(c.Opts.Names) == 0 {
			return fmt.Errorf("%s: at least one name", dptOptName(st, long))
		}
		for _, n := range c.Opts.Names {
			if !ValidName(n, false) {
				return fmt.Errorf("%s: %q is not a DNS name", dptOptName(st, long), Printable(n))
			}
		}
	case "ntp":
		if c.Opts.NTP = list(); len(c.Opts.NTP) == 0 {
			return fmt.Errorf("%s: at least one server", dptOptName(st, long))
		}
	case "iface":
		c.Opts.Iface = v
	case "all":
		c.Opts.All = true
	case "random-mac":
		c.Opts.RandomMAC = true
	case "select":
		c.Select = true
	case "4":
		c.Opts.Family = 4
	case "6":
		c.Opts.Family = 6
	case "json":
		c.JSON = true
	case "verbose":
		c.Verbose = true
	case "no-color":
		c.NoColor = true
	case "help":
		c.Mode = "help"
	case "version":
		c.Mode = "version"
	}
	return err
}
