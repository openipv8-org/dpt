// SPDX-License-Identifier: MIT
package shell

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"openipv8.org/dpt/internal/dpt"
)

// rootServer is a.root-servers.net, for the root command.
const rootServer = "198.41.0.4"

// Shell is the interactive mode's state: nslookup's settings and dpt's.
type Shell struct {
	iface  string // the interface chosen with interface; "" dpt chooses
	lr     *lineReader
	sysDNS []string // the system's resolvers, for info
	out    io.Writer

	initial  string // the server dpt started with
	server   string // the default server: an address
	srvName  string // as typed, when it was a name
	port     int
	qtype    uint16
	qclass   uint16
	timeout  time.Duration
	retry    int
	recurse  bool
	vc       bool
	debug    bool
	d2       bool
	domain   string
	srchlist []string
	search   bool
	defname  bool
	ntpd     string
	// target is the server: the one host the commands act on (ping,
	// ports, smtp, trace, connect...) and the DNS server lookups go to
	// first; set by server (or root).  targetIP is its address;
	// targetSet, that it was chosen (not the start's DNS server).  A host
	// given to a command is for that command only.
	target    string
	targetIP  string
	targetSet bool
	// server (srvName, as typed) is fallback=: where lookups go when the
	// target does not answer DNS; 8.8.8.8 at the start, "" when set
	// fallback clear turned it off.
	noDNS map[string]bool // targets that did not answer DNS
	// lastSMTP: the smtp questions' last answers, offered again (kept in
	// .dpt too; this when that cannot be read)
	lastSMTP dpt.SMTPAsked

	DPT   dpt.DPTDHCPOptions // count, names, references, timeout from the command line
	Color bool
	// Agent names dpt in a test message (dpt v0.2.1).
	Agent string
	// NewLive, when set, starts the status line shown while a command
	// works (a terminal); nil: none.
	NewLive func() *dpt.Live
}

func (s *Shell) live() *dpt.Live {
	if s.NewLive == nil {
		return nil
	}
	return s.NewLive()
}

// New is a shell whose default server is the system's first.
func New(out io.Writer, servers []string, o dpt.DPTDHCPOptions) *Shell {
	s := &Shell{out: out, port: 53, qtype: dpt.DNSTypeA, qclass: dpt.DNSClassIN,
		timeout: 2 * time.Second, retry: 1, recurse: true, search: true, defname: true, DPT: o}
	if o.Timeout > 0 {
		s.timeout = o.Timeout
	}
	s.server = fallbackDNS // fallback=: lookups the server cannot answer
	if len(servers) > 0 {
		s.initial = servers[0]
		s.target, s.targetIP = servers[0], servers[0]
	}
	s.noDNS = map[string]bool{}
	s.sysDNS = servers
	return s
}

// fallbackDNS is fallback= at the start.
var fallbackDNS = "8.8.8.8"

func (s *Shell) printf(f string, a ...any) { fmt.Fprintf(s.out, f, a...) }

// Run reads commands from in until exit or end of input.
func (s *Shell) Run(in *os.File) error {
	lr := newLineReader(in, s.out, HistoryFile())
	lr.redact = withoutPassword
	lr.complete = s.complete
	s.lr = lr
	if s.target == "" {
		s.printf("*** no DNS server found: set one with server <address> (lookups go to fallback=%s)\n\n", fallbackDNS)
	} else {
		s.printf("Default server: %s\nAddress: %s\n\n", s.target, s.shown(s.targetIP))
	}
	for {
		line, err := lr.ReadLine(s.prompt())
		if err == errInterrupt {
			continue
		}
		if err != nil {
			s.printf("\n")
			return nil
		}
		if s.Do(strings.TrimSpace(line)) {
			return nil
		}
	}
}

// prompt is dpt [<server>]>: fallback=, ntpd= and the interface are in info
// and set all, not in the way here.
func (s *Shell) prompt() string {
	if s.target == "" {
		return "dpt> "
	}
	return "dpt [" + s.target + "]> "
}

// settings writes the shell's settings, as info ends with them.
func (s *Shell) settings() {
	or := func(v, none string) string {
		if v == "" {
			return none
		}
		return v
	}
	s.printf("\nSHELL     server               %s\n", or(s.target, "none (server <name>)"))
	if s.targetIP != "" && s.targetIP != s.target {
		s.printf("                               %s\n", s.targetIP)
	}
	s.printf("          fallback=            %s\n", s.fallbackWords())
	s.printf("          ntpd=                %s\n", or(s.ntpd, "(the server)"))
	s.printf("          interface            %s\n", or(s.iface, "(dpt chooses)"))
}

// ctx is a context that Ctrl-C ends.
func (s *Shell) ctx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func (s *Shell) addr(server string) string { return dpt.DNSServerAddr(server, s.port) }

// shown is a server as nslookup prints it: address#port.
func (s *Shell) shown(server string) string { return server + "#" + strconv.Itoa(s.port) }

// Do runs one command line; it gives true for exit.
func (s *Shell) Do(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") {
		return false
	}
	f := strings.Fields(line)
	cmd := strings.ToLower(f[0])
	args := f[1:]
	switch {
	case cmd == "exit" || cmd == "quit":
		return true
	case cmd == "help" || cmd == "?":
		s.help()
	case cmd == "server":
		s.setTarget(args)
	case cmd == "lserver":
		// an alias of set fallback=
		if len(args) != 1 {
			s.printf("usage: lserver <server>   (the same as set fallback=<server>)\n")
			break
		}
		s.setFallback(args[0])
	case cmd == "root":
		// as nslookup's: a root server is the server
		s.target, s.targetIP, s.targetSet = "a.root-servers.net", rootServer, true
		delete(s.noDNS, rootServer)
		s.printf("Default server: a.root-servers.net\nAddress: %s\n\n", s.shown(rootServer))
	case cmd == "set":
		if len(args) == 0 {
			s.printf("usage: set <option>[=<value>]  (set all lists them)\n")
			break
		}
		if len(args) == 2 && strings.EqualFold(args[0], "fallback") && strings.EqualFold(args[1], "clear") {
			s.server, s.srvName = "", ""
			s.printf("fallback cleared: lookups go to the server only\n")
			break
		}
		for _, a := range args {
			s.set(a)
		}
	case strings.HasPrefix(cmd, "ntpd="), strings.HasPrefix(cmd, "fallback="):
		s.set(f[0])
	case cmd == "ls":
		s.ls(args)
	case cmd == "finger" || cmd == "view":
		s.printf("%s: not supported\n", cmd)
	case cmd == "ping":
		s.ping(args)
	case cmd == "time":
		s.time(args)
	case cmd == "trydhcp":
		s.trydhcp(args)
	case cmd == "info":
		ctx, cancel := s.ctx()
		// the outside addresses: asked now, shown last, waited for no
		// more than DPTOutsideWait from here
		outside := dpt.StartOutside(ctx, s.DPT.Family, time.Now().Add(dpt.DPTOutsideWait))
		r := dpt.DPTInfoGather(s.sysDNS, s.iface)
		l := s.live()
		dpt.DPTInfoTime(ctx, r, s.DPT.NTP, s.DPT.Timeout, l)
		l.Set("outside", "asking "+dpt.OutsideIPURL)
		r.Outside = outside()
		l.Stop()
		cancel()
		dpt.RenderDPTInfo(s.out, r, s.Color)
		s.settings()
		s.printf("\n")
	case cmd == "interface":
		s.chooseIface(args)
	case cmd == "dpt":
		s.dpt(args)
	case cmd == "features":
		s.features(args)
	case cmd == "smtp":
		s.smtp(args)
	case cmd == "sweep":
		s.sweep(args)
	case cmd == "ports":
		s.ports(args)
	case cmd == "connect":
		s.connect(args)
	case cmd == "trace":
		s.trace(args)
	case cmd == "outside-ip":
		s.outsideIP()
	default:
		// a lookup: <name> or <name> <server>
		if len(f) > 2 {
			s.printf("*** unknown command: %s (help lists them)\n", f[0])
			break
		}
		server := "" // the server, else fallback=
		if len(f) == 2 {
			a, err := s.resolve(f[1])
			if err != nil {
				s.printf("*** can't find address for server %s: %v\n", f[1], err)
				break
			}
			server = a
		}
		s.lookup(f[0], server)
	}
	return false
}

func (s *Shell) help() {
	s.printf(`Commands (nslookup):
  server [<host> | clear] the one server: the commands below act on it, and lookups go to it
                          first. The prompt shows it: dpt [<host>]>. A host given to a
                          command is for that command only. clear: the start's DNS server
  set fallback=<server>   where lookups go when the server does not answer DNS (8.8.8.8 at
                          the start); dpt says so when it falls back. info shows it
  lserver <server>        the same as set fallback=<server>
  set fallback clear      no fallback: lookups go to the server only
  <name>                  look up name with the server (else fallback=) and the type
  <address>               look up the name of an address (PTR)
  <name> <server>         look up name with another DNS server, once
  root                    the server: a root server (a.root-servers.net)
  set type=<T> | q=<T>    A AAAA MX NS SOA TXT CNAME PTR SRV CAA DS DNSKEY ANY ...
  set class=<C>           IN, CH (version.bind), HS
  set port=<n>  set timeout=<s>  set retry=<n>
  set [no]recurse  set [no]vc  set [no]debug  set [no]d2
  set domain=<d>  set srchlist=a/b/c  set [no]search  set [no]defname
  set all                 show the settings
  ls [-d] <domain>        zone transfer (AXFR): -d every record, else A and NS
  exit
dpt:
  ping [host] [count]     ICMP echo (default the server, 5)
  time [host]             NTP time of host (default ntpd, else the server) against the references
  ntpd=<server>           the server time asks (set ntpd= clears it: the server)
  trydhcp [iface]         probe the segment for DHCP servers (needs sudo / an Administrator prompt)
  info                    this machine's DHCP lease, gateway, DNS and NTP servers, clock against time services,
                          the outside IPv4 and IPv6 addresses (asks ifconfig.me)
  interface [name|auto]   choose the interface trydhcp and info use (no name: a list to choose from)
  dpt [host]              the whole test: ping, DNS, time, features
  features [host]         what the address offers
  smtp [host]             the mail check of the server (or host): 25, 465, 587, 2525, 8025, greeting,
                          STARTTLS or TLS, certificate, AUTH, why a port fails, a firewall in the
                          way; then what mail can and cannot do from here
  smtp prompt             asks, a line at a time: the server, a login, a test message (offering the
                          last answers, kept in .dpt)
  smtp [host] test <user> [password]
                          and log in: over trusted TLS when there is one, else untrusted TLS,
                          else in the clear (WARN). No host: the server; no password:
                          asked for, and never kept in the history
  smtp [host] [test <user> [password]] [from <address>] to <address>
                          and send a test message, "test from dpt at <this address>"
                          (from: the user, when it is an address)
  sweep [ports] [network] ping the /24 around the server (or network, or this machine's),
                          25 at a time; ports: then the common ports of each live one
  ports [host] [ports]    the common TCP ports and UDP services (DNS, NTP, QUIC...) of host
                          (default the server), or ports: 587,2525,8000-8010,53/udp
  connect [host] <port> [tls|notls]
                          connect as telnet would: the time, TLS and certificate, what the
                          server says first; then type to it (Ctrl-D or Ctrl-C to close)
  trace [host]            the routers on the way, each hop asked 3 times, with times and loss
  outside-ip              the address the internet sees (asks ifconfig.me)
  Tab completes commands, options and names
  help, ?                 this list
`)
}

// setFallback is set fallback=<server> (and lserver): where lookups go
// when the server does not answer DNS.
func (s *Shell) setFallback(host string) {
	a, err := s.resolve(host)
	if err != nil {
		s.printf("*** can't find address for fallback=%s: %v\n", host, err)
		return
	}
	s.server, s.srvName = a, ""
	if a != host {
		s.srvName = host
	}
	s.printf("fallback=%s (%s): lookups the server does not answer go to it\n", host, s.shown(a))
}

// fallbackWords is fallback= as info and set all show it.
func (s *Shell) fallbackWords() string {
	if s.server == "" {
		return "off: lookups go to the server only (set fallback=<server> turns it on)"
	}
	if s.srvName != "" {
		return s.srvName + " (" + s.server + ")"
	}
	return s.server
}

// dnsOrder is where lookups go: the server, then fallback= (when it is
// on, and is not the server).
func (s *Shell) dnsOrder() []string {
	switch {
	case s.targetIP == "" && s.server == "":
		return nil
	case s.targetIP == "":
		return []string{s.server}
	case s.server == "" || s.targetIP == s.server:
		return []string{s.targetIP}
	}
	return []string{s.targetIP, s.server}
}

// fallbackWarn says the server is not answering and the fallback is
// asked instead.
func (s *Shell) fallbackWarn() {
	s.printf("*** [%s] is not working: falling back to [%s]\n", s.target, s.serverName())
}

// askAny asks the server, then (when it does not answer) fallback=,
// saying so; when the fallback does not answer either, the lookup fails.
// It gives the answer and who gave it.
func (s *Shell) askAny(ctx context.Context, name string, t uint16) (*dpt.DNSAnswer, string, error) {
	order := s.dnsOrder()
	if len(order) == 0 {
		return nil, "", errors.New("no server")
	}
	if len(order) == 2 {
		srv := order[0]
		if !s.noDNS[srv] {
			// the server: one quick try; no DNS there is no reason to wait
			o := dpt.DNSAskOptions{Type: t, Class: s.qclass, NoRecurse: !s.recurse, TCP: s.vc}
			a, err := dpt.DNSAsk(ctx, s.addr(srv), name, o, min(s.timeout, 2*time.Second))
			if err == nil {
				return a, srv, nil
			}
			if ctx.Err() != nil {
				return nil, srv, err
			}
			s.noDNS[srv] = true // not asked again until the server is set again
		}
		s.fallbackWarn()
		order = order[1:]
	}
	a, err := s.ask(ctx, order[0], name, t)
	return a, order[0], err
}

// resolve gives host's address: itself, or looked up as lookups are
// (the server, else the fallback), else by the system.
func (s *Shell) resolve(host string) (string, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String(), nil
	}
	ctx, cancel := s.ctx()
	defer cancel()
	for _, t := range []uint16{dpt.DNSTypeA, dpt.DNSTypeAAAA} {
		a, _, err := s.askAny(ctx, fqdn(host), t)
		if err != nil || a == nil {
			continue
		}
		for _, r := range a.Answer {
			if r.Type == t {
				return net.IP(r.Data).String(), nil
			}
		}
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return "", errors.New("not found")
	}
	return ips[0].IP.String(), nil
}

func fqdn(n string) string {
	if strings.HasSuffix(n, ".") {
		return n
	}
	return n + "."
}

// set reads one nslookup option.
func (s *Shell) set(a string) {
	k, v, hasV := strings.Cut(a, "=")
	k = strings.ToLower(k)
	bad := func() { s.printf("*** invalid option: %s\n", a) }
	num := func(lo, hi int) (int, bool) {
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			s.printf("*** %s: %d-%d\n", k, lo, hi)
			return 0, false
		}
		return n, true
	}
	switch k {
	case "all":
		s.showAll()
	case "type", "q", "querytype", "ty":
		t, ok := dpt.DNSTypeByName(v)
		if !ok {
			s.printf("*** unknown query type: %s\n", v)
			return
		}
		s.qtype = t
	case "class", "cl":
		c, ok := dpt.DNSClassByName(v)
		if !ok {
			s.printf("*** unknown class: %s\n", v)
			return
		}
		s.qclass = c
	case "port", "po":
		if n, ok := num(1, 65535); ok {
			s.port = n
		}
	case "timeout", "ti":
		if n, ok := num(1, 3600); ok {
			s.timeout = time.Duration(n) * time.Second
		}
	case "retry", "ret":
		if n, ok := num(0, 20); ok {
			s.retry = n
		}
	case "recurse", "rec", "norecurse", "norec":
		s.recurse = !strings.HasPrefix(k, "no")
	case "vc", "novc":
		s.vc = k == "vc"
	case "debug", "deb", "nodebug", "nodeb":
		s.debug = !strings.HasPrefix(k, "no")
		if !s.debug {
			s.d2 = false
		}
	case "d2", "nod2":
		s.d2 = k == "d2"
		if s.d2 {
			s.debug = true
		}
	case "domain", "do":
		s.domain = strings.TrimSuffix(v, ".")
		s.srchlist = nil
		if s.domain != "" {
			s.srchlist = []string{s.domain}
		}
	case "srchlist", "srchl":
		s.srchlist = nil
		for _, d := range strings.Split(v, "/") {
			if d = strings.TrimSuffix(strings.TrimSpace(d), "."); d != "" {
				s.srchlist = append(s.srchlist, d)
			}
		}
		if len(s.srchlist) > 0 {
			s.domain = s.srchlist[0]
		}
	case "search", "sea", "nosearch", "nosea":
		s.search = !strings.HasPrefix(k, "no")
	case "defname", "def", "nodefname", "nodef":
		s.defname = !strings.HasPrefix(k, "no")
	case "fallback":
		// set fallback=<server>; set fallback clear is in Do
		if v = strings.TrimSpace(v); !hasV || v == "" {
			s.printf("usage: set fallback=<server>, or set fallback clear to turn it off\n")
			return
		}
		s.setFallback(v)
	case "ntpd":
		if !hasV {
			bad()
			return
		}
		s.ntpd = strings.TrimSpace(v)
		if s.ntpd == "" {
			s.printf("ntpd cleared: time asks the server\n")
		}
	default:
		bad()
	}
}

func (s *Shell) showAll() {
	no := func(on bool) string {
		if on {
			return "  "
		}
		return "no"
	}
	ntpd := s.ntpd
	if ntpd == "" {
		ntpd = "(the server)"
	}
	if s.target == "" {
		s.printf("Default server: (none: server <name> sets it)\n")
	} else {
		s.printf("Default server: %s\nAddress: %s\n", s.target, s.shown(s.targetIP))
	}
	s.printf("fallback = %s\n\nSet options:\n", s.fallbackWords())
	s.printf("  %svc\t\t%sdebug\t\t%sd2\n", no(s.vc), no(s.debug), no(s.d2))
	s.printf("  %ssearch\t%srecurse\t%sdefname\n", no(s.search), no(s.recurse), no(s.defname))
	s.printf("  timeout = %d\tretry = %d\tport = %d\n", int(s.timeout/time.Second), s.retry, s.port)
	s.printf("  querytype = %s\tclass = %s\n", dpt.DNSTypeString(s.qtype), dpt.DNSClassString(s.qclass))
	s.printf("  domain = %s\n  srchlist = %s\n", s.domain, strings.Join(s.srchlist, "/"))
	s.printf("  ntpd = %s\n", ntpd)
	s.printf("  dpt: count = %d, names = %s, references = %s\n\n", s.count(), strings.Join(s.names(), ","), strings.Join(s.refs(), ","))
}

func (s *Shell) count() int {
	if s.DPT.Count > 0 {
		return s.DPT.Count
	}
	return 5
}

func (s *Shell) names() []string {
	if len(s.DPT.Names) > 0 {
		return s.DPT.Names
	}
	return dpt.DPTDefaultNames
}

func (s *Shell) refs() []string {
	if len(s.DPT.NTP) > 0 {
		return s.DPT.NTP
	}
	return dpt.DPTDefaultNTP
}

// candidates are the names a lookup tries, as nslookup's search rules
// give them.
func (s *Shell) candidates(name string) []string {
	if strings.HasSuffix(name, ".") {
		return []string{name}
	}
	var withList []string
	if s.search && len(s.srchlist) > 0 {
		for _, d := range s.srchlist {
			withList = append(withList, name+"."+d+".")
		}
	} else if s.defname && s.domain != "" {
		withList = []string{name + "." + s.domain + "."}
	}
	if strings.Contains(name, ".") {
		return append([]string{name + "."}, withList...)
	}
	return append(withList, name+".")
}

func (s *Shell) ask(ctx context.Context, server, name string, t uint16) (*dpt.DNSAnswer, error) {
	o := dpt.DNSAskOptions{Type: t, Class: s.qclass, NoRecurse: !s.recurse, TCP: s.vc}
	var err error
	for i := 0; i <= s.retry; i++ {
		var a *dpt.DNSAnswer
		a, err = dpt.DNSAsk(ctx, s.addr(server), name, o, s.timeout)
		if err == nil {
			return a, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, err
}

// lookup is nslookup's plain lookup: on server, or ("") the server, else
// the fallback.
func (s *Shell) lookup(name, server string) {
	if server == "" && len(s.dnsOrder()) == 0 {
		s.printf("*** no server: use server <address>\n")
		return
	}
	ctx, cancel := s.ctx()
	defer cancel()
	t := s.qtype
	names := s.candidates(name)
	if ip := net.ParseIP(name); ip != nil {
		if t == dpt.DNSTypeA || t == dpt.DNSTypeAAAA {
			t = dpt.DNSTypePTR
		}
		names = []string{dpt.DNSReverseName(ip) + "."}
	}
	var last *dpt.DNSAnswer
	header := false
	for _, n := range names {
		var a *dpt.DNSAnswer
		var err error
		used := server
		if server != "" {
			a, err = s.ask(ctx, server, n, t)
		} else {
			a, used, err = s.askAny(ctx, n, t)
		}
		if !header {
			s.printf("Server:\t\t%s\nAddress:\t%s\n\n", used, s.shown(used))
			header = true
		}
		if err != nil {
			s.printf(";; connection timed out; no servers could be reached\n\n")
			return
		}
		last = a
		if s.debug {
			s.dump(a)
		}
		if a.Rcode != 3 { // not NXDOMAIN: this is the answer
			break
		}
	}
	a := last
	if a.Rcode != 0 {
		s.printf("** server can't find %s: %s\n\n", strings.TrimSuffix(name, "."), a.RcodeName())
		return
	}
	if len(a.Answer) == 0 {
		s.printf("*** Can't find %s: No answer\n\n", strings.TrimSuffix(name, "."))
		if len(a.Authority) > 0 {
			s.printf("Authoritative answers can be found from:\n")
			for _, r := range a.Authority {
				s.record(r)
			}
			s.printf("\n")
		}
		return
	}
	if !a.AA {
		s.printf("Non-authoritative answer:\n")
	}
	for i := 0; i < len(a.Answer); {
		r := a.Answer[i]
		// a name's run of addresses: Name once, then the addresses across
		j := i + 1
		if isAddr(r.Type) {
			for j < len(a.Answer) && isAddr(a.Answer[j].Type) && strings.EqualFold(a.Answer[j].Name, r.Name) {
				j++
			}
		}
		if j-i > 1 {
			var ips []string
			for _, x := range a.Answer[i:j] {
				ips = append(ips, dpt.Safe(dpt.DNSFormatRData(x.Type, x.Data)))
			}
			s.printf("Name:\t%s\n%s", strings.TrimSuffix(r.Name, "."), addressColumns(ips, 80))
		} else {
			s.record(r)
		}
		i = j
	}
	s.printf("\n")
}

func isAddr(t uint16) bool { return t == dpt.DNSTypeA || t == dpt.DNSTypeAAAA }

// addressColumns is "Addresses:" and the addresses in columns to its
// right, as many to a line as fit in width, the rest wrapped under them.
func addressColumns(ips []string, width int) string {
	const head = "Addresses: "
	rows := dpt.Columns(ips, width-len(head))
	return head + strings.Join(rows, "\n"+strings.Repeat(" ", len(head))) + "\n"
}

// record writes one record as nslookup does.
func (s *Shell) record(r dpt.DNSRecord) {
	n := strings.TrimSuffix(r.Name, ".")
	v := dpt.Safe(dpt.DNSFormatRData(r.Type, r.Data))
	switch r.Type {
	case dpt.DNSTypeA, dpt.DNSTypeAAAA:
		s.printf("Name:\t%s\nAddress: %s\n", n, v)
	case dpt.DNSTypeCNAME:
		s.printf("%s\tcanonical name = %s\n", n, v)
	case dpt.DNSTypeMX:
		s.printf("%s\tmail exchanger = %s\n", n, v)
	case dpt.DNSTypeNS:
		s.printf("%s\tnameserver = %s\n", n, v)
	case dpt.DNSTypePTR:
		s.printf("%s\tname = %s\n", n, v)
	case dpt.DNSTypeTXT:
		s.printf("%s\ttext = %s\n", n, v)
	case dpt.DNSTypeSRV:
		s.printf("%s\tservice = %s\n", n, v)
	case dpt.DNSTypeSOA:
		f := strings.Fields(v)
		if len(f) == 7 {
			s.printf("%s\n\torigin = %s\n\tmail addr = %s\n\tserial = %s\n\trefresh = %s\n\tretry = %s\n\texpire = %s\n\tminimum = %s\n",
				n, f[0], f[1], f[2], f[3], f[4], f[5], f[6])
			return
		}
		s.printf("%s\tsoa = %s\n", n, v)
	default:
		s.printf("%s\t%s = %s\n", n, strings.ToLower(dpt.DNSTypeString(r.Type)), v)
	}
}

// dump is set debug's view of an answer (and d2's raw octets).
func (s *Shell) dump(a *dpt.DNSAnswer) {
	if s.d2 {
		s.printf("------------\nSent %d octets:\n%s", len(a.Query), hex.Dump(a.Query))
		s.printf("Got %d octets (%s):\n%s", len(a.Raw), a.Network, hex.Dump(a.Raw))
	}
	q := a.Question
	s.printf("------------\n    HEADER:\n\topcode = QUERY, id = %d, rcode = %s\n\theader flags:  %s\n", a.ID, a.RcodeName(), strings.ReplaceAll(a.Flags(), " ", ", "))
	s.printf("\tquestions = 1,  answers = %d,  authority records = %d,  additional = %d\n", len(a.Answer), len(a.Authority), len(a.Additional))
	if a.EDNS {
		s.printf("\tEDNS: version %d, udp %d, do %v\n", a.EDNSVersion, a.EDNSSize, a.DOBit)
	}
	s.printf("    time = %.1f ms, %d octets over %s\n", float64(a.Time)/1e6, a.Size, a.Network)
	s.printf("\n    QUESTIONS:\n\t%s, type = %s, class = %s\n", strings.TrimSuffix(q.Name, "."), dpt.DNSTypeString(q.Type), dpt.DNSClassString(q.Class))
	sec := func(title string, rs []dpt.DNSRecord) {
		if len(rs) == 0 {
			return
		}
		s.printf("    %s:\n", title)
		for _, r := range rs {
			s.printf("    ->  %s\n\t%s = %s\n\tttl = %d\n", strings.TrimSuffix(r.Name, "."), strings.ToLower(dpt.DNSTypeString(r.Type)),
				dpt.Safe(dpt.DNSFormatRData(r.Type, r.Data)), r.TTL)
		}
	}
	sec("ANSWERS", a.Answer)
	sec("AUTHORITY RECORDS", a.Authority)
	sec("ADDITIONAL RECORDS", a.Additional)
	s.printf("------------\n")
}

// ls is a zone transfer.
func (s *Shell) ls(args []string) {
	all := false
	var dom string
	for _, a := range args {
		if a == "-d" {
			all = true
		} else if strings.HasPrefix(a, "-") {
			s.printf("ls: option %s not supported (only -d)\n", a)
			return
		} else {
			dom = a
		}
	}
	if dom == "" {
		s.printf("usage: ls [-d] <domain>\n")
		return
	}
	ctx, cancel := s.ctx()
	defer cancel()
	order := s.dnsOrder()
	if len(order) == 0 {
		s.printf("*** no server: use server <address>\n")
		return
	}
	srv := order[0]
	rs, err := dpt.DNSZoneTransfer(ctx, s.addr(srv), fqdn(dom), s.timeout*5)
	if err != nil && len(rs) == 0 {
		s.printf("*** can't list domain %s: %v\n", dom, err)
		return
	}
	s.printf("[%s]\n", srv)
	for _, r := range rs {
		if !all && r.Type != dpt.DNSTypeA && r.Type != dpt.DNSTypeAAAA && r.Type != dpt.DNSTypeNS {
			continue
		}
		s.printf(" %-30s %-6s %s\n", strings.TrimSuffix(r.Name, "."), dpt.DNSTypeString(r.Type), dpt.Safe(dpt.DNSFormatRData(r.Type, r.Data)))
	}
	if err != nil {
		s.printf("*** %v\n", err)
	}
}

// host gives the host a command acts on, as typed, and its address: the
// argument (for this command only), else the server.
func (s *Shell) host(args []string, i int) (string, string, bool) {
	if len(args) <= i {
		if s.target == "" {
			s.printf("*** no server: give one, or set it with server <name>\n")
			return "", "", false
		}
		return s.target, s.targetIP, true
	}
	name := args[i]
	a, err := s.resolve(name)
	if err != nil {
		s.printf("*** can't find %s: %v\n", name, err)
		return "", "", false
	}
	return name, a, true
}

// hostName is the server ("" none).
func (s *Shell) hostName() string { return s.target }

// setTarget is server [<name> | clear]: the one server the commands act
// on and lookups go to first (as nslookup's server), shown, or cleared
// back to the start's DNS server.
func (s *Shell) setTarget(args []string) {
	switch {
	case len(args) == 0:
		s.printf("Default server: %s\nAddress: %s\n\n", s.target, s.shown(s.targetIP))
	case len(args) == 1 && strings.EqualFold(args[0], "clear"):
		s.target, s.targetIP, s.targetSet = s.initial, s.initial, false
		s.printf("Default server: %s\nAddress: %s\n\n", s.target, s.shown(s.targetIP))
	case len(args) > 1:
		s.printf("usage: server [<name or address> | clear]\n")
	default:
		a, err := s.resolve(args[0])
		if err != nil {
			s.printf("*** can't find address for server %s: %v\n", args[0], err)
			return
		}
		s.target, s.targetIP, s.targetSet = args[0], a, true
		delete(s.noDNS, a) // asked again
		s.printf("Default server: %s\nAddress: %s\n\n", args[0], s.shown(a))
	}
}

func (s *Shell) opts() dpt.DPTOptions {
	o := s.DPT.DPTOptions
	o.Timeout = s.timeout
	if order := s.dnsOrder(); len(order) > 0 {
		o.Resolver = dpt.NewResolver(order[len(order)-1:]) // names: the fallback, else the server
	}
	return o
}

func (s *Shell) ping(args []string) {
	// ping <count> alone: the host (a number is no host's name)
	if len(args) == 1 {
		if _, err := strconv.Atoi(args[0]); err == nil {
			args = []string{s.hostName(), args[0]}
		}
	}
	name, ip, ok := s.host(args, 0)
	if !ok {
		return
	}
	o := s.opts()
	if len(args) > 1 {
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1 || n > 10000 {
			s.printf("*** count: 1-10000\n")
			return
		}
		o.Count = n
	}
	o.Count = max(o.Count, 0)
	if o.Count == 0 {
		o.Count = 5
	}
	ctx, cancel := s.ctx()
	defer cancel()
	s.printf("PING %s (%s): %d echoes\n", name, ip, o.Count)
	addr := net.ParseIP(ip)
	c, err := dpt.OpenICMP(addr)
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	defer c.Close()
	var replies []dpt.EchoReply
	sent := 0
	for i := 1; i <= o.Count && ctx.Err() == nil; i++ {
		start := time.Now()
		r, err := c.Echo(i, o.Timeout)
		sent++
		if err != nil {
			s.printf("seq %d: %v\n", i, err)
		} else {
			replies = append(replies, r)
			ttl := ""
			if r.TTL >= 0 {
				ttl = " ttl=" + strconv.Itoa(r.TTL)
			}
			s.printf("%d bytes from %s: seq=%d%s time=%.2f ms\n", r.Size, r.From, i, ttl, float64(r.RTT)/1e6)
		}
		if i < o.Count {
			select {
			case <-ctx.Done():
			case <-time.After(time.Second - time.Since(start)):
			}
		}
	}
	st := dpt.PingSummary(sent, replies)
	s.printf("--- %s ---\n%d sent, %d received, %.0f%% loss", name, st.Sent, st.Received, st.Loss)
	if st.Received > 0 {
		s.printf(", rtt min/avg/max/sd %.2f/%.2f/%.2f/%.2f ms", float64(st.Min)/1e6, float64(st.Avg)/1e6, float64(st.Max)/1e6, float64(st.StdDev)/1e6)
	}
	s.printf("\n\n")
}

func (s *Shell) time(args []string) {
	host := ""
	switch {
	case len(args) > 0:
		host = args[0]
	case s.ntpd != "":
		host = s.ntpd
	default:
		host = s.targetIP
	}
	if host == "" {
		s.printf("*** no server: give one, set it with server <name>, or set ntpd=<server>\n")
		return
	}
	ctx, cancel := s.ctx()
	defer cancel()
	o := s.opts()
	o.Live = s.live()
	t := dpt.DPTTimeRun(ctx, []dpt.DPTTimeAsk{{Server: host, Role: "target"}}, o)
	o.Live.Stop()
	dpt.RenderDPTTime(s.out, t, s.Color)
	s.printf("\n")
}

func (s *Shell) dpt(args []string) {
	name, _, ok := s.host(args, 0)
	if !ok {
		return
	}
	ctx, cancel := s.ctx()
	defer cancel()
	o := s.opts()
	p := dpt.NewDPTPrinter(s.out, s.Color, false)
	o.Live = s.live()
	o.OnTarget = func(t dpt.DPTTarget) { o.Live.Out(func() { p.Target(t) }) }
	o.OnSection = func(a *dpt.DPTAddrReport, sec string) { o.Live.Out(func() { p.Section(a, sec) }) }
	r, err := dpt.RunDPT(ctx, name, o)
	o.Live.Stop()
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	p.Summary(r)
	s.printf("\n")
}

func (s *Shell) features(args []string) {
	name, _, ok := s.host(args, 0)
	if !ok {
		return
	}
	ctx, cancel := s.ctx()
	defer cancel()
	o := s.opts()
	o.Count = 1
	o.Live = s.live()
	r, err := dpt.RunDPT(ctx, name, o)
	o.Live.Stop()
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	for _, a := range r.Results {
		if a.Features == nil {
			continue
		}
		f := *a.Features
		yn := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		s.printf("FEATURES of %s\n", a.Address)
		s.printf("  ICMP echo          %s\n", yn(f.ICMP))
		s.printf("  DNS UDP/53         %s\n  DNS TCP/53         %s\n", yn(f.DNSUDP), yn(f.DNSTCP))
		s.printf("  recursion (RA)     %s\n", yn(f.Recursion))
		if f.EDNS0 {
			s.printf("  EDNS0              yes, UDP size %d\n", f.EDNSSize)
		} else {
			s.printf("  EDNS0              no\n")
		}
		s.printf("  DNSSEC validation  %s\n  DNS over TLS/853   %s\n", yn(f.DNSSEC), yn(f.DoT))
		if f.NTP {
			s.printf("  NTP                yes, stratum %d\n", f.Stratum)
		} else {
			s.printf("  NTP                no\n")
		}
	}
	s.printf("\n")
}

func (s *Shell) trydhcp(args []string) {
	o := s.DPT
	o.Timeout = s.timeout
	if s.iface != "" {
		o.Iface = s.iface
	}
	if len(args) > 0 {
		o.Iface = args[0]
	}
	ctx, cancel := s.ctx()
	defer cancel()
	p := dpt.NewDPTDHCPPrinter(s.out, s.Color)
	o.Live = s.live()
	o.OnDHCPSection = func(r *dpt.DPTDHCPReport, sec string) { o.Live.Out(func() { p.Section(r, sec) }) }
	r, err := dpt.RunDPTDHCP(ctx, o)
	o.Live.Stop()
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	p.Summary(r)
	s.printf("\n")
}

// chooseIface is the interface command: a name, auto, or a list to
// choose from.
func (s *Shell) chooseIface(args []string) {
	list, def := dpt.DPTIfaceList()
	if len(args) > 0 {
		if strings.EqualFold(args[0], "auto") {
			s.iface = ""
			s.printf("interface: dpt chooses (%s now)\n", def)
			return
		}
		name, err := dpt.DPTIfacePick(list, def, args[0])
		if err != nil {
			s.printf("*** %v\n", err)
			return
		}
		s.iface = name
		s.printf("interface %s\n", name)
		return
	}
	if len(list) == 0 {
		s.printf("*** no Ethernet interface is up\n")
		return
	}
	dpt.RenderIfaceList(s.out, list, def)
	if s.lr == nil {
		s.printf("(interface <name> or interface <number> chooses)\n")
		return
	}
	answer, err := s.lr.ReadLine(dpt.DPTIfacePrompt(list, def))
	if err != nil {
		s.printf("\n")
		return
	}
	name, err := dpt.DPTIfacePick(list, def, answer)
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	s.iface = name
	s.printf("interface %s\n", name)
}
