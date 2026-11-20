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
	smtpHost string // the last smtp host: smtp test uses it

	DPT   dpt.DPTDHCPOptions // count, names, references, timeout from the command line
	Color bool
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
	if len(servers) > 0 {
		s.initial, s.server = servers[0], servers[0]
	}
	s.sysDNS = servers
	return s
}

func (s *Shell) printf(f string, a ...any) { fmt.Fprintf(s.out, f, a...) }

// Run reads commands from in until exit or end of input.
func (s *Shell) Run(in *os.File) error {
	lr := newLineReader(in, s.out, HistoryFile())
	lr.redact = withoutPassword
	lr.complete = s.complete
	s.lr = lr
	if s.server == "" {
		s.printf("*** no DNS server found: use server <address>\n")
	} else {
		s.printf("Default server: %s\nAddress: %s\n\n", s.server, s.shown(s.server))
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

func (s *Shell) prompt() string {
	srv := s.server
	if s.srvName != "" {
		srv = s.srvName
	}
	if srv == "" {
		srv = "none"
	}
	if s.iface != "" {
		srv += " " + s.iface
	}
	return "dpt [" + srv + "]> "
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
	case cmd == "server" || cmd == "lserver":
		if len(args) != 1 {
			s.printf("usage: %s <host>\n", cmd)
			break
		}
		via := s.server
		if cmd == "lserver" {
			via = s.initial
		}
		s.setServer(args[0], via)
	case cmd == "root":
		s.server, s.srvName = rootServer, "a.root-servers.net"
		s.printf("Default server: a.root-servers.net\nAddress: %s\n\n", s.shown(rootServer))
	case cmd == "set":
		if len(args) == 0 {
			s.printf("usage: set <option>[=<value>]  (set all lists them)\n")
			break
		}
		for _, a := range args {
			s.set(a)
		}
	case strings.HasPrefix(cmd, "ntpd="):
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
		dpt.RenderDPTInfo(s.out, dpt.DPTInfoGather(s.sysDNS, s.iface), s.Color)
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
	case cmd == "outside-ip":
		s.outsideIP()
	default:
		// a lookup: <name> or <name> <server>
		if len(f) > 2 {
			s.printf("*** unknown command: %s (help lists them)\n", f[0])
			break
		}
		server := s.server
		if len(f) == 2 {
			a, err := s.resolveHost(f[1], s.server)
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
  <name>                  look up name with the current server and type
  <address>               look up the name of an address (PTR)
  <name> <server>         look up name with another server, once
  server <host>           set the default server (resolved with the current one)
  lserver <host>          set the default server (resolved with the first one)
  root                    set the default server to a root server
  set type=<T> | q=<T>    A AAAA MX NS SOA TXT CNAME PTR SRV CAA DS DNSKEY ANY ...
  set class=<C>           IN, CH (version.bind), HS
  set port=<n>  set timeout=<s>  set retry=<n>
  set [no]recurse  set [no]vc  set [no]debug  set [no]d2
  set domain=<d>  set srchlist=a/b/c  set [no]search  set [no]defname
  set all                 show the settings
  ls [-d] <domain>        zone transfer (AXFR): -d every record, else A and NS
  exit
dpt:
  ping [host] [count]     ICMP echo (default the current server, 5)
  time [host]             NTP time of host (default ntpd, else the server) against the references
  ntpd=<server>           the server time asks (set ntpd= clears it)
  trydhcp [iface]         probe the segment for DHCP servers (needs sudo / an Administrator prompt)
  info                    this machine's DHCP lease, gateway, DNS and NTP servers (sends nothing)
  interface [name|auto]   choose the interface trydhcp and info use (no name: a list to choose from)
  dpt [host]              the whole test: ping, DNS, time, features
  features [host]         what the address offers
  smtp [host]             SMTP on 25, 465, 587: greeting, STARTTLS or TLS, certificate, AUTH
  smtp [host] test <user> [password]
                          and log in: over trusted TLS when there is one, else untrusted TLS,
                          else in the clear (WARN). No host: the last smtp host; no password:
                          asked for, and never kept in the history
  sweep [ports] [network] ping the /24 around the server (or network, or this machine's),
                          25 at a time; ports: then the 50 common TCP ports of each live one
  ports [host]            the 50 common TCP ports of host (default the current server)
  outside-ip              the address the internet sees (asks ifconfig.me)
  Tab completes commands, options and names
  help, ?                 this list
`)
}

func (s *Shell) setServer(host, via string) {
	a, err := s.resolveHost(host, via)
	if err != nil {
		s.printf("*** can't find address for server %s: %v\n", host, err)
		return
	}
	s.server = a
	s.srvName = ""
	if a != host {
		s.srvName = host
	}
	s.printf("Default server: %s\nAddress: %s\n\n", host, s.shown(a))
}

// resolveHost gives host's address: itself, or an A/AAAA lookup on via.
func (s *Shell) resolveHost(host, via string) (string, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String(), nil
	}
	ctx, cancel := s.ctx()
	defer cancel()
	if via != "" {
		for _, t := range []uint16{dpt.DNSTypeA, dpt.DNSTypeAAAA} {
			a, err := dpt.DNSAsk(ctx, s.addr(via), fqdn(host), dpt.DNSAskOptions{Type: t}, s.timeout)
			if err != nil {
				continue
			}
			for _, r := range a.Answer {
				if r.Type == t {
					return net.IP(r.Data).String(), nil
				}
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
	srv := s.server
	if s.srvName != "" {
		srv = s.srvName + " (" + s.server + ")"
	}
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
	s.printf("Default server: %s\nAddress: %s\n\nSet options:\n", srv, s.shown(s.server))
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

// lookup is nslookup's plain lookup.
func (s *Shell) lookup(name, server string) {
	if server == "" {
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
	s.printf("Server:\t\t%s\nAddress:\t%s\n\n", server, s.shown(server))
	var last *dpt.DNSAnswer
	for _, n := range names {
		a, err := s.ask(ctx, server, n, t)
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
	for _, r := range a.Answer {
		s.record(r)
	}
	s.printf("\n")
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
	rs, err := dpt.DNSZoneTransfer(ctx, s.addr(s.server), fqdn(dom), s.timeout*5)
	if err != nil && len(rs) == 0 {
		s.printf("*** can't list domain %s: %v\n", dom, err)
		return
	}
	s.printf("[%s]\n", s.server)
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

// host gives the address a dpt command acts on: the argument (resolved
// with the current server) or the current server itself.
func (s *Shell) host(args []string, i int) (string, string, bool) {
	if len(args) <= i {
		if s.server == "" {
			s.printf("*** no server: give a host\n")
			return "", "", false
		}
		return s.server, s.server, true
	}
	a, err := s.resolveHost(args[i], s.server)
	if err != nil {
		s.printf("*** can't find %s: %v\n", args[i], err)
		return "", "", false
	}
	return args[i], a, true
}

func (s *Shell) opts() dpt.DPTOptions {
	o := s.DPT.DPTOptions
	o.Timeout = s.timeout
	o.Resolver = dpt.NewResolver([]string{s.server})
	return o
}

func (s *Shell) ping(args []string) {
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
		s.printf("MEL: %v\n", err)
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
		host = s.server
	}
	if host == "" {
		s.printf("*** no host, no ntpd and no server\n")
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
		s.printf("MEL: %v\n", err)
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
