// SPDX-License-Identifier: MIT

package shell

import (
	"context"
	"net"
	"strconv"
	"strings"

	"openipv8.org/dpt/internal/dpt"
)

// The shell's smtp, sweep, ports and outside-ip.  With no host they act
// on the current server: smtp tests it, sweep pings the /24 around it,
// ports tries its ports.

// serverName is the current server as typed (its name when it had one).
func (s *Shell) serverName() string {
	if s.srvName != "" {
		return s.srvName
	}
	return s.server
}

// smtp [host] [test <user> [<password>]] [from <address>] [to <address>];
// with no host, the last smtp host (or the current server).  smtp alone
// asks, a line at a time, what to test.
func (s *Shell) smtp(args []string) {
	const use = "usage: smtp [host] [test <user> [<password>]] [from <address>] [to <address>]\n"
	host := s.smtpHost
	if host == "" {
		host = s.serverName()
	}
	if len(args) == 0 && s.lr != nil {
		// blank is the last host smtp tested; at first, nothing
		a, err := dpt.SMTPAsk(s.smtpHost, s.lr.Ask, s.lr.ReadSecret, func(l string) { s.printf("%s\n", l) })
		if err != nil {
			s.printf("*** %v\n", err)
			return
		}
		s.printf("  (the same as: %s)\n\n", a.Command())
		s.runSMTP(a.Host, a.User, a.Password, a.From, a.To)
		return
	}
	if len(args) > 0 && !strings.EqualFold(args[0], "test") && !strings.EqualFold(args[0], "from") && !strings.EqualFold(args[0], "to") {
		host, args = args[0], args[1:]
	}
	user, pass, from, to, err := dpt.ParseSMTPWords(args)
	if err != nil {
		if err.Error() == dpt.SMTPUse {
			s.printf(use)
		} else {
			s.printf("*** %v\n", err)
		}
		return
	}
	if host == "" {
		s.printf(use)
		return
	}
	if user != "" && pass == "" {
		if s.lr == nil {
			s.printf("*** smtp test %s: give the password\n", dpt.Printable(user))
			return
		}
		p, err := s.lr.ReadSecret("password for " + dpt.Printable(user) + ": ")
		if err != nil || p == "" {
			s.printf("*** no password: nothing sent\n")
			return
		}
		pass = p
	}
	s.runSMTP(host, user, pass, from, to)
}

func (s *Shell) runSMTP(host, user, pass, from, to string) {
	s.smtpHost = host
	ctx, cancel := s.ctx()
	defer cancel()
	p := dpt.NewSMTPPrinter(s.out, s.Color, false)
	l := s.live()
	o := dpt.SMTPOptions{Resolver: s.opts().Resolver, User: user, Password: pass, From: from, To: to, Agent: s.Agent, Live: l, Family: s.DPT.Family}
	if s.DPT.Timeout > 0 {
		o.Timeout = s.DPT.Timeout
	}
	o.OnTarget = func(r *dpt.SMTPReport) { l.Out(func() { p.Target(r) }) }
	o.OnPort = func(x *dpt.SMTPPort) { l.Out(func() { p.Port(x) }) }
	o.OnLogin = func(x *dpt.SMTPLogin) { l.Out(func() { p.Login(x) }) }
	o.OnSend = func(x *dpt.SMTPSend) { l.Out(func() { p.Send(x) }) }
	r, err := dpt.RunSMTP(ctx, host, o)
	l.Stop()
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	p.Summary(r)
	s.printf("\n")
}

// sweep [ports] [network]: with no network, the /24 around the current
// server (when it is an IPv4 address off this machine), else the
// interface's network.
func (s *Shell) sweep(args []string) {
	o := dpt.SweepOptions{Iface: s.iface}
	if s.DPT.Timeout > 0 {
		o.Timeout = s.DPT.Timeout
	}
	netArg := ""
	for _, a := range args {
		switch {
		case strings.EqualFold(a, "ports") && !o.Ports:
			o.Ports = true
		case netArg == "":
			netArg = a
		default:
			s.printf("usage: sweep [ports] [network]\n")
			return
		}
	}
	if netArg == "" {
		if ip := net.ParseIP(s.server); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			netArg = s.server
		}
	}
	if netArg != "" {
		n, err := dpt.ParseSweepNetwork(netArg)
		if err != nil {
			s.printf("*** %v\n", err)
			return
		}
		o.Network = n
	}
	ctx, cancel := s.ctx()
	defer cancel()
	p := dpt.NewSweepPrinter(s.out, s.Color)
	l := s.live()
	o.Live = l
	o.OnNetwork = func(r *dpt.SweepReport) { l.Out(func() { p.Network(r) }) }
	o.OnHost = func(h *dpt.SweepHost) { l.Out(func() { p.Host(h) }) }
	r, err := dpt.RunSweep(ctx, o)
	l.Stop()
	if err != nil {
		s.printf("MEL: %v\n", err)
		return
	}
	p.Summary(r)
	s.printf("\n")
}

// ports [host] [list]: the common ports of host, or of the current
// server; or the ports in list (587,2525,8000-8010,53/udp).
func (s *Shell) ports(args []string) {
	var list []dpt.DPTPortName
	if n := len(args); n > 0 && dpt.IsPortList(args[n-1]) {
		list, _ = dpt.ParsePortList(args[n-1])
		args = args[:n-1]
	}
	if len(args) > 1 {
		s.printf("usage: ports [host] [ports]   ports: 587,2525,8000-8010,53/udp\n")
		return
	}
	name, ip, ok := s.host(args, 0)
	if !ok {
		return
	}
	if len(args) == 0 {
		name = s.serverName()
	}
	ctx, cancel := s.ctx()
	defer cancel()
	l := s.live()
	r, err := dpt.RunPorts(ctx, ip, list, 0, s.DPT.Timeout, nil, l)
	l.Stop()
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	r.Target.Input = name
	dpt.RenderPorts(s.out, r, s.Color)
	s.printf("\n")
}

func (s *Shell) outsideIP() {
	ctx, cancel := s.ctx()
	defer cancel()
	l := s.live()
	l.Set("outside", "asking "+dpt.OutsideIPURL)
	r, err := dpt.RunOutsideIP(ctx, s.DPT.Family, 0)
	l.Stop()
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	dpt.RenderOutsideIP(s.out, r, s.Color)
	s.printf("\n")
}

// withoutPassword is a line with an smtp test password taken out, for
// the history and the echo: smtp host test user secret -> smtp host test
// user.
func withoutPassword(line string) (string, bool) {
	f := strings.Fields(line)
	if len(f) == 0 || !strings.EqualFold(f[0], "smtp") {
		return line, false
	}
	for i := 1; i < len(f); i++ {
		if strings.EqualFold(f[i], "test") && len(f) > i+2 {
			return strings.Join(f[:i+2], " "), true
		}
	}
	return line, false
}

// connect [host] <port> [tls|notls]: with no host, the current server.
func (s *Shell) connect(args []string) {
	const use = "usage: connect [host] <port> [tls|notls]\n"
	o := dpt.ConnectOptions{Timeout: s.DPT.Timeout, Family: s.DPT.Family, Resolver: s.opts().Resolver}
	if n := len(args); n > 0 {
		switch strings.ToLower(args[n-1]) {
		case "tls":
			o.TLS, args = true, args[:n-1]
		case "notls":
			o.NoTLS, args = true, args[:n-1]
		}
	}
	host := s.serverName()
	switch len(args) {
	case 1:
	case 2:
		host, args = args[0], args[1:]
	default:
		s.printf(use)
		return
	}
	port, err := strconv.Atoi(args[0])
	if err != nil || port < 1 || port > 65535 || host == "" {
		s.printf(use)
		return
	}
	o.Port = port
	ctx, cancel := s.ctx()
	defer cancel()
	l := s.live()
	o.Live = l
	r, conn, err := dpt.RunConnect(ctx, host, o)
	l.Stop()
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	dpt.RenderConnect(s.out, r, s.Color)
	if conn == nil {
		s.printf("\n")
		return
	}
	defer conn.Close()
	if r.Kind == "SSH" || s.lr == nil {
		s.printf("\n")
		return
	}
	s.printf("\nconnected: what you type goes to the server, a line at a time; Ctrl-D or Ctrl-C to close\n\n")
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	why := conn.Talk(func() (string, error) { return s.lr.Ask("") }, s.out, 0)
	s.printf("\n%s\n\n", why)
}

// trace [host]: with no host, the current server.
func (s *Shell) trace(args []string) {
	if len(args) > 1 {
		s.printf("usage: trace [host]\n")
		return
	}
	name, ip, ok := s.host(args, 0)
	if !ok {
		return
	}
	if len(args) == 0 {
		name = s.serverName()
	}
	ctx, cancel := s.ctx()
	defer cancel()
	l := s.live()
	r, err := dpt.RunTrace(ctx, ip, dpt.TraceOptions{Family: s.DPT.Family, Timeout: 0, Live: l})
	l.Stop()
	if err != nil {
		s.printf("*** %v\n", err)
		return
	}
	r.Target.Input = name
	dpt.RenderTrace(s.out, r, s.Color)
	s.printf("\n")
}
