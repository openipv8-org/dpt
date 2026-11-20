// SPDX-License-Identifier: MIT

package shell

import (
	"net"
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

// smtp [host] [test <user> [<password>]], or smtp test <user> [<password>]
// on the last smtp host.
func (s *Shell) smtp(args []string) {
	const use = "usage: smtp [host] [test <user> [<password>]]\n"
	host := s.smtpHost
	if host == "" {
		host = s.serverName()
	}
	if len(args) > 0 && !strings.EqualFold(args[0], "test") {
		host, args = args[0], args[1:]
	}
	user, pass := "", ""
	if len(args) > 0 {
		if !strings.EqualFold(args[0], "test") || len(args) < 2 || len(args) > 3 {
			s.printf(use)
			return
		}
		user = args[1]
		if len(args) == 3 {
			pass = args[2]
		}
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
	s.smtpHost = host
	ctx, cancel := s.ctx()
	defer cancel()
	p := dpt.NewSMTPPrinter(s.out, s.Color, false)
	l := s.live()
	o := dpt.SMTPOptions{Resolver: s.opts().Resolver, User: user, Password: pass, Live: l, Family: s.DPT.Family}
	if s.DPT.Timeout > 0 {
		o.Timeout = s.DPT.Timeout
	}
	o.OnTarget = func(r *dpt.SMTPReport) { l.Out(func() { p.Target(r) }) }
	o.OnPort = func(x *dpt.SMTPPort) { l.Out(func() { p.Port(x) }) }
	o.OnLogin = func(x *dpt.SMTPLogin) { l.Out(func() { p.Login(x) }) }
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

// ports [host]: the common TCP ports of host, or of the current server.
func (s *Shell) ports(args []string) {
	if len(args) > 1 {
		s.printf("usage: ports [host]\n")
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
	r, err := dpt.RunPorts(ctx, ip, 0, s.DPT.Timeout, nil, l)
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
