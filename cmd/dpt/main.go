// SPDX-License-Identifier: MIT

// DPT — Diagnostic Ports Time: is this address working as a network
// peer, and what is on the way to it?
//
//	dpt <address|dnsname> [-tdp] [options]   time, DNS and ping tests of the address
//	dpt dhcp [-td] [options]                 every DHCP server on the segment and its offer
//	dpt smtp <host> [test <user> [<pw>]] [from <a>] [to <a>]   SMTP ports 25, 465, 587, a login, a test message
//	dpt sweep [ports] [<network>]            live addresses (and their open ports)
//	dpt ports <host> [<ports>]               the common TCP and UDP ports of host
//	dpt connect <host> <port> [tls|notls]    connect, see what it says, type to it
//	dpt trace <host>                         the routers on the way
//	dpt outside-ip                           the address the internet sees
//	dpt                                      interactive shell: nslookup and more
//
// Test letters go together (t time, d DNS, p ping; none: all three).
// Options are written the way the system writes them: -tdp -c 3 -w 2 on
// Linux and macOS, /tdp /c:3 /w:2 on Windows.
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"
	"openipv8.org/dpt/internal/dpt"
	"openipv8.org/dpt/internal/elevate"
	"openipv8.org/dpt/internal/mel"
	"openipv8.org/dpt/internal/selfinstall"
	"openipv8.org/dpt/internal/shell"
	"openipv8.org/dpt/internal/sysdns"
)

var version = "dev"

// Exit codes.
const (
	exitOK    = 0
	exitFail  = 1
	exitMEL   = 2
	exitUsage = 3
)

func style() dpt.DPTArgStyle {
	if runtime.GOOS == "windows" {
		return dpt.DPTStyleWindows
	}
	return dpt.DPTStyleUnix
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	// the elevated copy on Windows: its output goes back to the window the
	// command was typed in
	relayed, relayColor := false, false
	if len(args) > 0 && strings.HasPrefix(args[0], elevate.RelayFlag) {
		c, err := elevate.Relay(strings.TrimPrefix(args[0], elevate.RelayFlag))
		if err != nil {
			return exitMEL
		}
		relayed, relayColor, args = true, c, args[1:]
	}
	st := style()
	c, err := dpt.ParseDPTArgs(args, st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpt: %v\n\n%s", err, dpt.DPTUsage(st, "dpt"))
		return exitUsage
	}
	switch c.Mode {
	case "help":
		fmt.Print(dpt.DPTUsage(st, "dpt"))
		return exitOK
	case "version":
		fmt.Printf("dpt %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return exitOK
	}
	if c.Select {
		// choose the interface from a list; never from a script
		if !elevate.Interactive() {
			fmt.Fprintf(os.Stderr, "dpt: %s needs a terminal to choose at: use %s\n", optName(st, "select"), optName(st, "iface"))
			return exitUsage
		}
		list, def := dpt.DPTIfaceList()
		if len(list) == 0 {
			fmt.Fprintln(os.Stderr, "MEL: no Ethernet interface is up")
			return exitMEL
		}
		dpt.RenderIfaceList(os.Stdout, list, def)
		fmt.Print(dpt.DPTIfacePrompt(list, def))
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		name, err := dpt.DPTIfacePick(list, def, answer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitUsage
		}
		c.Opts.Iface = name
		// a run again under sudo takes the choice, not the question
		args = withIface(args, st, name)
	}
	vt := enableVT() // Windows: the console must be told to read escape sequences
	color := vt && !c.NoColor && !c.JSON && term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""
	if relayed {
		color = relayColor && !c.NoColor && !c.JSON
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	// the status line while dpt works: only for a person watching
	live := func() *dpt.Live {
		if c.JSON {
			return nil
		}
		if relayed {
			if relayColor {
				return dpt.NewLive(os.Stderr, 80)
			}
			return nil
		}
		fd := int(os.Stderr.Fd())
		if !vt && runtime.GOOS == "windows" || !term.IsTerminal(fd) {
			return nil
		}
		w, _, err := term.GetSize(fd)
		if err != nil {
			w = 80
		}
		return dpt.NewLive(os.Stderr, w)
	}

	switch c.Mode {
	case "shell":
		if err := firstErr(mel.Interface(true), mel.UDP()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		cancel() // the shell handles Ctrl-C per command
		sh := shell.New(os.Stdout, sysdns.Servers(), c.Opts)
		sh.Color = color
		sh.Agent = "dpt " + version
		sh.NewLive = live
		if err := sh.Run(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitFail
		}
		return exitOK

	case "install", "upgrade":
		return runInstall(ctx, c.Mode, args, color)

	case "smtp", "sweep", "ports", "outside-ip", "connect", "trace":
		if err := mel.Interface(true); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		return runNet(ctx, c, color, live)

	case "info":
		// the outside addresses: asked now, shown last, waited for no
		// more than DPTOutsideWait from here
		outside := dpt.StartOutside(ctx, c.Opts.Family, time.Now().Add(dpt.DPTOutsideWait))
		r := dpt.DPTInfoGather(sysdns.Servers(), c.Opts.Iface)
		l := live()
		dpt.DPTInfoTime(ctx, r, c.Opts.NTP, c.Opts.Timeout, l)
		l.Set("outside", "asking "+dpt.OutsideIPURL)
		r.Outside = outside()
		l.Stop()
		if c.JSON {
			dpt.DPTJSON(os.Stdout, r)
		} else {
			dpt.RenderDPTInfo(os.Stdout, r, color)
		}
		return exitOK

	case "dhcp":
		if err := firstErr(mel.Interface(false), mel.DHCP(c.Opts.Iface), mel.UDP()); err != nil {
			// typed by a person: ask for the privilege (sudo, UAC); from
			// a script: never ask, say what it needs
			if mel.NeedsPrivilege(err) && !relayed && elevate.Possible() && elevate.Interactive() {
				code, eerr := elevate.Run("dhcp", args, color)
				if eerr == nil {
					return code
				}
				fmt.Fprintf(os.Stderr, "%v (%v)\n", err, eerr)
				return exitMEL
			}
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		o := c.Opts
		p := dpt.NewDPTDHCPPrinter(os.Stdout, color)
		if !c.JSON {
			o.Live = live()
			o.OnDHCPSection = func(r *dpt.DPTDHCPReport, sec string) { o.Live.Out(func() { p.Section(r, sec) }) }
		}
		r, err := dpt.RunDPTDHCP(ctx, o)
		o.Live.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "MEL:", err)
			return exitMEL
		}
		if c.JSON {
			dpt.DPTJSON(os.Stdout, r)
		} else {
			p.Summary(r)
		}
		if r.Failed() {
			return exitFail
		}
		return exitOK
	}

	// dpt <address|name>
	if err := firstErr(mel.Interface(true), mel.UDP()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitMEL
	}
	o := c.Opts.DPTOptions
	p := dpt.NewDPTPrinter(os.Stdout, color, c.Verbose)
	if !c.JSON {
		o.Live = live()
		o.OnTarget = func(t dpt.DPTTarget) { o.Live.Out(func() { p.Target(t) }) }
		o.OnSection = func(a *dpt.DPTAddrReport, sec string) { o.Live.Out(func() { p.Section(a, sec) }) }
	}
	defer o.Live.Stop()
	o.Live.Set("resolve", "looking up "+c.Target)
	ips, err := dpt.DPTResolve(ctx, c.Target, c.Opts.Family, nil)
	o.Live.Drop("resolve")
	if err != nil {
		o.Live.Stop()
		fmt.Fprintln(os.Stderr, "MEL:", err)
		return exitMEL
	}
	if c.Opts.Tests.Effective().Ping {
		if err := mel.ICMP(ips[0]); err != nil {
			o.Live.Stop()
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
	}
	r, err := dpt.RunDPT(ctx, c.Target, o)
	o.Live.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "MEL:", err)
		return exitMEL
	}
	if c.JSON {
		dpt.DPTJSON(os.Stdout, r)
	} else {
		p.Summary(r)
	}
	if r.Failed() {
		return exitFail
	}
	return exitOK
}

// runInstall is dpt install and dpt upgrade.
func runInstall(ctx context.Context, mode string, args []string, color bool) int {
	dest := selfinstall.Dest()
	// nothing to write: say so, and ask for no privilege
	var latest, have, self string
	switch mode {
	case "install":
		var err error
		if self, err = os.Executable(); err != nil {
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitFail
		}
		if selfinstall.SameFile(self, dest) {
			fmt.Printf("dpt %s is installed: %s\n", version, dest)
			return exitOK
		}
	case "upgrade":
		var err error
		fmt.Println("checking the newest release on github.com/" + selfinstall.Repo + " ...")
		if latest, err = selfinstall.LatestTag(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "dpt: cannot find the newest release:", err)
			return exitFail
		}
		have, err = selfinstall.InstalledVersion(dest)
		if err != nil {
			// never overwrite what might be newer
			fmt.Fprintf(os.Stderr, "dpt: %s %v: not replacing it (dpt install puts this dpt there)\n", dest, err)
			return exitFail
		}
		if have != "" && !selfinstall.Newer(latest, have) {
			fmt.Printf("dpt %s at %s is up to date (newest release %s)\n", have, dest, latest)
			return exitOK
		}
	}
	if !selfinstall.Writable(dest) {
		// typed by a person: ask for the privilege; from a script: never
		if elevate.Possible() && elevate.Interactive() {
			code, err := elevate.Run(mode, args, color)
			if err == nil {
				return code
			}
			fmt.Fprintf(os.Stderr, "MEL: %s needs %s (%v)\n", mode, dpt.DHCPNeeds, err)
			return exitMEL
		}
		fmt.Fprintf(os.Stderr, "MEL: %s needs %s (to write %s)\n", mode, dpt.DHCPNeeds, filepath.Dir(dest))
		return exitMEL
	}
	switch mode {
	case "install":
		if err := selfinstall.Install(self, dest); err != nil {
			fmt.Fprintln(os.Stderr, "dpt: install:", err)
			return exitFail
		}
		fmt.Printf("installed dpt %s: %s\n", version, dest)
	case "upgrade":
		file, err := selfinstall.Download(ctx, latest, filepath.Dir(dest), os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dpt: upgrade:", err)
			return exitFail
		}
		defer os.Remove(file)
		if err := selfinstall.Install(file, dest); err != nil {
			fmt.Fprintln(os.Stderr, "dpt: upgrade:", err)
			return exitFail
		}
		if have == "" {
			have = "none"
		}
		fmt.Printf("upgraded %s: %s -> %s\n", dest, have, latest)
	}
	if added, err := selfinstall.AddToPath(filepath.Dir(dest)); err != nil {
		fmt.Fprintf(os.Stderr, "dpt: could not add %s to PATH: %v\n", filepath.Dir(dest), err)
	} else if added {
		fmt.Printf("added %s to PATH: open a new window to use plain dpt\n", filepath.Dir(dest))
	}
	return exitOK
}

// optName writes an option the way this system does.
func optName(st dpt.DPTArgStyle, name string) string {
	if st == dpt.DPTStyleWindows {
		return "/" + name
	}
	return "--" + name
}

// withIface is args with the select option replaced by the chosen iface.
func withIface(args []string, st dpt.DPTArgStyle, name string) []string {
	var out []string
	for _, a := range args {
		if strings.EqualFold(a, optName(st, "select")) {
			continue
		}
		out = append(out, a)
	}
	if st == dpt.DPTStyleWindows {
		return append(out, "/iface:"+name)
	}
	return append(out, "--iface", name)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// runNet is smtp, sweep, ports, connect, trace and outside-ip.
func runNet(ctx context.Context, c *dpt.DPTCommand, color bool, live func() *dpt.Live) int {
	out := func(v any, text func()) int {
		if c.JSON {
			dpt.DPTJSON(os.Stdout, v)
		} else {
			text()
		}
		return exitOK
	}
	var l *dpt.Live
	if !c.JSON {
		l = live()
	}
	defer l.Stop()
	switch c.Mode {
	case "smtp":
		if c.Target == "" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintln(os.Stderr, "dpt: smtp prompt asks at a terminal:", dpt.SMTPUse)
				return exitUsage
			}
			l.Stop()
			a, err := askSMTP()
			if err != nil {
				fmt.Fprintln(os.Stderr, "dpt:", err)
				return exitUsage
			}
			fmt.Fprintf(os.Stderr, "  (the same as: dpt %s)\n\n", a.Command())
			c.Target, c.SMTPUser, c.SMTPPassword, c.SMTPFrom, c.SMTPTo = a.Host, a.User, a.Password, a.From, a.To
			if !c.JSON {
				l = live() // the status line, stopped while asking
				defer l.Stop()
			}
		}
		o := dpt.SMTPOptions{Timeout: c.Opts.Timeout, Family: c.Opts.Family, User: c.SMTPUser, Password: c.SMTPPassword,
			From: c.SMTPFrom, To: c.SMTPTo, Agent: "dpt " + version}
		if o.User != "" && o.Password == "" {
			pw, err := readPassword(c.SMTPUser)
			if err != nil {
				fmt.Fprintln(os.Stderr, "dpt:", err)
				return exitUsage
			}
			o.Password = pw
		}
		p := dpt.NewSMTPPrinter(os.Stdout, color, c.Verbose)
		if !c.JSON {
			o.Live = l
			o.OnTarget = func(r *dpt.SMTPReport) { l.Out(func() { p.Target(r) }) }
			o.OnPort = func(x *dpt.SMTPPort) { l.Out(func() { p.Port(x) }) }
			o.OnLogin = func(x *dpt.SMTPLogin) { l.Out(func() { p.Login(x) }) }
			o.OnSend = func(x *dpt.SMTPSend) { l.Out(func() { p.Send(x) }) }
		}
		r, err := dpt.RunSMTP(ctx, c.Target, o)
		l.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "MEL:", err)
			return exitMEL
		}
		out(r, func() { p.Summary(r) })
		if r.Failed() {
			return exitFail
		}
		return exitOK

	case "sweep":
		if err := mel.ICMP(net.IPv4(127, 0, 0, 1)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		o := dpt.SweepOptions{Iface: c.Opts.Iface, Ports: c.SweepPorts, Timeout: c.Opts.Timeout}
		if c.SweepNetwork != "" {
			o.Network, _ = dpt.ParseSweepNetwork(c.SweepNetwork)
		}
		p := dpt.NewSweepPrinter(os.Stdout, color)
		if !c.JSON {
			o.Live = l
			o.OnNetwork = func(r *dpt.SweepReport) { l.Out(func() { p.Network(r) }) }
			o.OnHost = func(h *dpt.SweepHost) { l.Out(func() { p.Host(h) }) }
		}
		r, err := dpt.RunSweep(ctx, o)
		l.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "MEL:", err)
			return exitMEL
		}
		return out(r, func() { p.Summary(r) })

	case "ports":
		r, err := dpt.RunPorts(ctx, c.Target, c.PortList, c.Opts.Family, c.Opts.Timeout, nil, l)
		l.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "MEL:", err)
			return exitMEL
		}
		return out(r, func() { dpt.RenderPorts(os.Stdout, r, color) })

	case "connect":
		r, conn, err := dpt.RunConnect(ctx, c.Target, dpt.ConnectOptions{Port: c.ConnectPort, TLS: c.ConnectTLS, NoTLS: c.NoTLS,
			Timeout: c.Opts.Timeout, Family: c.Opts.Family, Live: l})
		l.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "MEL:", err)
			return exitMEL
		}
		out(r, func() { dpt.RenderConnect(os.Stdout, r, color) })
		if conn == nil {
			return exitFail
		}
		defer conn.Close()
		// at a terminal: what is typed goes to the server; from a pipe:
		// its lines do (printf 'GET / HTTP/1.0\n\n' | dpt connect host 80).
		// Not SSH: there is nothing to say to it by hand.
		tty := term.IsTerminal(int(os.Stdin.Fd()))
		if c.JSON || r.Kind == "SSH" || !tty && !stdinHasData() {
			return exitOK
		}
		linger := time.Duration(0)
		if tty {
			eof := "Ctrl-D"
			if runtime.GOOS == "windows" {
				eof = "Ctrl-Z then Enter"
			}
			fmt.Fprintf(os.Stderr, "\nconnected: what you type goes to the server, a line at a time; %s or Ctrl-C to close\n\n", eof)
		} else {
			linger = 5 * time.Second
			fmt.Println()
		}
		in := bufio.NewReader(os.Stdin)
		stop := context.AfterFunc(ctx, func() { conn.Close() }) // Ctrl-C closes it
		defer stop()
		why := conn.Talk(func() (string, error) {
			l, err := in.ReadString('\n')
			if err != nil {
				return "", err
			}
			return strings.TrimRight(l, "\r\n"), nil
		}, os.Stdout, linger)
		fmt.Fprintf(os.Stderr, "\n%s\n", why)
		return exitOK

	case "trace":
		if err := mel.ICMP(net.IPv4(127, 0, 0, 1)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		r, err := dpt.RunTrace(ctx, c.Target, dpt.TraceOptions{Family: c.Opts.Family, Live: l})
		l.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "MEL:", err)
			return exitMEL
		}
		out(r, func() { dpt.RenderTrace(os.Stdout, r, color) })
		if r.Status == dpt.DPTFail {
			return exitFail
		}
		return exitOK

	default: // outside-ip
		l.Set("outside", "asking "+dpt.OutsideIPURL)
		r, err := dpt.RunOutsideIP(ctx, c.Opts.Family, c.Opts.Timeout)
		l.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitFail
		}
		return out(r, func() { dpt.RenderOutsideIP(os.Stdout, r, color) })
	}
}

// stdinHasData: stdin is a pipe or a file, not /dev/null or a console
// left behind.
func stdinHasData() bool {
	st, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	m := st.Mode()
	return m&os.ModeNamedPipe != 0 || m.IsRegular() && st.Size() > 0
}

// askSMTP asks at the terminal what smtp is to test, offering the last
// answers (kept in .dpt).
func askSMTP() (dpt.SMTPAsked, error) {
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		l, err := in.ReadString('\n')
		if err != nil {
			fmt.Fprintln(os.Stderr)
			return "", err
		}
		return strings.TrimRight(l, "\r\n"), nil
	}
	secret := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	a, err := dpt.SMTPAsk("", dpt.LoadSMTPAsked(), ask, secret, func(l string) { fmt.Fprintln(os.Stderr, l) })
	if err == nil {
		// offered next time
		if err := dpt.SaveSMTPAsked(a); err != nil {
			fmt.Fprintln(os.Stderr, "dpt: the answers were not kept for next time:", err)
		}
	}
	return a, err
}

// readPassword asks for the password with no echo on a terminal; from a
// pipe it is the first line.
func readPassword(user string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprintf(os.Stderr, "password for %s: ", dpt.Printable(user))
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	l, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if l = strings.TrimRight(l, "\r\n"); l == "" {
		if err == nil {
			err = fmt.Errorf("no password")
		}
		return "", fmt.Errorf("smtp test %s: give the password, or type it at a terminal (%v)", dpt.Printable(user), err)
	}
	return l, nil
}
