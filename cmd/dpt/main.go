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
//	dpt whois <address|network|AS|domain> [<server>] [both]   who holds it, by whois (port 43)
//	dpt rdap <address|network|AS|domain> [<server>]   who holds it, by RDAP
//	dpt time native [sync [fix]]             the system's own time tools, a resync, set to keep in sync
//	dpt                                      interactive shell: nslookup and more
//
// Test letters go together (t time, d DNS, p ping; none: all three).
// Options are written the way the system writes them: -tdp -c 3 -w 2 on
// Linux and macOS, /tdp /c:3 /w:2 on Windows.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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
	"openipv8.org/dpt/internal/timenative"
	"openipv8.org/dpt/man"
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
			fmt.Fprintln(os.Stderr, "dpt: no Ethernet interface is up")
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
		// the download itself (dpt-windows-amd64.exe, dpt-darwin-arm64...)
		// started with nothing after it: install it
		if len(args) == 0 && !relayed && selfinstall.IsDownloadName(os.Args[0]) && !installedByManager() {
			return autoInstall(ctx, color)
		}
		if err := firstErr(mel.Interface(true), mel.UDP()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		cancel() // the shell handles Ctrl-C per command
		sh := shell.New(os.Stdout, sysdns.Servers(), c.Opts)
		sh.Color = color
		sh.Agent = "dpt " + version
		sh.NewLive = live
		sh.TimeNative = func(ctx context.Context, words []string, wait func(string) error) int {
			a := append([]string{"time"}, words...)
			tc, err := dpt.ParseDPTArgs(a, st)
			if err != nil {
				fmt.Fprintln(os.Stdout, "***", err)
				return exitUsage
			}
			return timeNative(ctx, tc, a, color, false, wait)
		}
		if err := sh.Run(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitFail
		}
		return exitOK

	case "install", "upgrade":
		return runInstall(ctx, c.Mode, args, color)

	case "time":
		if c.TimeNative {
			return runTimeNative(ctx, c, args, color, relayed)
		}
		// time [<host>]: this clock (and host's NTP) against the references
		if err := firstErr(mel.Interface(true), mel.UDP()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		o := c.Opts.DPTOptions
		if !c.JSON {
			o.Live = live()
		}
		var extra []dpt.DPTTimeAsk
		if c.Target != "" {
			extra = []dpt.DPTTimeAsk{{Server: c.Target, Role: "target"}}
		}
		t := dpt.DPTTimeRun(ctx, extra, o)
		o.Live.Stop()
		if c.JSON {
			dpt.DPTJSON(os.Stdout, t)
		} else {
			dpt.RenderDPTTime(os.Stdout, t, color)
		}
		if t.Status == dpt.DPTFail {
			return exitFail
		}
		return exitOK

	case "smtp", "sweep", "ports", "outside-ip", "connect", "trace", "whois", "rdap":
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
			fmt.Fprintln(os.Stderr, "dpt:", err)
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
		fmt.Fprintln(os.Stderr, "dpt:", err)
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
		fmt.Fprintln(os.Stderr, "dpt:", err)
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
	// a package manager's dpt: upgrade runs the manager, install leaves it
	if exe, err := os.Executable(); err == nil {
		if m := selfinstall.Manager(exe); m != "" {
			cmd := selfinstall.ManagerUpgrade(m)
			if mode == "install" {
				fmt.Printf("dpt %s is installed by %s (%s): %s keeps it up to date\n", version, m, exe, strings.Join(cmd, " "))
				return exitOK
			}
			fmt.Printf("dpt %s was installed by %s: running %s\n", version, m, strings.Join(cmd, " "))
			x := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
			x.Stdin, x.Stdout, x.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := x.Run(); err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return ee.ExitCode()
				}
				fmt.Fprintf(os.Stderr, "dpt: %s: %v\n", cmd[0], err)
				return exitFail
			}
			return exitOK
		}
	}
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
		if selfinstall.SameFile(self, dest) && selfinstall.ManCurrent(man.Page) {
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
	if !selfinstall.Writable(dest) || mode == "install" && selfinstall.ManPath() != "" && !selfinstall.Writable(selfinstall.ManPath()) {
		// typed by a person: ask for the privilege; from a script: never
		if elevate.Possible() && elevate.Interactive() {
			code, err := elevate.Run(mode, args, color)
			if err == nil {
				return code
			}
			fmt.Fprintf(os.Stderr, "dpt: %s needs %s (%v)\n", mode, dpt.DHCPNeeds, err)
			return exitMEL
		}
		fmt.Fprintf(os.Stderr, "dpt: %s needs %s (to write %s)\n", mode, dpt.DHCPNeeds, filepath.Dir(dest))
		return exitMEL
	}
	switch mode {
	case "install":
		if selfinstall.SameFile(self, dest) {
			fmt.Printf("dpt %s is installed: %s\n", version, dest)
		} else {
			if err := selfinstall.Install(self, dest); err != nil {
				fmt.Fprintln(os.Stderr, "dpt: install:", err)
				return exitFail
			}
			fmt.Printf("installed dpt %s: %s\n", version, dest)
		}
		if !selfinstall.ManCurrent(man.Page) {
			if err := selfinstall.InstallMan(man.Page); err != nil {
				fmt.Fprintf(os.Stderr, "dpt: the manual page was not installed: %v\n", err)
			} else {
				fmt.Printf("installed the manual page: %s (man dpt)\n", selfinstall.ManPath())
			}
		}
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
		// the new dpt puts its own manual page in place
		if selfinstall.ManPath() != "" {
			x := exec.CommandContext(ctx, dest, "install")
			x.Stdout, x.Stderr = os.Stdout, os.Stderr
			x.Run()
		}
	}
	if added, err := selfinstall.AddToPath(filepath.Dir(dest)); err != nil {
		fmt.Fprintf(os.Stderr, "dpt: could not add %s to PATH: %v\n", filepath.Dir(dest), err)
	} else if added {
		fmt.Printf("added %s to PATH: open a new window to use plain dpt\n", filepath.Dir(dest))
	}
	return exitOK
}

// installedByManager: this dpt is a package manager's (winget's).
func installedByManager() bool {
	exe, err := os.Executable()
	return err == nil && selfinstall.Manager(exe) != ""
}

// autoInstall is the download started with no command: install it where
// the system finds it, unless the same or a newer dpt is there; then say
// how to use it (on Windows, where a double-click's window closes at
// once, wait for Enter).
func autoInstall(ctx context.Context, color bool) int {
	code := func() int {
		dest := selfinstall.Dest()
		fmt.Printf("dpt %s: this is the download, so it installs itself (%s)\n", version, dest)
		have, err := selfinstall.InstalledVersion(dest)
		if err == nil && have != "" && !selfinstall.Newer(version, have) {
			fmt.Printf("dpt %s is already installed at %s: nothing changed\n", have, dest)
			return exitOK
		}
		return runInstall(ctx, "install", []string{"install"}, color)
	}()
	if code == exitOK {
		fmt.Println("\nto use it: open a new terminal and type dpt")
	}
	if runtime.GOOS == "windows" && elevate.Interactive() {
		fmt.Print("\npress Enter to close ")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	return code
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

// runNet is smtp, sweep, ports, connect, trace, whois and outside-ip.
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
			fmt.Fprintln(os.Stderr, "dpt:", err)
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
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitMEL
		}
		return out(r, func() { p.Summary(r) })

	case "ports":
		r, err := dpt.RunPorts(ctx, c.Target, c.PortList, c.Opts.Family, c.Opts.Timeout, nil, l)
		l.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitMEL
		}
		return out(r, func() { dpt.RenderPorts(os.Stdout, r, color) })

	case "connect":
		r, conn, err := dpt.RunConnect(ctx, c.Target, dpt.ConnectOptions{Port: c.ConnectPort, TLS: c.ConnectTLS, NoTLS: c.NoTLS,
			Timeout: c.Opts.Timeout, Family: c.Opts.Family, Live: l})
		l.Stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, "dpt:", err)
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
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitMEL
		}
		out(r, func() { dpt.RenderTrace(os.Stdout, r, color) })
		if r.Status == dpt.DPTFail {
			return exitFail
		}
		return exitOK

	case "whois", "rdap":
		more := "--verbose"
		if runtime.GOOS == "windows" {
			more = "/verbose"
		}
		o := dpt.WhoisOptions{Timeout: c.Opts.Timeout, Family: c.Opts.Family, Agent: "dpt " + version, Server: c.WhoisServer, Live: l}
		rs, errs := lookups(ctx, c, o)
		l.Stop()
		if c.JSON {
			if c.WhoisBoth {
				dpt.DPTJSON(os.Stdout, map[string]any{"whois": rs[0], "rdap": rs[1], "errors": errs})
			} else if rs[0] != nil {
				dpt.DPTJSON(os.Stdout, rs[0])
			}
		}
		found := false
		for i, r := range rs {
			if errs[i] != "" {
				fmt.Fprintln(os.Stderr, "dpt:", errs[i])
				continue
			}
			if !c.JSON {
				if i > 0 {
					fmt.Println()
				}
				dpt.RenderWhois(os.Stdout, r, color, c.Verbose, more, "dpt ")
			}
			found = found || r.Found || r.Special != ""
		}
		if !found {
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

// runTimeNative is time native [sync [fix]]: each command shown, run on
// Enter.  On Windows the Administrator commands run in a copy of dpt that
// UAC starts (dpt-steps=a-b), its output relayed here.
func runTimeNative(ctx context.Context, c *dpt.DPTCommand, args []string, color, relayed bool) int {
	var wait func(string) error
	if elevate.Interactive() && !relayed {
		in := bufio.NewReader(os.Stdin)
		wait = func(prompt string) error {
			fmt.Fprint(os.Stdout, prompt)
			got := make(chan error, 1)
			go func() { _, err := in.ReadString('\n'); got <- err }()
			select {
			case err := <-got:
				return err
			case <-ctx.Done():
				fmt.Fprintln(os.Stdout)
				return timenative.ErrStopped
			}
		}
	}
	return timeNative(ctx, c, args, color, relayed, wait)
}

// timeNative runs the plan c asks for; wait waits for Enter (nil: never).
func timeNative(ctx context.Context, c *dpt.DPTCommand, args []string, color, relayed bool, wait func(string) error) int {
	e := timenative.Detect()
	p := timenative.Status(e)
	switch {
	case c.TimeFix:
		p = timenative.Fix(e)
	case c.TimeSync:
		p = timenative.Sync(e)
	}
	o := timenative.Options{Out: os.Stdout, Color: color, From: c.TimeFrom, To: c.TimeTo,
		Elevated: !elevate.Possible() || relayed, Wait: wait}
	if runtime.GOOS == "windows" && !o.Elevated {
		o.Elevate = func(from, to int) (int, error) {
			a := append(append([]string{}, args...), fmt.Sprintf("dpt-steps=%d-%d", from, to))
			return elevate.Run(p.What, a, color)
		}
	}
	return timenative.Run(ctx, p, o)
}

// lookups runs whois, rdap, or (whois both) the two; errs[i] is why
// rs[i] is missing.
func lookups(ctx context.Context, c *dpt.DPTCommand, o dpt.WhoisOptions) ([]*dpt.WhoisReport, []string) {
	run := []func(context.Context, string, dpt.WhoisOptions) (*dpt.WhoisReport, error){dpt.RunWhois}
	switch {
	case c.Mode == "rdap":
		run = run[:0]
		run = append(run, dpt.RunRDAP)
	case c.WhoisBoth:
		run = append(run, dpt.RunRDAP)
	}
	rs, errs := make([]*dpt.WhoisReport, len(run)), make([]string, len(run))
	for i, f := range run {
		r, err := f(ctx, c.Target, o)
		rs[i] = r
		if err != nil {
			errs[i] = err.Error()
		}
	}
	return rs, errs
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
