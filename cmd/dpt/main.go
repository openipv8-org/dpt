// SPDX-License-Identifier: MIT

// dpt — DNS Ping Time: is this address working as a network peer?
//
//	dpt <address|dnsname> [-tdp] [options]   time, DNS and ping tests of the address
//	dpt dhcp [-td] [options]                 every DHCP server on the segment and its offer
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
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

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

	switch c.Mode {
	case "shell":
		if err := firstErr(mel.Interface(true), mel.UDP()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		cancel() // the shell handles Ctrl-C per command
		sh := shell.New(os.Stdout, sysdns.Servers(), c.Opts)
		sh.Color = color
		if err := sh.Run(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "dpt:", err)
			return exitFail
		}
		return exitOK

	case "install", "upgrade":
		return runInstall(ctx, c.Mode, args, color)

	case "info":
		r := dpt.DPTInfoGather(sysdns.Servers(), c.Opts.Iface)
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
		r, err := dpt.RunDPTDHCP(ctx, c.Opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, "MEL:", err)
			return exitMEL
		}
		if c.JSON {
			dpt.DPTJSON(os.Stdout, r)
		} else {
			dpt.RenderDPTDHCP(os.Stdout, r, color)
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
	ips, err := dpt.DPTResolve(ctx, c.Target, c.Opts.Family, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MEL:", err)
		return exitMEL
	}
	if c.Opts.Tests.Effective().Ping {
		if err := mel.ICMP(ips[0]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
	}
	r, err := dpt.RunDPT(ctx, c.Target, c.Opts.DPTOptions)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MEL:", err)
		return exitMEL
	}
	if c.JSON {
		dpt.DPTJSON(os.Stdout, r)
	} else {
		dpt.RenderDPT(os.Stdout, r, color, c.Verbose)
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
