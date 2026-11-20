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
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"golang.org/x/term"
	"openipv8.org/dpt/internal/dpt"
	"openipv8.org/dpt/internal/elevate"
	"openipv8.org/dpt/internal/mel"
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
	color := !c.NoColor && !c.JSON && term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""
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

	case "info":
		r := dpt.DPTInfoGather(sysdns.Servers())
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
				code, eerr := elevate.Run(args, color)
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

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
