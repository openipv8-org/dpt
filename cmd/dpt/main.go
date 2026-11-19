// SPDX-License-Identifier: MIT

// dpt — DNS Ping Time: is this address working as a network peer?
//
//	dpt <address|dnsname> [-tdp] [options]   time, DNS and ping tests of the address
//	dpt dhcp [-td] [options]                 every DHCP server on the segment and its offer
//	dpt                                      interactive shell: nslookup and more
//
// Test letters go together (t time, d DNS, p ping; none: all three).
// Options are written the way the system writes them: -tdp -c 3 -w 2 on
// Linux and macOS, /tdp /c:3 /w:2 on Windows.  The work is done by concomm, the same
// code as the console's dpt command.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"golang.org/x/term"
	"openipv8.org/concomm"
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

func style() concomm.DPTArgStyle {
	if runtime.GOOS == "windows" {
		return concomm.DPTStyleWindows
	}
	return concomm.DPTStyleUnix
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	st := style()
	c, err := concomm.ParseDPTArgs(args, st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dpt: %v\n\n%s", err, concomm.DPTUsage(st, "dpt"))
		return exitUsage
	}
	switch c.Mode {
	case "help":
		fmt.Print(concomm.DPTUsage(st, "dpt"))
		return exitOK
	case "version":
		fmt.Printf("dpt %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return exitOK
	}
	color := !c.NoColor && !c.JSON && term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""
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

	case "dhcp":
		if err := firstErr(mel.Interface(false), mel.DHCP(c.Opts.Iface), mel.UDP()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitMEL
		}
		r, err := concomm.RunDPTDHCP(ctx, c.Opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, "MEL:", err)
			return exitMEL
		}
		if c.JSON {
			concomm.DPTJSON(os.Stdout, r)
		} else {
			concomm.RenderDPTDHCP(os.Stdout, r, color)
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
	ips, err := concomm.DPTResolve(ctx, c.Target, c.Opts.Family, nil)
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
	r, err := concomm.RunDPT(ctx, c.Target, c.Opts.DPTOptions)
	if err != nil {
		fmt.Fprintln(os.Stderr, "MEL:", err)
		return exitMEL
	}
	if c.JSON {
		concomm.DPTJSON(os.Stdout, r)
	} else {
		concomm.RenderDPT(os.Stdout, r, color, c.Verbose)
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
