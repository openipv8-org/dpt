// SPDX-License-Identifier: MIT

package dpt

import (
	"fmt"
	"io"
	"strings"
)

// RenderWhois writes what whois found:
//
//	WHOIS     1.1.1.1
//	SOURCE    RDAP  APNIC  rdap.apnic.net  in 412 ms
//	HOLDER    APNIC Research and Development
//	NETWORK   APNIC-LABS  1.1.1.0 - 1.1.1.255  1.1.1.0/24  AU
//	ABUSE     helpdesk@apnic.net
//	DATES     registered 2011-08-10   changed 2023-04-26
//
// verbose adds every contact and remark, and a whois answer's text;
// without it, a last line says so, naming more (--verbose, /verbose).
func RenderWhois(w io.Writer, r *WhoisReport, color, verbose bool, more string) {
	o := dptOut{w: w, color: color} // one block: no blank line between sections
	head := o.bold(r.Query)
	if r.Asked != "" && !strings.EqualFold(r.Asked, r.Query) {
		head += o.dim("  asked as " + r.Asked)
	}
	o.line("WHOIS", head)

	if r.Special != "" {
		o.line("RANGE", r.Special)
		o.line("", o.dim("no registry holds it, so none was asked"))
		return
	}

	src := o.bold(r.Source)
	if r.Registry != "" {
		src += "  " + r.Registry
	}
	src += "  " + r.Server
	if r.Related != "" && r.RelatedWhy == "" {
		src += o.dim(", then the registrar's " + r.Related)
	}
	src += o.dim("  in " + took(r.Elapsed))
	o.line("SOURCE", src)
	if r.Related != "" && r.RelatedWhy != "" {
		o.line("", o.dim("the registrar's RDAP, "+r.Related+": ")+o.yellow(r.RelatedWhy))
	}
	if r.Chosen {
		o.line("", o.dim("the server given, asked directly (not the one IANA lists)"))
	}
	if r.Source == "whois" && !r.Chosen {
		o.line("", o.yellow("not in RDAP: ")+r.NoRDAP)
		o.line("", o.dim("the summary is read from the text, which each registry writes its own way"))
		if len(r.Asks) > 1 {
			o.line("", o.dim("asked "+strings.ReplaceAll(strings.Join(r.Asks, ", then "), ":43", "")))
		}
	}
	if r.Source == "whois" && r.Chosen {
		o.line("", o.dim("the summary is read from the text, which each registry writes its own way"))
	} else if r.URL != "" && verbose {
		o.line("", o.dim(r.URL))
	}

	if !r.Found {
		what := "nothing found for " + r.Asked
		if r.Kind == "domain" {
			what = r.Asked + " is not registered at " + whoisWho(r) + " (it may be free to register)"
		}
		o.line("NOT FOUND", o.yellow(what))
		if r.Source == "whois" && verbose {
			renderWhoisText(o, r.Text)
		}
		return
	}

	switch r.Kind {
	case "domain":
		o.line("DOMAIN", o.bold(r.Name))
		if r.Holder != "" {
			o.line("HOLDER", r.Holder)
		}
		if r.Registrar != "" {
			o.line("REGISTRAR", r.Registrar)
		}
		if len(r.Status) > 0 {
			o.line("STATUS", strings.Join(r.Status, ", "))
		}
		sec := "DNS"
		for _, l := range wrapWords(strings.Join(r.NameServers, " "), 80-10) {
			o.line(sec, l)
			sec = ""
		}
		if r.DNSSEC != "" {
			o.line("DNSSEC", r.DNSSEC)
		}
	case "asn":
		o.line("HOLDER", o.bold(nonEmpty(r.Holder, r.Name)))
		as := nonEmpty(r.ASNs, r.Asked)
		if r.Name != "" && r.Name != r.Holder {
			as += "  " + r.Name
		}
		if r.Country != "" {
			as += "  " + r.Country
		}
		o.line("AS", as)
	default:
		o.line("HOLDER", o.bold(nonEmpty(r.Holder, r.Name)))
		var n []string
		for _, s := range []string{r.Name, r.Range, strings.Join(r.CIDRs, ", "), r.Country} {
			if s != "" {
				n = append(n, s)
			}
		}
		if len(n) > 0 {
			o.line("NETWORK", strings.Join(n, "  "))
		}
		if r.Type != "" && verbose {
			o.line("", o.dim("type "+r.Type))
		}
	}
	if len(r.Abuse) > 0 {
		o.line("ABUSE", strings.Join(r.Abuse, "  "))
	}
	if len(r.Events) > 0 {
		var ev []string
		for _, e := range r.Events {
			ev = append(ev, e.Action+" "+e.Date)
		}
		o.line("DATES", strings.Join(ev, "   "))
	}

	remarks := r.Remarks
	if !verbose && len(remarks) > 3 {
		remarks = remarks[:3]
	}
	sec := "REMARKS"
	if len(remarks) > 0 {
		fmt.Fprintln(o.w)
	}
	for _, rm := range remarks {
		for _, l := range wrapWords(rm, 80-10) {
			o.line(sec, l)
			sec = ""
		}
	}

	if verbose {
		if len(r.Contacts) > 0 {
			fmt.Fprintln(o.w)
		}
		for _, c := range r.Contacts {
			o.line("CONTACT", o.bold(strings.Join(c.Roles, ", "))+o.dim(prefixed("  ", c.Handle)))
			for _, s := range []string{c.Name, c.Org, strings.Join(c.Email, "  "), strings.Join(c.Phone, "  "), c.Address} {
				if s != "" && s != c.Handle {
					o.line("", s)
				}
			}
		}
		if r.Source == "whois" {
			renderWhoisText(o, r.Text)
		}
	} else {
		what := "every contact and remark"
		if r.Source == "whois" {
			what = "the whole answer"
		}
		if more != "" {
			fmt.Fprintln(o.w, o.dim(fmt.Sprintf("\n(%s: %s)", more, what)))
		}
	}
}

// whoisWho is the registry, else the server.
func whoisWho(r *WhoisReport) string {
	if r.Registry != "" {
		return r.Registry
	}
	return r.Server
}

func renderWhoisText(o dptOut, text string) {
	fmt.Fprintln(o.w)
	sec := "TEXT"
	blank := false
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		l = strings.TrimRight(l, " ")
		if l == "" {
			if blank {
				continue
			}
			blank = true
		} else {
			blank = false
		}
		o.line(sec, l)
		sec = ""
	}
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	if b != "" {
		return b
	}
	return "(not given)"
}

func prefixed(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}

// wrapWords breaks s into lines of at most n columns, at spaces.
func wrapWords(s string, n int) []string {
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		if line != "" && len(line)+1+len(w) > n {
			out = append(out, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}
