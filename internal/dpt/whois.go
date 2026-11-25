// SPDX-License-Identifier: MIT

package dpt

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// whois: who holds an address, a network, an AS number or a domain.
//
// RDAP first (RFC 9082, 9083): IANA's bootstrap lists (RFC 9224) say
// which registry's server holds it, and the answer is JSON, so it is read
// the same way from every registry.  Where there is no RDAP server, or it
// does not answer, plain whois (port 43): IANA, then the server it refers
// to, then one referral from there; that answer is text, and the summary
// is read from the lines every registry writes in its own way.

// RDAPBootstrapURL is where IANA's bootstrap lists are (ipv4.json,
// ipv6.json, asn.json, dns.json).
var RDAPBootstrapURL = "https://data.iana.org/rdap/"

// WhoisIANA is IANA's whois server, which refers each question to the
// registry that holds it.
var WhoisIANA = "whois.iana.org:43"

// WhoisOptions are a whois run's settings.
type WhoisOptions struct {
	Timeout time.Duration // per request; 0: 10 s
	Family  int           // 4 or 6: connect over that family only
	Agent   string        // the User-Agent
	// Server: ask this one only, not the one IANA says: a whois server
	// (whois.godaddy.com, host:port) or an RDAP one (https://...)
	Server string
	Live   *Live
}

// WhoisReport is what was found.
type WhoisReport struct {
	Query  string `json:"query"`
	Kind   string `json:"kind"`  // address, network, asn, domain
	Asked  string `json:"asked"` // what the registry was asked: the registered domain, the AS number
	Source string `json:"source"`
	// Special: a range no registry holds (private, documentation...)
	Special  string `json:"special,omitempty"`
	Registry string `json:"registry,omitempty"` // ARIN, RIPE NCC, Verisign...
	Server   string `json:"server,omitempty"`
	URL      string `json:"url,omitempty"`
	// NoRDAP says why the answer is whois, not RDAP
	NoRDAP string `json:"no_rdap,omitempty"`
	// Chosen: the server was given, not found through IANA
	Chosen bool `json:"server_given,omitempty"`
	Found  bool `json:"found"`

	Name        string         `json:"name,omitempty"`
	Handle      string         `json:"handle,omitempty"`
	Holder      string         `json:"holder,omitempty"`
	Range       string         `json:"range,omitempty"`
	CIDRs       []string       `json:"cidrs,omitempty"`
	ASNs        string         `json:"asns,omitempty"`
	Type        string         `json:"type,omitempty"`
	Country     string         `json:"country,omitempty"`
	Registrar   string         `json:"registrar,omitempty"`
	Abuse       []string       `json:"abuse,omitempty"`
	Events      []WhoisEvent   `json:"events,omitempty"`
	Status      []string       `json:"status,omitempty"`
	NameServers []string       `json:"name_servers,omitempty"`
	DNSSEC      string         `json:"dnssec,omitempty"`
	Remarks     []string       `json:"remarks,omitempty"`
	Contacts    []WhoisContact `json:"contacts,omitempty"`

	// a domain: the registrar's own RDAP server, asked after the
	// registry's (it holds the registrant)
	Related    string `json:"related_server,omitempty"`
	RelatedWhy string `json:"related_error,omitempty"`

	// whois: the servers asked, in turn, and the last one's answer
	Asks []string `json:"whois_servers,omitempty"`
	Text string   `json:"text,omitempty"`

	RDAP    json.RawMessage `json:"rdap,omitempty"`
	Elapsed Ms              `json:"elapsed_ms"`
}

// WhoisEvent is a dated event: registered, changed, expires.
type WhoisEvent struct {
	Action string `json:"action"`
	Date   string `json:"date"`
}

// WhoisContact is a person, a group or an organisation and its roles.
type WhoisContact struct {
	Roles   []string `json:"roles"`
	Handle  string   `json:"handle,omitempty"`
	Name    string   `json:"name,omitempty"`
	Org     string   `json:"org,omitempty"`
	Email   []string `json:"email,omitempty"`
	Phone   []string `json:"phone,omitempty"`
	Address string   `json:"address,omitempty"`
}

// WhoisUse is how whois is written.
const WhoisUse = "whois <address | network | AS number | domain> [<server>]: 1.1.1.1, 2001:db8::/32, AS13335, example.com;\n" +
	"  server: ask that whois server (whois.godaddy.com) or RDAP server (https://rdap.arin.net/registry/) only"

// CheckWhoisServer says whether s can be a server for whois to ask.
func CheckWhoisServer(s string) error {
	if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return nil
		}
		return fmt.Errorf("whois: %q is not an RDAP server's address", Printable(s))
	}
	host := s
	if h, p, err := net.SplitHostPort(s); err == nil {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("whois: %q: the port is a number from 1 to 65535", Printable(s))
		}
		host = h
	}
	if _, err := netip.ParseAddr(host); err == nil || ValidName(host, false) {
		return nil
	}
	return fmt.Errorf("whois: %q is not a server (whois.godaddy.com, or https://... for RDAP)", Printable(s))
}

// whoisQuery is a question, read: kind and what is asked.
type whoisQuery struct {
	kind   string // address, network, asn, domain
	addr   netip.Addr
	prefix netip.Prefix
	asn    uint32
	domain string // lower case; an IDN in its xn-- form
}

// ParseWhoisQuery reads what whois is asked.
func ParseWhoisQuery(s string) (whoisQuery, error) {
	q := strings.TrimSpace(s)
	if q == "" {
		return whoisQuery{}, errors.New(WhoisUse)
	}
	if a, err := netip.ParseAddr(q); err == nil && a.Zone() == "" {
		return whoisQuery{kind: "address", addr: a.Unmap()}, nil
	}
	if p, err := netip.ParsePrefix(q); err == nil {
		return whoisQuery{kind: "network", prefix: p.Masked(), addr: p.Masked().Addr()}, nil
	}
	n := q
	if len(n) > 2 && strings.EqualFold(n[:2], "as") {
		n = n[2:]
	}
	if v, err := strconv.ParseUint(n, 10, 32); err == nil && n != "" && n[0] != '+' {
		return whoisQuery{kind: "asn", asn: uint32(v)}, nil
	}
	d := strings.TrimSuffix(q, ".")
	if !ValidName(d, false) || !strings.Contains(d, ".") {
		why := ""
		for _, c := range d {
			if c > 0x7f {
				why = "; a name with letters beyond a-z is written in its xn-- form"
				break
			}
		}
		return whoisQuery{}, fmt.Errorf("whois: %q is not an address, a network, an AS number or a domain (%s)%s", Printable(q), WhoisUse, why)
	}
	return whoisQuery{kind: "domain", domain: strings.ToLower(d)}, nil
}

// whoisSpecial says which range no registry holds an address is in, or
// "".
func whoisSpecial(a netip.Addr) string {
	ranges := []struct{ p, what string }{
		{"10.0.0.0/8", "private (RFC 1918): used inside networks, held by no one"},
		{"172.16.0.0/12", "private (RFC 1918): used inside networks, held by no one"},
		{"192.168.0.0/16", "private (RFC 1918): used inside networks, held by no one"},
		{"100.64.0.0/10", "shared address space (RFC 6598): a provider's carrier-grade NAT, held by no one"},
		{"127.0.0.0/8", "loopback: this machine itself"},
		{"169.254.0.0/16", "link-local (RFC 3927): taken by a machine that got no DHCP answer"},
		{"192.0.2.0/24", "documentation (RFC 5737): for examples, never on the internet"},
		{"198.51.100.0/24", "documentation (RFC 5737): for examples, never on the internet"},
		{"203.0.113.0/24", "documentation (RFC 5737): for examples, never on the internet"},
		{"198.18.0.0/15", "benchmarking (RFC 2544): for test networks"},
		{"224.0.0.0/4", "multicast"},
		{"240.0.0.0/4", "reserved (class E)"},
		{"0.0.0.0/8", "this network (RFC 1122): not an address on the internet"},
		{"::1/128", "loopback: this machine itself"},
		{"::/128", "the unspecified address"},
		{"fc00::/7", "unique local (RFC 4193): IPv6's private addresses, held by no one"},
		{"fe80::/10", "link-local: on one segment only"},
		{"2001:db8::/32", "documentation (RFC 3849): for examples, never on the internet"},
		{"ff00::/8", "multicast"},
	}
	for _, r := range ranges {
		if netip.MustParsePrefix(r.p).Contains(a) {
			return r.what
		}
	}
	return ""
}

// RunWhois finds who holds q: RDAP first, whois where there is none.
func RunWhois(ctx context.Context, query string, o WhoisOptions) (*WhoisReport, error) {
	q, err := ParseWhoisQuery(query)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	start := time.Now()
	r := &WhoisReport{Query: query, Kind: q.kind, Asked: q.asked()}
	defer func() { r.Elapsed = ms(time.Since(start)) }()
	if q.kind == "address" || q.kind == "network" {
		if s := whoisSpecial(q.addr); s != "" {
			r.Source, r.Special = "dpt", s
			return r, nil
		}
	}
	cl := whoisHTTP(o)
	defer cl.CloseIdleConnections()

	if o.Server != "" {
		return whoisChosen(ctx, cl, q, r, o)
	}
	o.Live.Set("whois", "asking IANA which registry holds "+r.Asked)
	bases, err := rdapBases(ctx, cl, q)
	switch {
	case err != nil:
		r.NoRDAP = "IANA's list of RDAP servers: " + err.Error()
	case len(bases) == 0:
		r.NoRDAP = "no RDAP server for " + q.where() + " in IANA's list"
	default:
		why, ok := rdapAsk(ctx, cl, q, bases, r, o)
		if ok {
			return r, nil
		}
		r.NoRDAP = why
	}
	// plain whois
	if err := whoisAsk(ctx, q, r, o); err != nil {
		return nil, fmt.Errorf("whois %s: RDAP: %s; whois: %v", r.Asked, r.NoRDAP, err)
	}
	return r, nil
}

// whoisChosen asks the server given, and only it.
func whoisChosen(ctx context.Context, cl *http.Client, q whoisQuery, r *WhoisReport, o WhoisOptions) (*WhoisReport, error) {
	r.Chosen = true
	if strings.HasPrefix(o.Server, "https://") || strings.HasPrefix(o.Server, "http://") {
		if why, ok := rdapAsk(ctx, cl, q, []string{o.Server}, r, o); !ok {
			return nil, fmt.Errorf("whois %s: RDAP: %s", r.Asked, why)
		}
		return r, nil
	}
	server := o.Server
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(strings.Trim(server, "[]"), "43")
	}
	if q.kind == "domain" {
		r.Asked = registeredGuess(q.domain)
	}
	o.Live.Set("whois", "asking "+server)
	t, err := whoisTCP(ctx, server, whoisLine(server, r.Asked), o)
	if err != nil {
		return nil, fmt.Errorf("whois %s: %s: %v", r.Asked, server, err)
	}
	r.Source, r.Text, r.Asks = "whois", t, []string{server}
	r.Server = strings.TrimSuffix(server, ":43")
	r.Registry = registryName(r.Server)
	r.fromWhoisText(t)
	return r, nil
}

// asked is the question as a registry is asked it.
func (q whoisQuery) asked() string {
	switch q.kind {
	case "address":
		return q.addr.String()
	case "network":
		return q.prefix.String()
	case "asn":
		return "AS" + strconv.FormatUint(uint64(q.asn), 10)
	}
	return q.domain
}

// where is the part of the bootstrap that was looked for.
func (q whoisQuery) where() string {
	switch q.kind {
	case "asn":
		return q.asked()
	case "domain":
		return "." + q.domain[strings.LastIndexByte(q.domain, '.')+1:]
	}
	return q.addr.String()
}

func whoisHTTP(o WhoisOptions) *http.Client {
	network := "tcp"
	if o.Family == 4 || o.Family == 6 {
		network += strconv.Itoa(o.Family)
	}
	d := &net.Dialer{Timeout: o.Timeout}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) },
		TLSHandshakeTimeout: o.Timeout,
	}
	return &http.Client{Transport: tr, Timeout: o.Timeout}
}

func whoisGet(ctx context.Context, cl *http.Client, u, agent string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	if agent != "" {
		req.Header.Set("User-Agent", agent)
	}
	resp, err := cl.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, nil, errors.New(Safe(err.Error()))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp, nil, errors.New(Safe(err.Error()))
	}
	return resp, b, nil
}

// rdapBases are the RDAP servers IANA lists for q, https first.
func rdapBases(ctx context.Context, cl *http.Client, q whoisQuery) ([]string, error) {
	file := map[string]string{"asn": "asn.json", "domain": "dns.json"}[q.kind]
	if file == "" {
		file = "ipv4.json"
		if q.addr.Is6() {
			file = "ipv6.json"
		}
	}
	resp, b, err := whoisGet(ctx, cl, RDAPBootstrapURL+file, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	var boot struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(b, &boot); err != nil {
		return nil, fmt.Errorf("not the list it should be (%v)", err)
	}
	best, bestLen := []string(nil), -1
	for _, s := range boot.Services {
		if len(s) != 2 {
			continue
		}
		for _, e := range s[0] {
			if n, ok := bootMatch(q, e); ok && n > bestLen {
				best, bestLen = s[1], n
			}
		}
	}
	var out []string
	for _, u := range best { // https before http
		if strings.HasPrefix(u, "https://") {
			out = append(out, u)
		}
	}
	for _, u := range best {
		if strings.HasPrefix(u, "http://") {
			out = append(out, u)
		}
	}
	return out, nil
}

// bootMatch says whether a bootstrap entry covers q, and how closely
// (the longest prefix, the longest domain suffix wins).
func bootMatch(q whoisQuery, e string) (int, bool) {
	switch q.kind {
	case "asn":
		lo, hi, _ := strings.Cut(e, "-")
		if hi == "" {
			hi = lo
		}
		a, err1 := strconv.ParseUint(lo, 10, 32)
		b, err2 := strconv.ParseUint(hi, 10, 32)
		return 0, err1 == nil && err2 == nil && uint64(q.asn) >= a && uint64(q.asn) <= b
	case "domain":
		e = strings.ToLower(strings.TrimSuffix(e, "."))
		if q.domain == e || strings.HasSuffix(q.domain, "."+e) {
			return strings.Count(e, ".") + 1, true
		}
		return 0, false
	}
	p, err := netip.ParsePrefix(e)
	if err != nil || !p.Contains(q.addr) || q.kind == "network" && q.prefix.Bits() < p.Bits() {
		return 0, false
	}
	return p.Bits(), true
}

// The RDAP answer, as much of it as dpt reads.
type rdapObj struct {
	ObjectClassName string `json:"objectClassName"`
	Handle          string `json:"handle"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Country         string `json:"country"`
	StartAddress    string `json:"startAddress"`
	EndAddress      string `json:"endAddress"`
	StartAutnum     *int64 `json:"startAutnum"`
	EndAutnum       *int64 `json:"endAutnum"`
	LdhName         string `json:"ldhName"`
	UnicodeName     string `json:"unicodeName"`
	CIDRs           []struct {
		V4 string `json:"v4prefix"`
		V6 string `json:"v6prefix"`
		N  int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Events      []rdapEvent  `json:"events"`
	Status      []string     `json:"status"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned *bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	Remarks []rdapRemark `json:"remarks"`
	Links   []struct {
		Rel  string `json:"rel"`
		Href string `json:"href"`
		Type string `json:"type"`
	} `json:"links"`
	ErrorCode   int      `json:"errorCode"`
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapRemark struct {
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

type rdapEntity struct {
	Handle    string `json:"handle"`
	Roles     []string
	Vcard     []any `json:"vcardArray"`
	PublicIDs []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

// rdapPaths are the paths to ask for q, in turn: a domain from the name
// as given down to the shortest under its top-level domain
// (www.example.co.uk, example.co.uk, co.uk), stopping at the first the
// registry holds.
func rdapPaths(q whoisQuery) []string {
	switch q.kind {
	case "address":
		return []string{"ip/" + q.addr.String()}
	case "network":
		return []string{"ip/" + q.prefix.String()}
	case "asn":
		return []string{"autnum/" + strconv.FormatUint(uint64(q.asn), 10)}
	}
	var out []string
	labels := strings.Split(q.domain, ".")
	for i := 0; i+2 <= len(labels) && len(out) < 5; i++ {
		out = append(out, "domain/"+strings.Join(labels[i:], "."))
	}
	return out
}

// rdapAsk asks the RDAP servers; ok is false (with why) when none
// answered, and whois is to be asked instead.
func rdapAsk(ctx context.Context, cl *http.Client, q whoisQuery, bases []string, r *WhoisReport, o WhoisOptions) (string, bool) {
	var why string
	for _, base := range bases {
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		host := urlHost(base)
		o.Live.Set("whois", "asking "+host)
		answered := false
		paths := rdapPaths(q)
		for i, p := range paths {
			u := base + p
			resp, b, err := whoisGet(ctx, cl, u, o.Agent)
			if err != nil {
				why = host + ": " + err.Error()
				break
			}
			final := resp.Request.URL.String() // a registry may redirect to another
			r.Source, r.URL, r.Server = "RDAP", final, urlHost(final)
			r.Registry = registryName(r.Server)
			if resp.StatusCode == 404 {
				answered = true
				continue // a domain: try the shorter name
			}
			// a name under a registered one (www.example.org) is a bad
			// request to some registries (Public Interest Registry), not
			// "not found": try the shorter name too
			if resp.StatusCode == 400 && q.kind == "domain" && i+1 < len(paths) {
				continue
			}
			if resp.StatusCode != 200 {
				why = host + ": " + resp.Status
				break
			}
			var obj rdapObj
			if err := json.Unmarshal(b, &obj); err != nil || obj.ObjectClassName == "" {
				why = host + ": the answer is not RDAP"
				break
			}
			r.Found, r.RDAP = true, b
			if q.kind == "domain" {
				r.Asked = strings.TrimPrefix(p, "domain/")
			}
			r.fromRDAP(&obj)
			if q.kind == "domain" {
				r.related(ctx, cl, &obj, o)
			}
			return "", true
		}
		if answered {
			return "", true // not found: an answer, not a reason for whois
		}
	}
	return why, false
}

func urlHost(u string) string {
	if x, err := url.Parse(u); err == nil && x.Host != "" {
		return x.Hostname()
	}
	return u
}

// registryName is the registry a server belongs to, where dpt knows it.
func registryName(host string) string {
	h := strings.ToLower(host)
	for _, k := range []struct{ suffix, name string }{
		{"arin.net", "ARIN"}, {"ripe.net", "RIPE NCC"}, {"apnic.net", "APNIC"},
		{"lacnic.net", "LACNIC"}, {"afrinic.net", "AFRINIC"}, {"iana.org", "IANA"},
		{"verisign.com", "Verisign"}, {"publicinterestregistry.org", "Public Interest Registry"},
		{"identitydigital.services", "Identity Digital"}, {"nominet.uk", "Nominet"},
		{"markmonitor.com", "MarkMonitor"},
	} {
		if h == k.suffix || strings.HasSuffix(h, "."+k.suffix) {
			return k.name
		}
	}
	return ""
}

// fromRDAP fills the report from an RDAP answer.
func (r *WhoisReport) fromRDAP(obj *rdapObj) {
	r.Handle, r.Name, r.Type, r.Country = Safe(obj.Handle), Safe(obj.Name), Safe(obj.Type), Safe(obj.Country)
	if obj.ObjectClassName == "domain" {
		r.Name = strings.ToLower(Safe(obj.LdhName))
		if obj.UnicodeName != "" && !strings.EqualFold(obj.UnicodeName, obj.LdhName) {
			r.Name += " (" + Safe(obj.UnicodeName) + ")"
		}
	}
	if obj.StartAddress != "" {
		r.Range = Safe(obj.StartAddress)
		if obj.EndAddress != "" && obj.EndAddress != obj.StartAddress {
			r.Range += " - " + Safe(obj.EndAddress)
		}
	}
	for _, c := range obj.CIDRs {
		p := c.V4
		if p == "" {
			p = c.V6
		}
		if p != "" {
			r.CIDRs = append(r.CIDRs, Safe(p)+"/"+strconv.Itoa(c.N))
		}
	}
	if obj.StartAutnum != nil {
		r.ASNs = "AS" + strconv.FormatInt(*obj.StartAutnum, 10)
		if obj.EndAutnum != nil && *obj.EndAutnum != *obj.StartAutnum {
			r.ASNs += " - AS" + strconv.FormatInt(*obj.EndAutnum, 10)
		}
	}
	r.Events = sortEvents(rdapEvents(obj.Events))
	for _, s := range obj.Status {
		r.Status = append(r.Status, Safe(s))
	}
	for _, n := range obj.Nameservers {
		r.NameServers = append(r.NameServers, strings.TrimSuffix(strings.ToLower(Safe(n.LdhName)), "."))
	}
	if obj.SecureDNS != nil && obj.SecureDNS.DelegationSigned != nil {
		r.DNSSEC = map[bool]string{true: "signed (DNSSEC)", false: "not signed"}[*obj.SecureDNS.DelegationSigned]
	}
	r.Remarks = rdapRemarks(obj.Remarks)
	r.addContacts(obj.Entities)
}

func rdapEvents(ev []rdapEvent) []WhoisEvent {
	var out []WhoisEvent
	for _, e := range ev {
		a := map[string]string{"registration": "registered", "last changed": "changed", "expiration": "expires",
			"transfer": "transferred", "reregistration": "registered again"}[strings.ToLower(e.Action)]
		if a == "" {
			continue // last update of RDAP database, and the like
		}
		d := Safe(e.Date)
		if t, err := time.Parse(time.RFC3339, e.Date); err == nil {
			d = t.UTC().Format("2006-01-02")
		}
		out = append(out, WhoisEvent{Action: a, Date: d})
	}
	return out
}

func rdapRemarks(rs []rdapRemark) []string {
	var out []string
	for _, rm := range rs {
		for _, d := range rm.Description {
			if d = strings.TrimSpace(Safe(d)); d != "" && !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
	}
	return out
}

// addContacts adds the entities, and those within them, to the contacts;
// the holder, the registrar and the abuse contact come from their roles.
func (r *WhoisReport) addContacts(es []rdapEntity) {
	for _, e := range es {
		c := vcardContact(e)
		if c.Org != "" && strings.EqualFold(c.Org, c.Name) {
			c.Org = ""
		}
		if len(c.Roles) > 0 && (c.Name != "" || c.Org != "" || len(c.Email) > 0 || len(c.Phone) > 0) && !r.mergeContact(c) {
			r.Contacts = append(r.Contacts, c)
		}
		name := c.Org
		if name == "" {
			name = c.Name
		}
		if slices.Contains(c.Roles, "registrant") && r.Holder == "" && name != "" {
			r.Holder = name
		}
		if slices.Contains(c.Roles, "registrar") && r.Registrar == "" && name != "" {
			r.Registrar = name
			for _, id := range e.PublicIDs {
				if strings.EqualFold(id.Type, "IANA Registrar ID") && id.Identifier != "" {
					r.Registrar += " (IANA " + Safe(id.Identifier) + ")"
				}
			}
		}
		if slices.Contains(c.Roles, "abuse") {
			for _, a := range append(c.Email, c.Phone...) {
				if !slices.Contains(r.Abuse, a) {
					r.Abuse = append(r.Abuse, a)
				}
			}
		}
		r.addContacts(e.Entities)
	}
}

// vcardContact reads an entity's jCard (RFC 7095): ["vcard", [[name,
// params, type, value], ...]].
func vcardContact(e rdapEntity) WhoisContact {
	c := WhoisContact{Handle: Safe(e.Handle)}
	for _, r := range e.Roles {
		c.Roles = append(c.Roles, Safe(r))
	}
	if len(e.Vcard) < 2 {
		return c
	}
	props, _ := e.Vcard[1].([]any)
	text := func(v any) string {
		switch x := v.(type) {
		case string:
			return strings.TrimSpace(Safe(x))
		case []any:
			var parts []string
			for _, p := range x {
				if s, ok := p.(string); ok && strings.TrimSpace(s) != "" {
					parts = append(parts, strings.TrimSpace(Safe(s)))
				}
			}
			return strings.Join(parts, ", ")
		}
		return ""
	}
	for _, p := range props {
		f, ok := p.([]any)
		if !ok || len(f) < 4 {
			continue
		}
		name, _ := f[0].(string)
		params, _ := f[1].(map[string]any)
		v := text(f[3])
		switch strings.ToLower(name) {
		case "fn":
			c.Name = v
		case "org":
			c.Org = v
		case "email":
			if v != "" && !slices.Contains(c.Email, v) {
				c.Email = append(c.Email, v)
			}
		case "tel":
			v = strings.TrimPrefix(v, "tel:")
			if t, _ := params["type"].(string); strings.EqualFold(t, "fax") {
				continue
			}
			if v != "" && !slices.Contains(c.Phone, v) {
				c.Phone = append(c.Phone, v)
			}
		case "adr":
			if l, ok := params["label"].(string); ok && strings.TrimSpace(l) != "" {
				v = strings.Join(strings.Fields(strings.ReplaceAll(Safe(strings.ReplaceAll(l, "\n", ", ")), ",,", ",")), " ")
			}
			if v != "" {
				c.Address = v
			}
		}
	}
	return c
}

// related asks a domain's registrar's RDAP server, which the registry's
// answer links to: it holds the registrant (often redacted).
func (r *WhoisReport) related(ctx context.Context, cl *http.Client, obj *rdapObj, o WhoisOptions) {
	for _, l := range obj.Links {
		if l.Rel != "related" || !strings.Contains(l.Type, "rdap") || l.Href == "" || l.Href == r.URL {
			continue
		}
		u, err := url.Parse(l.Href)
		if err != nil || u.Scheme != "https" && u.Scheme != "http" {
			continue
		}
		r.Related = u.Hostname()
		o.Live.Set("whois", "asking the registrar, "+r.Related)
		resp, b, err := whoisGet(ctx, cl, l.Href, o.Agent)
		switch {
		case err != nil:
			r.RelatedWhy = err.Error()
		case resp.StatusCode != 200:
			r.RelatedWhy = resp.Status
		default:
			var reg rdapObj
			if err := json.Unmarshal(b, &reg); err != nil || reg.ObjectClassName == "" {
				r.RelatedWhy = "the answer is not RDAP"
				return
			}
			holder := r.Holder
			r.addContacts(reg.Entities)
			if holder == "" && r.Holder != "" && whoisRedacted(r.Holder) {
				r.Holder = "redacted by the registrar (privacy)"
			}
			for _, rm := range rdapRemarks(reg.Remarks) {
				if !slices.Contains(r.Remarks, rm) {
					r.Remarks = append(r.Remarks, rm)
				}
			}
		}
		return
	}
}

func whoisRedacted(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "redacted") || strings.Contains(l, "privacy") || strings.Contains(l, "withheld")
}

// whoisAsk is plain whois: IANA, the server it refers to, then one
// referral from there (an RIR's ReferralServer, a domain's registrar).
func whoisAsk(ctx context.Context, q whoisQuery, r *WhoisReport, o WhoisOptions) error {
	asked := r.Asked
	if q.kind == "domain" {
		asked = registeredGuess(q.domain)
		r.Asked = asked
	}
	server := WhoisIANA
	var text, answered string
	for hop := 0; hop < 3 && server != ""; hop++ {
		o.Live.Set("whois", "asking "+server)
		t, err := whoisTCP(ctx, server, whoisLine(server, asked), o)
		if err != nil {
			if hop == 0 {
				return err
			}
			r.Asks = append(r.Asks, server+" (did not answer: "+err.Error()+")")
			break
		}
		r.Asks = append(r.Asks, server)
		text, answered = t, server
		next := whoisReferral(t)
		if next == "" || next == server {
			break
		}
		server = next
	}
	r.Source, r.Text = "whois", text
	r.Server = strings.TrimSuffix(answered, ":43")
	r.Registry = registryName(r.Server)
	r.fromWhoisText(text)
	return nil
}

// registeredGuess is a domain's registered name as a guess: whois has no
// "not found, try shorter", so the last two labels (three under a
// two-letter second level: example.co.uk).
func registeredGuess(d string) string {
	l := strings.Split(d, ".")
	if len(l) <= 2 {
		return d
	}
	n := 2
	if len(l[len(l)-1]) == 2 && len(l[len(l)-2]) <= 3 && len(l) >= 3 &&
		slices.Contains([]string{"co", "com", "net", "org", "ac", "gov", "edu", "ltd", "plc", "ne", "or", "go"}, l[len(l)-2]) {
		n = 3
	}
	return strings.Join(l[len(l)-n:], ".")
}

// whoisLine is the question as a server wants it.
func whoisLine(server, q string) string {
	switch h := strings.TrimSuffix(server, ":43"); {
	case h == "whois.arin.net":
		if strings.HasPrefix(q, "AS") {
			return "a + " + q[2:] // the AS number, in full
		}
		return "n + " + q // the network, in full
	case h == "whois.verisign-grs.com" || strings.HasSuffix(h, ".verisign-grs.com"):
		return "domain " + q
	}
	return q
}

// whoisReferral is the server an answer refers on to, or "".
func whoisReferral(text string) string {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "refer", "whois", "referralserver", "registrar whois server":
			if strings.Contains(v, "://") && !strings.HasPrefix(strings.ToLower(v), "whois://") {
				continue // rwhois://, http://: another protocol
			}
			v = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(v), "whois://"), "/")
			if v == "" || strings.ContainsAny(v, " /") {
				continue
			}
			if !strings.Contains(v, ":") {
				v += ":43"
			}
			return v
		}
	}
	return ""
}

// whoisTCP asks a whois server (RFC 3912): the question, CRLF, and the
// answer until the server closes.
func whoisTCP(ctx context.Context, server, line string, o WhoisOptions) (string, error) {
	network := "tcp"
	if o.Family == 4 || o.Family == 6 {
		network += strconv.Itoa(o.Family)
	}
	d := net.Dialer{Timeout: o.Timeout}
	c, err := d.DialContext(ctx, network, server)
	if err != nil {
		return "", errors.New(Safe(err.Error()))
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(o.Timeout))
	if _, err := io.WriteString(c, line+"\r\n"); err != nil {
		return "", errors.New(Safe(err.Error()))
	}
	b, err := io.ReadAll(io.LimitReader(c, 1<<20))
	if err != nil && len(b) == 0 {
		return "", errors.New(Safe(err.Error()))
	}
	return SafeLines(strings.ReplaceAll(string(b), "\r\n", "\n")), nil
}

// fromWhoisText reads the summary from a whois answer's "key: value"
// lines, which each registry names its own way.
func (r *WhoisReport) fromWhoisText(text string) {
	first := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	event := func(action, v string) {
		for _, e := range r.Events {
			if e.Action == action {
				return
			}
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			v = t.UTC().Format("2006-01-02")
		} else if len(v) >= 10 && v[4] == '-' && v[7] == '-' {
			v = v[:10]
		}
		r.Events = append(r.Events, WhoisEvent{Action: action, Date: v})
	}
	add := func(dst *[]string, v string) {
		if !slices.Contains(*dst, v) {
			*dst = append(*dst, v)
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "orgname", "org-name", "organization", "organisation", "registrant organization", "registrant", "owner", "registrant name":
			first(&r.Holder, v)
		case "netname", "asname", "domain name", "domain":
			if k == "domain name" || k == "domain" {
				v = strings.ToLower(v)
			}
			first(&r.Name, v)
		case "netrange", "inetnum", "inet6num":
			first(&r.Range, v)
		case "cidr", "route", "route6":
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					add(&r.CIDRs, p)
				}
			}
		case "aut-num", "asnumber", "origin":
			first(&r.ASNs, v)
		case "country":
			first(&r.Country, strings.ToUpper(v))
		case "registrar":
			first(&r.Registrar, v)
		case "orgabuseemail", "abuse-mailbox", "registrar abuse contact email", "abuse-c email", "e-mail abuse":
			add(&r.Abuse, v)
		case "name server", "nserver":
			add(&r.NameServers, strings.TrimSuffix(strings.ToLower(strings.Fields(v)[0]), "."))
		case "domain status", "status":
			add(&r.Status, strings.Fields(v)[0])
		case "dnssec":
			first(&r.DNSSEC, v)
		case "creation date", "created", "regdate", "registered":
			event("registered", v)
		case "updated date", "last-modified", "updated", "changed", "last modified":
			event("changed", v)
		case "registry expiry date", "registrar registration expiration date", "expiry date", "expires", "paid-till":
			event("expires", v)
		}
	}
	r.Events = sortEvents(r.Events)
	nf := strings.ToLower(text)
	r.Found = r.Holder != "" || r.Name != "" || r.Range != "" || r.Registrar != "" ||
		!(strings.Contains(nf, "no match") || strings.Contains(nf, "not found") || strings.Contains(nf, "no entries found") ||
			strings.Contains(nf, "no data found") || strings.TrimSpace(text) == "")
}

// sortEvents puts the events in the order they happen: registered,
// transferred, changed, expires.
func sortEvents(ev []WhoisEvent) []WhoisEvent {
	rank := map[string]int{"registered": 0, "registered again": 1, "transferred": 2, "changed": 3, "expires": 4}
	slices.SortStableFunc(ev, func(a, b WhoisEvent) int { return rank[a.Action] - rank[b.Action] })
	return ev
}

// mergeContact adds c to an already listed contact with the same roles
// and name (a registry's answer and its registrar's repeat them, each with
// some of the details); ok is false when there is none.
func (r *WhoisReport) mergeContact(c WhoisContact) bool {
	for i := range r.Contacts {
		x := &r.Contacts[i]
		if !slices.Equal(x.Roles, c.Roles) || !strings.EqualFold(x.Name, c.Name) && x.Name != "" && c.Name != "" {
			continue
		}
		if x.Name == "" {
			x.Name = c.Name
		}
		if x.Org == "" && !strings.EqualFold(c.Org, x.Name) {
			x.Org = c.Org
		}
		if x.Address == "" {
			x.Address = c.Address
		}
		if x.Handle == "" {
			x.Handle = c.Handle
		}
		for _, e := range c.Email {
			if !slices.Contains(x.Email, e) {
				x.Email = append(x.Email, e)
			}
		}
		for _, p := range c.Phone {
			if !slices.Contains(x.Phone, p) {
				x.Phone = append(x.Phone, p)
			}
		}
		return true
	}
	return false
}
