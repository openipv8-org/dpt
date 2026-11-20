// SPDX-License-Identifier: MIT

package dpt

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sweep: which addresses on the network this machine is on answer a
// ping, 25 at a time; with ports, the 50 common TCP ports of each one
// that does.  ports: those 50 ports of one address.  outside-ip: the
// address the internet sees this machine as.

// DPTPortName is a port and its usual service.
type DPTPortName struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// DPTTopPorts are the 50 TCP ports tried.
var DPTTopPorts = []DPTPortName{
	{21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"},
	{80, "http"}, {81, "http-alt"}, {88, "kerberos"}, {110, "pop3"}, {111, "rpcbind"},
	{135, "msrpc"}, {139, "netbios"}, {143, "imap"}, {389, "ldap"}, {443, "https"},
	{445, "smb"}, {465, "smtps"}, {514, "rsh"}, {515, "lpd"}, {548, "afp"},
	{554, "rtsp"}, {587, "submission"}, {631, "ipp"}, {636, "ldaps"}, {873, "rsync"},
	{993, "imaps"}, {995, "pop3s"}, {1080, "socks"}, {1433, "mssql"}, {1521, "oracle"},
	{1723, "pptp"}, {1883, "mqtt"}, {2049, "nfs"}, {3000, "http-dev"}, {3306, "mysql"},
	{3389, "rdp"}, {5000, "upnp"}, {5060, "sip"}, {5432, "postgres"}, {5900, "vnc"},
	{5985, "winrm"}, {6379, "redis"}, {8000, "http-alt"}, {8080, "http-proxy"}, {8081, "http-alt"},
	{8443, "https-alt"}, {8888, "http-alt"}, {9000, "http-alt"}, {9100, "jetdirect"}, {9200, "elasticsearch"},
}

// sweepMaxHosts is the most addresses a sweep tries: a larger network
// is swept as the /24 this machine is in.
const sweepMaxHosts = 1024

// connLimit is how many port probes run at once over the whole sweep
// (macOS allows a process 256 open files by default).
const connLimit = 100

// SweepOptions is one sweep.
type SweepOptions struct {
	Network *net.IPNet    // nil: the interface's IPv4 network
	Iface   string        // "": the one dpt chooses
	Ports   bool          // also try DPTTopPorts on each live address
	Batch   int           // addresses pinged at once; 0: 25
	Timeout time.Duration // echo wait and connect; 0: 1 s
	Live    *Live
	// OnNetwork gets the network before the sweep; OnHost each live
	// address, in address order, as soon as its batch is done.
	OnNetwork func(r *SweepReport)
	OnHost    func(h *SweepHost)
	// Ping, for tests: nil is ICMP echo
	Ping func(ip net.IP, timeout time.Duration) (EchoReply, error)
	// Names gives an address's name; nil: reverse DNS
	Names func(ctx context.Context, ip string) string
}

// SweepHost is one address that answered.
type SweepHost struct {
	Address  string        `json:"address"`
	Name     string        `json:"name,omitempty"`
	RTT      Ms            `json:"rtt_ms"`
	TTL      int           `json:"ttl,omitempty"`
	Self     bool          `json:"this_machine,omitempty"`
	Gateway  bool          `json:"gateway,omitempty"`
	Scanned  bool          `json:"ports_tried,omitempty"`
	Open     []DPTOpenPort `json:"open,omitempty"`
	Closed   int           `json:"closed,omitempty"`
	Filtered int           `json:"filtered,omitempty"`
	ip       uint32
}

// DPTOpenPort is a port that took the connection.
type DPTOpenPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Connect Ms     `json:"connect_ms"`
}

// SweepReport is a sweep.
type SweepReport struct {
	Iface   string      `json:"interface,omitempty"`
	Network string      `json:"network"`
	Self    string      `json:"this_machine,omitempty"`
	Gateway string      `json:"gateway,omitempty"`
	Note    string      `json:"note,omitempty"`
	Tried   int         `json:"tried"`
	Hosts   []SweepHost `json:"live"`
	Ports   bool        `json:"ports"`
	Elapsed Ms          `json:"elapsed_ms"`
	Started time.Time   `json:"started"`
}

func ip4u(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }
func u2ip4(u uint32) net.IP { b := make(net.IP, 4); binary.BigEndian.PutUint32(b, u); return b }

// sweepNetwork is the interface's IPv4 network and address, and its
// gateway.
func sweepNetwork(iface string) (string, *net.IPNet, net.IP, net.IP, error) {
	if iface == "" {
		var err error
		if iface, err = DPTDefaultIface(); err != nil {
			return "", nil, nil, nil, err
		}
	}
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("interface %s not found", Safe(iface))
	}
	addrs, _ := i.Addrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || n.IP.IsLinkLocalUnicast() || n.IP.IsLoopback() {
			continue
		}
		return iface, &net.IPNet{IP: n.IP.Mask(n.Mask).To4(), Mask: n.Mask}, n.IP.To4(), gateways()[i.Index], nil
	}
	return "", nil, nil, nil, fmt.Errorf("%s has no IPv4 address", Safe(iface))
}

// ParseSweepNetwork reads a network to sweep: 192.168.1.0/24.
// A bare address is the /24 around it.
func ParseSweepNetwork(s string) (*net.IPNet, error) {
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return &net.IPNet{IP: ip.To4().Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}, nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil || n.IP.To4() == nil {
		return nil, fmt.Errorf("%q is not an IPv4 network (192.168.1.0/24)", Printable(s))
	}
	if ones, _ := n.Mask.Size(); 1<<(32-ones) > sweepMaxHosts {
		return nil, fmt.Errorf("%s is more than %d addresses: give a /22 or smaller", n, sweepMaxHosts)
	}
	n.IP = n.IP.To4()
	return n, nil
}

// sweepAddrs are a network's host addresses (no network or broadcast
// address below /31).
func sweepAddrs(n *net.IPNet) []uint32 {
	ones, bits := n.Mask.Size()
	first := ip4u(n.IP)
	size := uint32(1) << (bits - ones)
	var out []uint32
	for k := uint32(0); k < size; k++ {
		if size > 2 && (k == 0 || k == size-1) {
			continue
		}
		out = append(out, first+k)
	}
	return out
}

func icmpPing(ip net.IP, timeout time.Duration) (EchoReply, error) {
	c, err := OpenICMP(ip)
	if err != nil {
		return EchoReply{}, err
	}
	defer c.Close()
	return c.Echo(1, timeout)
}

func reverseName(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return Safe(strings.TrimSuffix(names[0], "."))
}

// RunSweep pings the network, Batch addresses at a time.
func RunSweep(ctx context.Context, o SweepOptions) (*SweepReport, error) {
	if o.Batch <= 0 {
		o.Batch = 25
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	if o.Names == nil {
		o.Names = reverseName
	}
	rep := &SweepReport{Ports: o.Ports, Started: time.Now()}
	var self, gw net.IP
	if o.Network == nil {
		iface, n, s, g, err := sweepNetwork(o.Iface)
		if err != nil {
			return nil, err
		}
		rep.Iface, self, gw = iface, s, g
		if ones, _ := n.Mask.Size(); 1<<(32-ones) > sweepMaxHosts {
			rep.Note = fmt.Sprintf("%s is more than %d addresses: sweeping this machine's /24", n, sweepMaxHosts)
			n = &net.IPNet{IP: s.Mask(net.CIDRMask(24, 32)).To4(), Mask: net.CIDRMask(24, 32)}
		}
		o.Network = n
	}
	rep.Network = o.Network.String()
	if self != nil {
		rep.Self = self.String()
	}
	if gw != nil {
		rep.Gateway = gw.String()
	}
	addrs := sweepAddrs(o.Network)
	if o.Ping == nil {
		// no ICMP socket for this user: say so, not "nothing is live"
		c, err := OpenICMP(u2ip4(addrs[0]))
		if err != nil {
			return nil, err
		}
		c.Close()
		o.Ping = icmpPing
	}
	rep.Tried = len(addrs)
	if o.OnNetwork != nil {
		o.OnNetwork(rep)
	}
	sem := make(chan struct{}, connLimit)
	defer o.Live.Drop("sweep")
	for b := 0; b < len(addrs) && ctx.Err() == nil; b += o.Batch {
		batch := addrs[b:min(b+o.Batch, len(addrs))]
		o.Live.Set("sweep", fmt.Sprintf("pinging %s - %s  (%d of %d)   %d live",
			u2ip4(batch[0]), u2ip4(batch[len(batch)-1]), b+len(batch), len(addrs), len(rep.Hosts)))
		found := make([]*SweepHost, len(batch))
		var wg sync.WaitGroup
		for i, a := range batch {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ip := u2ip4(a)
				var r EchoReply
				var err error
				// a single echo is easily lost; any error (no reply,
				// unreachable) is not live
				for try := 0; try < 2 && ctx.Err() == nil; try++ {
					if r, err = o.Ping(ip, o.Timeout); err == nil {
						break
					}
				}
				if err != nil {
					return
				}
				h := &SweepHost{Address: ip.String(), RTT: ms(r.RTT), TTL: max(r.TTL, 0), ip: a}
				h.Self = self != nil && self.Equal(ip)
				h.Gateway = gw != nil && gw.Equal(ip)
				h.Name = o.Names(ctx, h.Address)
				if o.Ports && ctx.Err() == nil {
					h.Scanned = true
					h.Open, h.Closed, h.Filtered = ScanPorts(ctx, ip.String(), DPTTopPorts, o.Timeout, sem, nil)
				}
				found[i] = h
			}()
		}
		wg.Wait()
		for _, h := range found {
			if h != nil {
				rep.Hosts = append(rep.Hosts, *h)
				if o.OnHost != nil {
					o.OnHost(h)
				}
			}
		}
	}
	rep.Elapsed = ms(time.Since(rep.Started))
	return rep, nil
}

// ScanPorts tries ports on ip with a TCP connection each, at most
// cap(sem) at once; progress, when set, gets the count done.
func ScanPorts(ctx context.Context, ip string, ports []DPTPortName, timeout time.Duration, sem chan struct{}, progress func(done int)) (open []DPTOpenPort, closed, filtered int) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	done := 0
	for _, p := range ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			start := time.Now()
			d := net.Dialer{Timeout: timeout}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p.Port)))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				c.Close()
				open = append(open, DPTOpenPort{Port: p.Port, Service: p.Service, Connect: ms(time.Since(start))})
			case strings.Contains(err.Error(), "refused"):
				closed++
			default:
				filtered++
			}
			done++
			if progress != nil {
				progress(done)
			}
		}()
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open, closed, filtered
}

// PortsReport is ports <address>.
type PortsReport struct {
	Target   DPTTarget     `json:"target"`
	Name     string        `json:"name,omitempty"`
	Open     []DPTOpenPort `json:"open"`
	Closed   int           `json:"closed"`
	Filtered int           `json:"filtered"`
	Tried    int           `json:"tried"`
	Elapsed  Ms            `json:"elapsed_ms"`
}

// RunPorts tries DPTTopPorts on target (the first address it resolves to).
func RunPorts(ctx context.Context, target string, family int, timeout time.Duration, r *net.Resolver, live *Live) (*PortsReport, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	look, cancel := context.WithTimeout(ctx, 2*timeout)
	ips, err := DPTResolve(look, target, family, r)
	cancel()
	if err != nil {
		return nil, err
	}
	ip := ips[0].String()
	rep := &PortsReport{Target: DPTTarget{Input: target, Tested: []string{ip}}, Tried: len(DPTTopPorts)}
	for _, a := range ips {
		rep.Target.Addresses = append(rep.Target.Addresses, a.String())
	}
	start := time.Now()
	defer live.Drop("ports")
	live.Set("ports", fmt.Sprintf("ports of %s 0/%d", ip, len(DPTTopPorts)))
	rep.Open, rep.Closed, rep.Filtered = ScanPorts(ctx, ip, DPTTopPorts, timeout, make(chan struct{}, connLimit), func(n int) {
		live.Set("ports", fmt.Sprintf("ports of %s %d/%d", ip, n, len(DPTTopPorts)))
	})
	rep.Elapsed = ms(time.Since(start))
	if net.ParseIP(target) != nil {
		rep.Name = reverseName(ctx, ip)
	}
	return rep, nil
}

// OutsideIPURL answers with the address it sees, as text.
var OutsideIPURL = "https://ifconfig.me/ip"

// OutsideIP is the address the internet sees.
type OutsideIP struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	Source  string `json:"source"`
	Elapsed Ms     `json:"elapsed_ms"`
}

// RunOutsideIP asks OutsideIPURL; family 4 or 6 chooses the way out.
func RunOutsideIP(ctx context.Context, family int, timeout time.Duration) (*OutsideIP, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	network := "tcp"
	if family == 4 || family == 6 {
		network += strconv.Itoa(family)
	}
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) },
		TLSHandshakeTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", OutsideIPURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "curl/8 (dpt)") // the plain-text answer curl gets
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", OutsideIPURL, Safe(err.Error()))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", OutsideIPURL, resp.Status)
	}
	s := strings.TrimSpace(string(b))
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("%s: not an address: %q", OutsideIPURL, Safe(s))
	}
	r := &OutsideIP{Address: ip.String(), Source: OutsideIPURL, Elapsed: ms(time.Since(start))}
	r.Name = reverseName(ctx, r.Address)
	return r, nil
}
