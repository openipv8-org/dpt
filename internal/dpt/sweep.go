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
// ping, 25 at a time; with ports, the common TCP and UDP ports of each
// one that does.  ports: those ports (or a list given) of one address.  outside-ip: the
// address the internet sees this machine as.

// DPTPortName is a port and its usual service.
type DPTPortName struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Proto   string `json:"proto"` // tcp or udp
}

// DPTTopPorts are the common TCP ports tried.
var DPTTopPorts = []DPTPortName{
	{21, "ftp", "tcp"}, {22, "ssh", "tcp"}, {23, "telnet", "tcp"}, {25, "smtp", "tcp"}, {53, "dns", "tcp"},
	{80, "http", "tcp"}, {81, "http-alt", "tcp"}, {88, "kerberos", "tcp"}, {110, "pop3", "tcp"}, {111, "rpcbind", "tcp"},
	{135, "msrpc", "tcp"}, {139, "netbios", "tcp"}, {143, "imap", "tcp"}, {389, "ldap", "tcp"}, {443, "https", "tcp"},
	{445, "smb", "tcp"}, {465, "smtps", "tcp"}, {514, "rsh", "tcp"}, {515, "lpd", "tcp"}, {548, "afp", "tcp"},
	{554, "rtsp", "tcp"}, {587, "submission", "tcp"}, {631, "ipp", "tcp"}, {636, "ldaps", "tcp"}, {873, "rsync", "tcp"},
	{993, "imaps", "tcp"}, {995, "pop3s", "tcp"}, {1080, "socks", "tcp"}, {1433, "mssql", "tcp"}, {1521, "oracle", "tcp"},
	{1723, "pptp", "tcp"}, {1883, "mqtt", "tcp"}, {2049, "nfs", "tcp"}, {2525, "smtp-alt", "tcp"}, {3000, "http-dev", "tcp"}, {3306, "mysql", "tcp"},
	{3389, "rdp", "tcp"}, {5000, "upnp", "tcp"}, {5060, "sip", "tcp"}, {5432, "postgres", "tcp"}, {5900, "vnc", "tcp"},
	{5985, "winrm", "tcp"}, {6379, "redis", "tcp"}, {8000, "http-alt", "tcp"}, {8025, "smtp-alt", "tcp"}, {8080, "http-proxy", "tcp"}, {8081, "http-alt", "tcp"},
	{8443, "https-alt", "tcp"}, {8888, "http-alt", "tcp"}, {9000, "http-alt", "tcp"}, {9100, "jetdirect", "tcp"}, {9200, "elasticsearch", "tcp"},
	// HTTPS moved up by thousands: 1443, 2443 ... 14443 (8443 is above)
	{1443, "https-alt", "tcp"}, {2443, "https-alt", "tcp"}, {3443, "https-alt", "tcp"}, {4443, "https-alt", "tcp"}, {5443, "https-alt", "tcp"}, {6443, "https-alt", "tcp"}, {7443, "https-alt", "tcp"},
	{9443, "https-alt", "tcp"}, {10443, "https-alt", "tcp"}, {11443, "https-alt", "tcp"}, {12443, "https-alt", "tcp"}, {13443, "https-alt", "tcp"}, {14443, "https-alt", "tcp"},
}

// DPTDefaultPorts are what ports and sweep ports try: the common TCP
// ports and the common UDP services.
var DPTDefaultPorts = append(append([]DPTPortName{}, DPTTopPorts...), DPTUDPPorts...)

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
	Ports   bool          // also try DPTDefaultPorts on each live address
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

// DPTOpenPort is a port that took the connection (TCP) or answered (UDP).
type DPTOpenPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Proto   string `json:"proto"`
	Connect Ms     `json:"connect_ms"` // UDP: the answer's time
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
					h.Open, h.Closed, h.Filtered = ScanPorts(ctx, ip.String(), DPTDefaultPorts, o.Timeout, sem, nil)
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
			if p.Proto == "udp" {
				st, rtt := probeUDP(ctx, ip, p.Port, timeout)
				mu.Lock()
				defer mu.Unlock()
				switch st {
				case udpOpen:
					open = append(open, DPTOpenPort{Port: p.Port, Service: p.Service, Proto: "udp", Connect: ms(rtt)})
				case udpClosed:
					closed++
				default:
					filtered++
				}
			} else {
				start := time.Now()
				d := net.Dialer{Timeout: timeout}
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p.Port)))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					c.Close()
					open = append(open, DPTOpenPort{Port: p.Port, Service: p.Service, Proto: "tcp", Connect: ms(time.Since(start))})
				case strings.Contains(err.Error(), "refused"):
					closed++
				default:
					filtered++
				}
			}
			done++
			if progress != nil {
				progress(done)
			}
		}()
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool {
		if open[i].Port != open[j].Port {
			return open[i].Port < open[j].Port
		}
		return open[i].Proto < open[j].Proto
	})
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

// RunPorts tries ports (nil: DPTDefaultPorts) on target (the first
// address it resolves to).
func RunPorts(ctx context.Context, target string, ports []DPTPortName, family int, timeout time.Duration, r *net.Resolver, live *Live) (*PortsReport, error) {
	if ports == nil {
		ports = DPTDefaultPorts
	}
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
	rep := &PortsReport{Target: DPTTarget{Input: target, Tested: []string{ip}}, Tried: len(ports)}
	for _, a := range ips {
		rep.Target.Addresses = append(rep.Target.Addresses, a.String())
	}
	start := time.Now()
	defer live.Drop("ports")
	live.Set("ports", fmt.Sprintf("ports of %s 0/%d", ip, len(ports)))
	rep.Open, rep.Closed, rep.Filtered = ScanPorts(ctx, ip, ports, timeout, make(chan struct{}, connLimit), func(n int) {
		live.Set("ports", fmt.Sprintf("ports of %s %d/%d", ip, n, len(ports)))
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
