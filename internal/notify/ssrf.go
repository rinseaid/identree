package notify

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ssrfDeniedNets contains CIDR ranges that webhook URLs must not resolve to.
var ssrfDeniedNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",      // this host (RFC 1122)
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC1918
		"100.64.0.0/10",  // CGNAT (RFC 6598)
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local / cloud metadata
		"224.0.0.0/4",    // multicast
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 ULA
		"ff00::/8",       // IPv6 multicast
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("ssrf: bad CIDR: " + cidr)
		}
		ssrfDeniedNets = append(ssrfDeniedNets, n)
	}
}

// isPrivateIP returns true if ip falls within any denied CIDR range.
func isPrivateIP(ip net.IP) bool {
	for _, n := range ssrfDeniedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ssrfCheckEnabled controls whether the SSRF denylist is enforced.
// Tests that need localhost webhook servers can set this to false.
var ssrfCheckEnabled = true

// ssrfSafeDialContext wraps the default dialer with a DNS-level SSRF check.
// It resolves the hostname, filters out private/denied IPs, and connects to
// the first allowed address. If ALL resolved IPs are denied, it returns an error.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !ssrfCheckEnabled {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrf: invalid address %q: %w", addr, err)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf: resolve %q: %w", host, err)
	}

	var dialer net.Dialer
	dialer.Timeout = 10 * time.Second

	for _, ipAddr := range ips {
		if isPrivateIP(ipAddr.IP) {
			continue
		}
		target := net.JoinHostPort(ipAddr.IP.String(), port)
		conn, err := dialer.DialContext(ctx, network, target)
		if err != nil {
			continue // try next IP
		}
		return conn, nil
	}

	return nil, fmt.Errorf("ssrf: all resolved addresses for %q are denied (private/internal)", host)
}
