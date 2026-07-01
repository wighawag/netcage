package cli

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DirectAllow is one validated split-tunnel allowlist entry: a private LAN
// destination the jailed tool may reach DIRECTLY (over the real NIC) instead of
// through the socks5h proxy. It is the parse+validate output this CLI produces;
// the split-tunnel-jail-wiring task consumes it (adds the network to the
// sidecar's TUN_EXCLUDED_ROUTES and an `ip daddr <net> tcp dport <port> accept`
// nft rule). See prd split-tunnel-lan-allowlist + the spike finding.
//
// Network is always non-nil. A bare IP is normalised to a host route (/32 for
// IPv4). Port is the TCP destination port, or 0 meaning "all ports on this
// network" (a bare IP or CIDR with no `:port`). The entry is TCP-only by
// construction (ADR-0003 hard-blocks UDP even to allowlisted hosts); TCP is
// implicit here and is enforced at the jail-wiring layer, not encoded per entry.
type DirectAllow struct {
	Network *net.IPNet // the allowed destination network (a /32 for a bare IP)
	Port    int        // TCP port, or 0 for all ports on the network
	Raw     string     // the original flag value, preserved for diagnostics
}

// privateRanges is the ONLY set of destination ranges --allow-direct accepts:
// RFC1918 private space plus link-local. Restricting directs to these ranges is
// the security gate (prd guardrail / story 3): a user cannot accidentally allow
// a PUBLIC address that would become a real anonymity leak. A public-IP direct,
// if ever wanted, is a separate louder opt-in, NOT part of this feature. An
// allowlisted network must be FULLY contained in one of these (a prefix that
// straddles public space is refused).
var privateRanges = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local (RFC3927)
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("cli: bad built-in private range " + c) // unreachable: constants
		}
		nets = append(nets, n)
	}
	return nets
}()

// parseAllowDirect parses one --allow-direct value into a validated DirectAllow.
// It accepts an IP or a CIDR, each optionally suffixed with `:port`, and REJECTS
// (loudly, naming the value + reason): a hostname or otherwise non-IP/CIDR
// literal; a malformed value; an out-of-range or non-numeric port; and any
// address/network NOT fully within the private/link-local ranges (a public
// destination that would leak). This is the fail-loud-at-startup security gate.
func parseAllowDirect(raw string) (DirectAllow, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return DirectAllow{}, fmt.Errorf("empty --allow-direct value: expected an RFC1918/link-local IP or CIDR, optionally with :port")
	}

	hostPart, port, err := splitAllowDirectPort(value)
	if err != nil {
		return DirectAllow{}, err
	}

	network, err := parseHostToNetwork(hostPart, value)
	if err != nil {
		return DirectAllow{}, err
	}

	if !networkWithinPrivateRanges(network) {
		return DirectAllow{}, fmt.Errorf(
			"--allow-direct %q is not a private address: only RFC1918 / link-local ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16) may be reached directly; a public destination would leak your real IP around the jail",
			raw)
	}

	return DirectAllow{Network: network, Port: port, Raw: raw}, nil
}

// splitAllowDirectPort separates an optional trailing `:port` from the host
// (IP or CIDR) part. It disambiguates the `:` that separates a port from the
// `:` inside an IPv6 literal by requiring the port to be the segment after the
// LAST `:` AND the remaining host part to still parse as an IP/CIDR. For the
// IPv4/CIDR shapes this feature targets, a single trailing `:<digits>` is the
// port. A present-but-invalid port is rejected here (naming the value).
func splitAllowDirectPort(value string) (host string, port int, err error) {
	idx := strings.LastIndexByte(value, ':')
	if idx < 0 {
		return value, 0, nil // no port
	}

	// A bracketed IPv6 literal (e.g. "[fe80::1]:80") is out of scope for v1
	// (IPv4 RFC1918/link-local), but treat an unbracketed multi-colon token as a
	// possible IPv6 with no port rather than mis-splitting it.
	if strings.Count(value, ":") > 1 && !strings.Contains(value, "]") {
		return value, 0, nil // let network parsing reject it (not IPv4)
	}

	host = value[:idx]
	portStr := value[idx+1:]
	if portStr == "" {
		return "", 0, fmt.Errorf("--allow-direct %q has an empty port after ':': expected :<1-65535>", value)
	}
	p, perr := strconv.Atoi(portStr)
	if perr != nil {
		return "", 0, fmt.Errorf("--allow-direct %q has a non-numeric port %q: expected :<1-65535>", value, portStr)
	}
	if p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("--allow-direct %q has an out-of-range port %d: expected :<1-65535>", value, p)
	}
	return host, p, nil
}

// parseHostToNetwork turns the host part (an IP or a CIDR) into a normalised
// *net.IPNet: a bare IP becomes a host route (/32 for IPv4, /128 for IPv6). A
// value that is neither a valid IP nor a valid CIDR literal (e.g. a hostname) is
// rejected, naming the original value and that hostnames are unsupported.
func parseHostToNetwork(host, value string) (*net.IPNet, error) {
	if strings.Contains(host, "/") {
		_, network, err := net.ParseCIDR(host)
		if err != nil {
			return nil, fmt.Errorf("--allow-direct %q is not a valid CIDR: %v (IP/CIDR literals only; hostnames are unsupported)", value, err)
		}
		return network, nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("--allow-direct %q is not a valid IP or CIDR literal (hostnames are unsupported: a LAN name cannot resolve through the proxy)", value)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// networkWithinPrivateRanges reports whether the whole network is contained in
// one of the accepted private/link-local ranges. Both the network address AND
// the broadcast-equivalent (last address) must fall inside the same range, so a
// too-wide prefix that straddles public space (e.g. 10.0.0.0/7) is refused.
func networkWithinPrivateRanges(n *net.IPNet) bool {
	for _, r := range privateRanges {
		if rangeContainsNetwork(r, n) {
			return true
		}
	}
	return false
}

// rangeContainsNetwork reports whether accepted range r fully contains network n
// (both endpoints of n lie in r). It compares in the same address family.
func rangeContainsNetwork(r, n *net.IPNet) bool {
	first := n.IP
	last := lastAddr(n)
	if first == nil || last == nil {
		return false
	}
	return r.Contains(first) && r.Contains(last)
}

// lastAddr returns the last address of a network (network address OR'd with the
// inverted mask), used to prove the whole prefix is within an accepted range.
func lastAddr(n *net.IPNet) net.IP {
	ip := n.IP
	mask := n.Mask
	if len(ip) != len(mask) {
		// Normalise an IPv4 network stored as a 16-byte IP against its 4-byte mask.
		if v4 := ip.To4(); v4 != nil && len(mask) == net.IPv4len {
			ip = v4
		} else {
			return nil
		}
	}
	last := make(net.IP, len(ip))
	for i := range ip {
		last[i] = ip[i] | ^mask[i]
	}
	return last
}
