package jail

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// TestDirectUnreachableDiagnostic_DistinguishesLANFromPolicyBlock pins the
// story-10 wording (podman-free): when an allowlisted direct is unreachable, the
// message must name the direct, mark it as ON the allowlist, and say a LAN
// problem is distinct from a jail-policy block, so an operator can tell an
// unreachable-on-LAN allowed direct apart from a (silently dropped)
// non-allowlisted destination. It wraps ErrDirectUnreachable so callers can match.
func TestDirectUnreachableDiagnostic_DistinguishesLANFromPolicyBlock(t *testing.T) {
	msg := directUnreachableDiagnostic("192.168.1.150", 8080, "192.168.1.150:8080")
	if !errors.Is(ErrDirectUnreachable, ErrDirectUnreachable) { // sanity: sentinel exists
		t.Fatal("ErrDirectUnreachable sentinel missing")
	}
	for _, want := range []string{
		"192.168.1.150:8080", // names the direct
		"allowlisted",        // marks it as on the allowlist
		"LAN problem",        // the LAN-vs-policy distinction
		"NOT a jail-policy block",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("story-10 diagnostic missing %q\ngot: %s", want, msg)
		}
	}
	if !strings.Contains(msg, ErrDirectUnreachable.Error()) {
		t.Fatalf("diagnostic must carry the ErrDirectUnreachable sentinel text\ngot: %s", msg)
	}
}

// allow builds a validated DirectAllow entry the way the CLI would, for the
// wiring tests (network + optional port). A bare IP becomes a /32 host route.
func allow(t *testing.T, cidr string, port int) cli.DirectAllow {
	t.Helper()
	if strings.Contains(cidr, "/") {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", cidr, err)
		}
		return cli.DirectAllow{Network: n, Port: port, Raw: cidr}
	}
	ip := net.ParseIP(cidr)
	if ip == nil {
		t.Fatalf("bad test IP %q", cidr)
	}
	return cli.DirectAllow{
		Network: &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Port:    port,
		Raw:     cidr,
	}
}

// TestSidecarRunArgs_AllowlistExcludesEachNet: with a non-empty allowlist, every
// allowed network is added to TUN_EXCLUDED_ROUTES ALONGSIDE the proxy reachback
// /32 (the enabler half of the spike: excluding the destination from the TUN is
// what lets it egress the real NIC via pasta instead of the proxy).
func TestSidecarRunArgs_AllowlistExcludesEachNet(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{
		allow(t, "192.168.1.150", 8080),
		allow(t, "10.0.0.0/24", 0),
	}
	var excluded string
	args := c.SidecarRunArgs()
	for _, a := range args {
		if strings.HasPrefix(a, "TUN_EXCLUDED_ROUTES=") {
			excluded = strings.TrimPrefix(a, "TUN_EXCLUDED_ROUTES=")
		}
	}
	if excluded == "" {
		t.Fatalf("no TUN_EXCLUDED_ROUTES env in sidecar args: %s", strings.Join(args, " "))
	}
	// The proxy reachback /32 must still be present (this feature ADDS to it, it
	// does not replace it).
	if !strings.Contains(excluded, mappedHostLoopback+"/32") {
		t.Fatalf("TUN_EXCLUDED_ROUTES %q dropped the proxy reachback %s/32", excluded, mappedHostLoopback)
	}
	for _, want := range []string{"192.168.1.150/32", "10.0.0.0/24"} {
		if !strings.Contains(excluded, want) {
			t.Fatalf("TUN_EXCLUDED_ROUTES %q missing allowed net %q", excluded, want)
		}
	}
	// The value must be a comma-separated list (the tun2socks env convention), so
	// each excluded route is a distinct entry, not concatenated.
	parts := strings.Split(excluded, ",")
	if len(parts) != 3 {
		t.Fatalf("TUN_EXCLUDED_ROUTES %q must be 3 comma-separated routes (reachback + 2 allowed); got %d: %v", excluded, len(parts), parts)
	}
}

// TestFirewallScript_AllowlistAcceptsBeforeDropsWithRFC1918Drops: with a
// non-empty allowlist, firewallScript emits an ACCEPT for each entry BEFORE the
// RFC1918-range drops (the narrowing half of the spike), and the RFC1918 drops
// appear AFTER as defense-in-depth. A port-less entry accepts all TCP ports to
// that net; UDP stays hard-dropped throughout. (iptables syntax since ADR-0006:
// the sidecar applies its own firewall.)
func TestFirewallScript_AllowlistAcceptsBeforeDropsWithRFC1918Drops(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{
		allow(t, "192.168.1.150", 8080),
		allow(t, "10.1.2.0/24", 0),
	}
	rs := c.firewallScript("9050")

	acceptWithPort := "iptables -A OUTPUT -p tcp -d 192.168.1.150/32 --dport 8080 -j ACCEPT"
	acceptAllPorts := "iptables -A OUTPUT -p tcp -d 10.1.2.0/24 -j ACCEPT"
	if !strings.Contains(rs, acceptWithPort) {
		t.Fatalf("firewall script missing per-port accept %q\ngot:\n%s", acceptWithPort, rs)
	}
	if !strings.Contains(rs, acceptAllPorts) {
		t.Fatalf("firewall script missing all-TCP-ports accept %q\ngot:\n%s", acceptAllPorts, rs)
	}

	// The RFC1918 + link-local drops must all be present (defense-in-depth).
	rfc1918Drops := []string{
		"iptables -A OUTPUT -d 10.0.0.0/8 -j DROP",
		"iptables -A OUTPUT -d 172.16.0.0/12 -j DROP",
		"iptables -A OUTPUT -d 192.168.0.0/16 -j DROP",
		"iptables -A OUTPUT -d 169.254.0.0/16 -j DROP",
	}
	for _, want := range rfc1918Drops {
		if !strings.Contains(rs, want) {
			t.Fatalf("firewall script missing RFC1918/link-local drop %q\ngot:\n%s", want, rs)
		}
	}

	// Ordering: every accept must come BEFORE every RFC1918 drop, else a
	// non-allowlisted host on the same range would shadow the allowed one.
	firstRFC1918Drop := len(rs)
	for _, d := range rfc1918Drops {
		if idx := strings.Index(rs, d); idx >= 0 && idx < firstRFC1918Drop {
			firstRFC1918Drop = idx
		}
	}
	for _, accept := range []string{acceptWithPort, acceptAllPorts} {
		if idx := strings.Index(rs, accept); idx < 0 || idx > firstRFC1918Drop {
			t.Fatalf("allow accept must precede the RFC1918 drops (accept-before-drop); accept at %d, first drop at %d\n%s", idx, firstRFC1918Drop, rs)
		}
	}

	// UDP hard-drop is untouched (ADR-0003): directs are TCP-only.
	if !strings.Contains(rs, "iptables -A OUTPUT -p udp -j DROP") {
		t.Fatalf("UDP must still be hard-dropped even with an allowlist\ngot:\n%s", rs)
	}
}

// TestFirewallScript_AllPortsAllowExcludesClearDNS: a PORT-OMITTED (all-TCP-ports)
// allow must NOT carry clear DNS to the LAN host (row 2 of the Tails leak
// catalogue). The all-ports accept would otherwise include tcp/53, opening a
// direct clear TCP-DNS hole to a LAN resolver (which can reveal the local
// network's public IP). The fix: emit a DROP for the clear-DNS ports (53/853/5353)
// to that net BEFORE the all-ports accept, so 53 falls to the loopback
// DNS-over-SOCKS forwarder (never direct to the LAN) while every other TCP port
// stays reachable. iptables is first-match, so the DROP shadows the accept for 53.
func TestFirewallScript_AllPortsAllowExcludesClearDNS(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{allow(t, "192.168.1.150", 0)} // all TCP ports
	rs := c.firewallScript("9050")

	allPortsAccept := "iptables -A OUTPUT -p tcp -d 192.168.1.150/32 -j ACCEPT"
	if !strings.Contains(rs, allPortsAccept) {
		t.Fatalf("all-ports allow must still accept non-DNS TCP %q\ngot:\n%s", allPortsAccept, rs)
	}

	// The clear-DNS ports must be DROPPED to that net, and each drop must precede
	// the all-ports accept (iptables first-match: the DROP must shadow the accept).
	acceptIdx := strings.Index(rs, allPortsAccept)
	for _, port := range []int{53, 853, 5353} {
		drop := "iptables -A OUTPUT -p tcp -d 192.168.1.150/32 --dport " + strconv.Itoa(port) + " -j DROP"
		idx := strings.Index(rs, drop)
		if idx < 0 {
			t.Fatalf("all-ports allow must DROP clear-DNS port %d to the net %q\ngot:\n%s", port, drop, rs)
		}
		if idx > acceptIdx {
			t.Fatalf("clear-DNS DROP for %d must PRECEDE the all-ports accept (first-match); drop at %d, accept at %d\n%s", port, idx, acceptIdx, rs)
		}
	}
}

// TestFirewallScript_PortScopedAllowCarriesNoDNSExclusion: a PORT-SCOPED allow
// (an explicit non-DNS port) needs NO 53-exclusion drop, because it only opens
// that one port; the guardrail already rejects an explicit :53 at the CLI. So the
// 53-drop shape appears ONLY for the port-omitted (all-ports) case, keeping the
// per-port rule minimal.
func TestFirewallScript_PortScopedAllowCarriesNoDNSExclusion(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{allow(t, "192.168.1.150", 8080)}
	rs := c.firewallScript("9050")
	if strings.Contains(rs, "--dport 53 -j DROP") {
		t.Fatalf("a port-scoped (non-DNS) allow must not emit a 53-exclusion drop\ngot:\n%s", rs)
	}
}

// TestFirewallScript_EmptyAllowlistByteIdenticalToToday: an EMPTY allowlist must
// produce a script BYTE-IDENTICAL to today's (no accept rules, no RFC1918 drops,
// which do not exist in the default jail). This is the off-by-default invariant;
// the existing TestFirewallScript_* tests guard the content, this guards that an
// empty allowlist adds literally nothing.
func TestFirewallScript_EmptyAllowlistByteIdenticalToToday(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	withEmpty := c.firewallScript("9050")

	c.AllowDirect = nil
	withNil := c.firewallScript("9050")
	if withEmpty != withNil {
		t.Fatalf("empty vs nil allowlist differ; both must be today's ruleset\nempty:\n%s\nnil:\n%s", withEmpty, withNil)
	}

	// No allowlist artifacts may appear (the only ACCEPTs in the default jail are
	// the loopback-DNS UDP accept and the reachback proxy-port accept).
	for _, forbidden := range []string{
		"iptables -A OUTPUT -d 10.0.0.0/8 -j DROP",
		"iptables -A OUTPUT -d 172.16.0.0/12 -j DROP",
		"iptables -A OUTPUT -d 192.168.0.0/16 -j DROP",
		"iptables -A OUTPUT -d 169.254.0.0/16 -j DROP",
		"iptables -A OUTPUT -p tcp -d 192.168",
	} {
		if strings.Contains(withEmpty, forbidden) {
			t.Fatalf("empty allowlist must NOT add %q (it does not exist in today's jail)\ngot:\n%s", forbidden, withEmpty)
		}
	}
}

// TestSidecarRunArgs_EmptyAllowlistByteIdenticalToToday: an EMPTY allowlist must
// leave TUN_EXCLUDED_ROUTES byte-identical to today (exactly the proxy reachback
// /32, no extra routes), so the existing forced-egress / teardown tests do not
// regress.
func TestSidecarRunArgs_EmptyAllowlistByteIdenticalToToday(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true

	// The excluded-routes value must be EXACTLY the reachback /32 (no comma list).
	excluded := ""
	for _, a := range c.SidecarRunArgs() {
		if strings.HasPrefix(a, "TUN_EXCLUDED_ROUTES=") {
			excluded = strings.TrimPrefix(a, "TUN_EXCLUDED_ROUTES=")
		}
	}
	if excluded != mappedHostLoopback+"/32" {
		t.Fatalf("empty allowlist TUN_EXCLUDED_ROUTES must be exactly %s/32 (today's value); got %q", mappedHostLoopback, excluded)
	}

	withEmpty := strings.Join(c.SidecarRunArgs(), " ")
	c.AllowDirect = nil
	withNil := strings.Join(c.SidecarRunArgs(), " ")
	if withEmpty != withNil {
		t.Fatalf("empty vs nil allowlist sidecar args differ:\nempty: %s\nnil:   %s", withEmpty, withNil)
	}
}
