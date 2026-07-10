package jail

import (
	"net"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// This file is the jail-wiring half of the host-loopback class of --allow
// (ADR-0019, task allow-host-loopback-reachback): a host-loopback DirectAllow
// (127.0.0.0/8) is rewritten to the pasta map address (mappedHostLoopback) at
// rule-emit time, the map + excluded route + DROP closer are emitted whenever
// there is a host-loopback allow (EVEN with a remote proxy), and the empty-allow
// byte-identical strict jail invariant (ADR-0005) is preserved for the model
// case. It is pure logic (no podman); the direct-reachable-but-still-tight
// behaviour is the integration test behind the tag.

// allowLoopback builds a validated host-loopback DirectAllow the way the CLI
// would (127.0.0.0/8 /32 + exact port + HostLoopback class), for the wiring
// tests. It mirrors allow() (the LAN helper) but sets the host-loopback class.
func allowLoopback(t *testing.T, ip string, port int) cli.DirectAllow {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("bad test loopback IP %q", ip)
	}
	return cli.DirectAllow{
		Network:      &net.IPNet{IP: parsed, Mask: net.CIDRMask(32, 32)},
		Port:         port,
		Raw:          ip,
		HostLoopback: true,
	}
}

// TestFirewallScript_HostLoopbackAllow_RewritesToMapAndKeepsClosure: a
// host-loopback allow emits an ACCEPT targeting the pasta MAP address
// (mappedHostLoopback), NOT the user's typed 127.0.0.1, BEFORE the map's DROP
// closer, so exactly the named port is reachable and every other host-loopback
// port stays dropped. The user never types the map address.
func TestFirewallScript_HostLoopbackAllow_RewritesToMapAndKeepsClosure(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true // proxy on host loopback
	c.AllowDirect = []cli.DirectAllow{allowLoopback(t, "127.0.0.1", 11434)}
	rs := c.firewallScript("9050")

	// The accept targets the MAP address at the named port (the rewrite).
	mapAccept := "iptables -A OUTPUT -p tcp -d " + mappedHostLoopback + " --dport 11434 -j ACCEPT"
	if !strings.Contains(rs, mapAccept) {
		t.Fatalf("host-loopback allow must accept the MAP address at the named port %q\ngot:\n%s", mapAccept, rs)
	}
	// The user's typed 127.0.0.1 must NEVER appear as a rule destination.
	if strings.Contains(rs, "-d 127.0.0.1 --dport") || strings.Contains(rs, "-d 127.0.0.1/32 --dport") {
		t.Fatalf("host-loopback allow must NOT emit a rule to the typed 127.0.0.1 (it is rewritten to the map)\ngot:\n%s", rs)
	}
	// The map DROP closer keeps every other host-loopback port closed.
	closer := "iptables -A OUTPUT -d " + mappedHostLoopback + " -j DROP"
	if !strings.Contains(rs, closer) {
		t.Fatalf("host-loopback map DROP closer %q missing (closure not tight)\ngot:\n%s", closer, rs)
	}
	// Ordering: the map accept must precede the map DROP closer.
	if strings.Index(rs, mapAccept) > strings.Index(rs, closer) {
		t.Fatalf("map accept must precede the map DROP closer\n%s", rs)
	}
}

// TestFirewallScript_HostLoopbackAllow_RemoteProxyStillGetsMapCloser: a host
// model on loopback needs the map + DROP closer EVEN with a REMOTE proxy (the
// model reachback is orthogonal to the proxy reachback, ADR-0019). Today the map
// closer was only emitted for a host-loopback proxy; this proves it is emitted
// for a remote-proxy jail that has a host-loopback allow.
func TestFirewallScript_HostLoopbackAllow_RemoteProxyStillGetsMapCloser(t *testing.T) {
	c := cfg()
	c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080"}
	c.ProxyOnHostLoopback = false // REMOTE proxy
	c.AllowDirect = []cli.DirectAllow{allowLoopback(t, "127.0.0.1", 11434)}
	rs := c.firewallScript("1080")

	mapAccept := "iptables -A OUTPUT -p tcp -d " + mappedHostLoopback + " --dport 11434 -j ACCEPT"
	closer := "iptables -A OUTPUT -d " + mappedHostLoopback + " -j DROP"
	if !strings.Contains(rs, mapAccept) {
		t.Fatalf("remote-proxy + host-model must still emit the map accept %q\ngot:\n%s", mapAccept, rs)
	}
	if !strings.Contains(rs, closer) {
		t.Fatalf("remote-proxy + host-model must still emit the map DROP closer %q\ngot:\n%s", closer, rs)
	}
}

// TestSidecarRunArgs_HostLoopbackAllow_AddsMapAndExcludedRouteWithRemoteProxy:
// the pasta --map-host-loopback option AND the mappedHostLoopback/32 excluded
// route are present whenever there is a host-loopback allow, INDEPENDENT of proxy
// locality (here a REMOTE proxy). The excluded route is the map address, not the
// user's typed 127.0.0.1.
func TestSidecarRunArgs_HostLoopbackAllow_AddsMapAndExcludedRouteWithRemoteProxy(t *testing.T) {
	c := cfg()
	c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080"}
	c.ProxyOnHostLoopback = false // REMOTE proxy
	c.AllowDirect = []cli.DirectAllow{allowLoopback(t, "127.0.0.1", 11434)}
	args := strings.Join(c.SidecarRunArgs(), " ")

	if !strings.Contains(args, "--map-host-loopback,"+mappedHostLoopback) {
		t.Fatalf("host-loopback allow must add pasta --map-host-loopback,%s even with a remote proxy\nargs: %s", mappedHostLoopback, args)
	}

	var excluded string
	for _, a := range c.SidecarRunArgs() {
		if strings.HasPrefix(a, "TUN_EXCLUDED_ROUTES=") {
			excluded = strings.TrimPrefix(a, "TUN_EXCLUDED_ROUTES=")
		}
	}
	if !strings.Contains(excluded, mappedHostLoopback+"/32") {
		t.Fatalf("host-loopback allow must exclude the map route %s/32 (remote-proxy-plus-host-model); got %q", mappedHostLoopback, excluded)
	}
	if strings.Contains(excluded, "127.0.0.1") {
		t.Fatalf("the excluded route must be the map address, never the typed 127.0.0.1; got %q", excluded)
	}
}

// TestExcludedRoutes_HostLoopbackProxyAndModel_NoDuplicateMapRoute: when the
// proxy is ALSO host-loopback, the map is SHARED (one map address). The excluded
// route must contain mappedHostLoopback/32 exactly ONCE, not duplicated by the
// proxy reachback + the host-model allow both adding it.
func TestExcludedRoutes_HostLoopbackProxyAndModel_NoDuplicateMapRoute(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{allowLoopback(t, "127.0.0.1", 11434)}
	excluded := c.excludedRoutes()
	if got := strings.Count(excluded, mappedHostLoopback+"/32"); got != 1 {
		t.Fatalf("shared map: excluded routes must carry %s/32 exactly once, got %d: %q", mappedHostLoopback, got, excluded)
	}
}

// TestFirewallVerifyRules_HostLoopbackAllow_AssertsMapAcceptAndCloser: the
// post-start verification (the fail-loud layer) must assert the map accept(s) +
// the map DROP closer for a host-loopback allow, so a half-applied host-loopback
// hole is caught loudly.
func TestFirewallVerifyRules_HostLoopbackAllow_AssertsMapAcceptAndCloser(t *testing.T) {
	c := cfg()
	c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080"}
	c.ProxyOnHostLoopback = false // REMOTE proxy, host model only
	c.AllowDirect = []cli.DirectAllow{allowLoopback(t, "127.0.0.1", 11434)}
	v4, _ := c.firewallVerifyRules("1080")

	wantAccept := "-A OUTPUT -d " + mappedHostLoopback + "/32 -p tcp -m tcp --dport 11434 -j ACCEPT"
	wantCloser := "-A OUTPUT -d " + mappedHostLoopback + "/32 -j DROP"
	joined := strings.Join(v4, "\n")
	if !strings.Contains(joined, wantAccept) {
		t.Fatalf("firewallVerifyRules must assert the map accept %q\ngot:\n%s", wantAccept, joined)
	}
	if !strings.Contains(joined, wantCloser) {
		t.Fatalf("firewallVerifyRules must assert the map DROP closer %q\ngot:\n%s", wantCloser, joined)
	}
}

// TestFirewallScript_NoHostLoopbackAllow_ByteIdenticalForModelCase: with NO
// host-loopback allow and a REMOTE proxy, NO map/accept/route/drop is emitted for
// the model case (off-by-default, ADR-0005). A remote-proxy jail with no
// host-loopback allow does NOT get --map-host-loopback.
func TestFirewallScript_NoHostLoopbackAllow_ByteIdenticalForModelCase(t *testing.T) {
	c := cfg()
	c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080"}
	c.ProxyOnHostLoopback = false // remote proxy, no host-loopback allow

	rs := c.firewallScript("1080")
	if strings.Contains(rs, mappedHostLoopback) {
		t.Fatalf("remote-proxy jail with no host-loopback allow must emit NO map rule for the model case\ngot:\n%s", rs)
	}
	args := strings.Join(c.SidecarRunArgs(), " ")
	if strings.Contains(args, "--map-host-loopback") {
		t.Fatalf("remote-proxy jail with no host-loopback allow must NOT get --map-host-loopback\nargs: %s", args)
	}
	if strings.Contains(c.excludedRoutes(), mappedHostLoopback) {
		t.Fatalf("remote-proxy jail with no host-loopback allow must NOT exclude the map route\ngot: %s", c.excludedRoutes())
	}
}

// TestFirewallScript_ClassDispatch_LANvsLoopback_SameEntryPoint: the SAME
// AllowDirect slice carrying a LAN entry AND a host-loopback entry dispatches
// each to its own destination: the LAN entry accepts its LAN /32, the
// host-loopback entry accepts the map address. This is the class-dispatch at the
// rule-emit seam.
func TestFirewallScript_ClassDispatch_LANvsLoopback_SameEntryPoint(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{
		allow(t, "192.168.1.150", 8080),      // LAN class
		allowLoopback(t, "127.0.0.1", 11434), // host-loopback class
	}
	rs := c.firewallScript("9050")

	lanAccept := "iptables -A OUTPUT -p tcp -d 192.168.1.150/32 --dport 8080 -j ACCEPT"
	mapAccept := "iptables -A OUTPUT -p tcp -d " + mappedHostLoopback + " --dport 11434 -j ACCEPT"
	if !strings.Contains(rs, lanAccept) {
		t.Fatalf("LAN entry must accept its LAN /32 %q\ngot:\n%s", lanAccept, rs)
	}
	if !strings.Contains(rs, mapAccept) {
		t.Fatalf("host-loopback entry must accept the map address %q\ngot:\n%s", mapAccept, rs)
	}
}
