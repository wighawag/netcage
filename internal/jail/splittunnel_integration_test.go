//go:build integration
// +build integration

package jail_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/socks5hfixture"
)

// findDirectTarget discovers a real, directly-reachable RFC1918/link-local
// HOST:PORT to use as the split-tunnel direct in the integration test. The
// split-tunnel mechanism egresses the excluded destination over the REAL NIC via
// pasta (it does NOT go through the fixture), so the target must be a genuinely
// reachable LAN service, exactly as the spike used a real llama.cpp on
// 192.168.1.150:8080. It honours NETCAGE_TEST_DIRECT=host:port for an explicit
// target, else probes the default gateway on a couple of common TCP ports (a LAN
// gateway is the one RFC1918 host a test host almost always has). Returns "" if
// none is reachable, so the test can Skip rather than assert against nothing.
func findDirectTarget(t *testing.T) (host string, port int) {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv("NETCAGE_TEST_DIRECT")); v != "" {
		h, p, err := net.SplitHostPort(v)
		if err != nil {
			t.Fatalf("NETCAGE_TEST_DIRECT=%q is not host:port: %v", v, err)
		}
		pn, _ := net.LookupPort("tcp", p)
		return h, pn
	}
	gw := defaultGateway(t)
	if gw == "" || net.ParseIP(gw) == nil {
		return "", 0
	}
	if !isPrivateOrLinkLocal(net.ParseIP(gw)) {
		return "", 0
	}
	for _, p := range []int{53, 80, 443} {
		if tcpReachable(gw, p, 2*time.Second) {
			return gw, p
		}
	}
	return "", 0
}

func defaultGateway(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", "ip route | awk '/^default/{print $3; exit}'").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func isPrivateOrLinkLocal(ip net.IP) bool {
	return ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func tcpReachable(host string, port int, to time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), to)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestJail_SplitTunnel_DirectReachableRestForcedThroughProxy is the podman-gated
// proof of the split-tunnel allowlist end to end (the spike's decisive matrix,
// reproduced against netcage's real wiring + the socks5h fixture):
//
//   - an ALLOWLISTED direct (a reachable RFC1918/link-local host:port) is reached
//     DIRECTLY over the LAN (it answers on TCP);
//   - a NON-allowlisted host on the SAME private range is BLOCKED (dropped by the
//     RFC1918 defense-in-depth rule, so allowing one host does not expose its
//     neighbours);
//   - a PUBLIC destination still exits via the PROXY (the observed exit IP is the
//     fixture's, not the host's), so the allowlist is a narrow hole, not a policy
//     flip; and
//   - UDP to the allowlisted host is DROPPED (ADR-0003 intact; directs are
//     TCP-only).
//
// The run leaves NO run-attributable residue. It Skips without podman, and Skips
// if no reachable RFC1918/link-local direct target exists on the test host (the
// direct egresses the real NIC, so it needs a genuine LAN service, like the
// spike's llama.cpp; set NETCAGE_TEST_DIRECT=host:port to pin one).
func TestJail_SplitTunnel_DirectReachableRestForcedThroughProxy(t *testing.T) {
	requirePodman(t)

	directHost, directPort := findDirectTarget(t)
	if directHost == "" {
		t.Skip("no reachable RFC1918/link-local direct target on this host; set NETCAGE_TEST_DIRECT=host:port to run the split-tunnel integration test")
	}

	echoPort, stopEcho := startExitEcho(t)
	defer stopEcho()

	const exitIP = "127.0.0.2" // the fixture's known exit IP (loopback alias)
	const placeholderIP = "198.51.100.10"
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:         exitIP,
		AllowIPConnect: true,
		RedirectTarget: "127.0.0.1:" + echoPort,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	// A NON-allowlisted host on the SAME /24 as the direct target, which must be
	// blocked. We derive it by flipping the last octet of the direct host to .254
	// (.1 is often the gateway/direct target); if that collides, use .253.
	blockedHost := siblingOnSameRange(directHost)

	runID := "split" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")

	// The tool script exercises all four assertions inside the jail and prints
	// labelled results the test parses:
	//   DIRECT:<ok|fail>   - TCP connect to the allowlisted direct host:port
	//   BLOCKED:<ok|fail>  - TCP connect to a non-allowlisted sibling (must FAIL)
	//   UDP:<ok|fail>      - UDP to the allowlisted host (must FAIL/drop)
	//   EXIT:<ip>          - public fetch by IP, echoed source IP (must be exitIP)
	script := strings.Join([]string{
		"if nc -z -w 4 " + directHost + " " + strconv.Itoa(directPort) + " 2>/dev/null; then echo DIRECT:ok; else echo DIRECT:fail; fi",
		"if nc -z -w 3 " + blockedHost + " " + strconv.Itoa(directPort) + " 2>/dev/null; then echo BLOCKED:reachable; else echo BLOCKED:dropped; fi",
		// UDP to the allowed host must be dropped (ADR-0003), even though TCP to it
		// works. The firewall's UDP rule is a silent DROP (no ICMP), so a UDP
		// probe gets NO answer. We send a UDP DNS query straight to the direct host on
		// :53 (bypassing the jail's own resolv.conf forwarder by naming the server) and
		// assert it gets NO reply: on the LAN that host answers UDP DNS directly, so a
		// no-answer here proves the jail dropped the egress UDP, not that the host is
		// silent. `nslookup` exits non-zero on timeout/no-server.
		// Query a name that DOES resolve (example.com) so a WORKING UDP path returns
		// 0 (UDP:answered); only a dropped egress UDP yields the non-zero/no-answer we
		// assert on. An NXDOMAIN name would false-pass (nslookup also exits non-zero on
		// NXDOMAIN), so we deliberately use a resolvable name.
		"if nslookup -type=A -timeout=3 example.com " + directHost + " >/dev/null 2>&1; then echo UDP:answered; else echo UDP:dropped; fi",
		"echo EXIT:$(wget -qO- -T 8 http://" + placeholderIP + ":" + echoPort + " 2>/dev/null || echo none)",
	}, "; ")

	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", script},
		RunID:               runID,
		AllowDirect: []cli.DirectAllow{
			{
				Network: &net.IPNet{IP: net.ParseIP(directHost), Mask: net.CIDRMask(32, 32)},
				Port:    directPort,
				Raw:     directHost + ":" + strconv.Itoa(directPort),
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err != nil {
		t.Fatalf("jail.Run (split-tunnel): %v\nstderr: %s", err, res.ToolStderr)
	}
	out := res.ToolStdout

	if !strings.Contains(out, "DIRECT:ok") {
		t.Fatalf("allowlisted direct %s:%d was NOT reachable directly over the LAN (excluded route + firewall accept not opening the direct path)\noutput:\n%s", directHost, directPort, out)
	}
	if !strings.Contains(out, "BLOCKED:dropped") {
		t.Fatalf("a NON-allowlisted host %s on the same range was NOT blocked (RFC1918 defense-in-depth drop missing/ineffective)\noutput:\n%s", blockedHost, out)
	}
	if !strings.Contains(out, "UDP:dropped") {
		t.Fatalf("UDP to the allowlisted host was NOT dropped (ADR-0003 breached; directs must be TCP-only)\noutput:\n%s", out)
	}
	if !strings.Contains(out, "EXIT:") || !strings.Contains(out, exitIP) {
		t.Fatalf("public destination did NOT exit via the proxy (expected exit IP %s)\noutput:\n%s", exitIP, out)
	}

	// No run-attributable container may remain (no residue).
	psOut, _ := exec.CommandContext(ctx, "podman", "ps", "-a", "--format", "{{.Names}}").CombinedOutput()
	if strings.Contains(string(psOut), "netcage-run-"+runID) {
		t.Fatalf("split-tunnel run left run-attributable residue:\n%s", psOut)
	}
}

// siblingOnSameRange returns a different host on the same /24 as the given IPv4
// address, for the non-allowlisted-blocked assertion. It flips the last octet to
// .254 (or .253 if the target already ends .254), so the sibling is on the same
// private range but is NOT the allowlisted host.
func siblingOnSameRange(host string) string {
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return host
	}
	last := byte(254)
	if ip[3] == 254 {
		last = 253
	}
	return net.IPv4(ip[0], ip[1], ip[2], last).String()
}
