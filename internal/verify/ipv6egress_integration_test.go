//go:build integration
// +build integration

package verify_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/socks5hfixture"
	"github.com/wighawag/netcage/internal/verify"
)

// v6PublicLiteral is a well-known always-up public IPv6 address (Cloudflare's
// 2606:4700:4700::1111) used as the v6 egress TARGET. The probe attempts to reach
// it two ways (a v6-literal TCP connect and a v6 DNS query aimed at it as a
// resolver); netcage does not carry v6, so BOTH must be dropped. Its actual
// reachability from the host is irrelevant: the CONTROL leg (forced v4 egress
// works) is what proves the jail is live, so v6 SILENCE is a genuine drop, not a
// dead probe or a v6-less host.
const v6PublicLiteral = "2606:4700:4700::1111"

// TestVerify_IPv6EgressFailsClosed is the Tails row-3 live assertion (IPv6 as a
// total bypass): from inside the jail, ANY IPv6 egress fails closed. It proves
// both v6 paths are dropped:
//
//   - v6 TCP: a v6-literal TCP connect (nc -6 to v6PublicLiteral:80) does NOT
//     reach the real network. netcage forces v4 through the TUN with CLONE_MAIN=0,
//     so the netns has only a v4 `default dev tun0`; v6 TCP is unrouted.
//   - v6 DNS: a DNS query aimed DIRECTLY at a v6 resolver (nslookup ...
//     <v6-literal>) does NOT get an answer. Egress v6 UDP is hard-dropped
//     (firewallScript's ip6tables DROP) and there is no v6 route, so the v6 DNS
//     path fails closed.
//
// It is the black-hole/counter shape (like the row-2 no-clear-LAN-DNS probe),
// NOT the naive "a v6 dig must time out": the CONTROL leg proves forced v4 egress
// is genuinely UP (a v4 by-IP fetch through the jail reaches the proxy's exit
// IP), so the v6 SILENCE is the drop/unroute, not a dead probe. The assertion
// INTENT mirrors anonctl's equivalent v6-drop assertion (v6 dropped, not
// proxied).
//
// Isolated to throwaway EPHEMERAL probe containers (remove-both, no residue) via
// the shared verify integration harness; the host is untouched.
func TestVerify_IPv6EgressFailsClosed(t *testing.T) {
	requirePodman(t)

	// The proxy + a stand-in "public" v4 echo: a CONNECT to any IP is redirected
	// to a host echo dialed from the fixture's known exit IP, so a v4 by-IP fetch
	// through the jail exits via the proxy. This is the CONTROL leg: it proves the
	// jail is live and forced v4 egress works, so a silent v6 attempt is provably a
	// DROP, not an unreachable/dead probe.
	echoPort, stopEcho := startHTTPExitEcho(t)
	defer stopEcho()
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	const (
		controlMarker = "V4-CONTROL-UP"
		v6TCPMarker   = "V6-TCP-REACHED"
		v6DNSMarker   = "V6-DNS-REACHED"
	)

	check := verify.Check{Name: "ipv6-egress-fails-closed", Run: func(ctx context.Context) verify.Assertion {
		// Three legs in one jailed probe:
		//   CONTROL: a v4 by-IP fetch through the jail reaches the proxy exit IP
		//     (forced v4 egress is UP), so v6 silence below is a genuine drop.
		//   V6-TCP: a v6-literal TCP connect; prints v6TCPMarker ONLY if it egressed.
		//   V6-DNS: a DNS query aimed at the v6 literal as a resolver; prints
		//     v6DNSMarker ONLY if it got an answer (i.e. v6 egress reached a resolver).
		// The `-w`/`-timeout` bounds keep a dropped attempt from hanging the probe.
		script := strings.Join([]string{
			// CONTROL: forced v4 egress reaches the proxy exit IP.
			"if wget -qO- -T 8 http://" + placeholder + ":" + echoPort + "/ 2>/dev/null | grep -q " + exitIP + "; then echo " + controlMarker + "; fi",
			// V6-TCP: connect to the public v6 literal on :80. If it connects, v6 egress
			// reached the real network (a LEAK). -6 forces v6; -w bounds the wait.
			"if nc -6 -z -w 6 " + v6PublicLiteral + " 80 2>/dev/null; then echo " + v6TCPMarker + "; fi",
			// V6-DNS: aim a DNS query straight at the v6 literal as the resolver. Reaching
			// it at all is v6 egress; an answer means the v6 DNS path egressed (a LEAK).
			"if nslookup -timeout=5 example.com " + v6PublicLiteral + " >/dev/null 2>&1; then echo " + v6DNSMarker + "; fi",
		}, "; ")
		cfg := jail.Config{
			Ephemeral:           true, // internal one-shot: remove-both, no residue
			Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
			ProxyOnHostLoopback: true,
			Image:               "docker.io/library/alpine:latest",
			ToolArgv:            []string{"sh", "-c", script},
			RunID:               runID("vipv6"),
		}
		res, err := verify.DefaultJailRunner(ctx, cfg)
		if err != nil {
			return verify.IPv6EgressFailsClosedAssertion(false, false, err)
		}
		out := res.ToolStdout
		// CONTROL must be up, else v6 silence could be a dead probe, not a drop ->
		// the probe has no verdict.
		if !strings.Contains(out, controlMarker) {
			return verify.IPv6EgressFailsClosedAssertion(false, false,
				fmt.Errorf("control leg failed: forced v4 egress did not reach the proxy exit IP %s, so a silent v6 attempt is not provably a DROP; output:\n%s", exitIP, out))
		}
		v6TCPReached := strings.Contains(out, v6TCPMarker)
		v6DNSReached := strings.Contains(out, v6DNSMarker)
		return verify.IPv6EgressFailsClosedAssertion(v6TCPReached, v6DNSReached, nil)
	}}

	rep := verify.Run(ctx, []verify.Check{check})
	t.Logf("ipv6-egress-fails-closed report:\n%s", rep.String())
	if !rep.Ok() {
		t.Fatalf("IPv6 egress must fail closed (row 3): a v6-literal TCP and a v6 DNS attempt from the jail must both be dropped:\n%s", rep.String())
	}
}
