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

// pingRepliedMarker is printed by the jailed probe ONLY if an ICMP echo (`ping`)
// to an off-box address got a reply, i.e. an ICMP packet carrying the real source
// IP egressed the jail and was answered (a LEAK). netcage confines non-TCP (ICMP
// does not ride the TUN-to-SOCKS path), so the reply must NEVER come back and the
// marker must be ABSENT.
const pingRepliedMarker = "ICMP-REPLIED"

// TestVerify_ICMPDropped is the Tails row-4 live assertion (ICMP / raw sockets
// leaking the real IP): from inside the jail, an ICMP echo (`ping`) to an off-box
// address is DROPPED (no reply), so no packet carrying the real source IP reaches
// the network. netcage's jail confines non-TCP: ICMP has no route out (the TUN
// table is only `default dev tun0` and tun2socks relays TCP, not raw ICMP), so
// the echo never egresses.
//
// It is the black-hole/counter shape (like the row-3 IPv6 and row-5 UDP probes),
// NOT the naive "a ping must time out": the CONTROL leg proves forced v4 TCP
// egress is genuinely UP (a v4 by-IP fetch through the jail reaches the proxy's
// exit IP), so the ping SILENCE is the confinement (no ICMP route), not a dead
// probe or an unreachable host. Mirroring anonctl's `pingAsAnon`, a missing
// `ping` binary or any ping error is treated as no-reply = the fail-closed PASS:
// the probe prints pingRepliedMarker ONLY on an actual reply.
//
// The PMTU cost this drop implies is a documented caveat, not a test assertion:
// netcage deliberately does NOT tune PMTU (no `tcp_mtu_probing`); the jailed
// tool's forced traffic rides tun2socks TCP, and no motivating tool needs raw
// ICMP (revisit only if a real tool's PMTU breaks). This keeps the assertion
// INTENT consistent with anonctl's `icmp-drop` (same concept, same PMTU
// resolution).
//
// Isolated to a throwaway EPHEMERAL probe container (remove-both, no residue) via
// the shared verify integration harness; the host is untouched.
func TestVerify_ICMPDropped(t *testing.T) {
	requirePodman(t)

	// The CONTROL leg's proxy + a stand-in "public" v4 echo: a CONNECT to any IP is
	// redirected to a host echo dialed from the fixture's known exit IP, so a v4
	// by-IP fetch through the jail exits via the proxy. This proves the jail is live
	// and forced TCP egress works, so a silent ping is provably the confinement.
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

	const controlMarker = "V4-CONTROL-UP"

	check := verify.Check{Name: "icmp-dropped", Run: func(ctx context.Context) verify.Assertion {
		// Two legs in one jailed probe:
		//   CONTROL: a v4 by-IP fetch through the jail reaches the proxy exit IP
		//     (forced TCP egress is UP), so a silent ping below is the confinement.
		//   ICMP: `ping` a single packet at an off-box address with a short deadline.
		//     It prints pingRepliedMarker ONLY on an actual reply (a LEAK). A missing
		//     `ping`, a timeout, or any error yields NO marker = the fail-closed PASS
		//     (mirroring anonctl's pingAsAnon).
		//
		// The ping target is the pasta-mapped host loopback (an off-box, in-jail
		// unreachable-for-ICMP stand-in): were ICMP not confined, the packet would
		// carry the real source IP out. `-c 1 -W 3` bounds a dropped ping so it
		// cannot hang the probe.
		script := strings.Join([]string{
			// CONTROL: forced v4 egress reaches the proxy exit IP.
			"if wget -qO- -T 8 http://" + placeholder + ":" + echoPort + "/ 2>/dev/null | grep -q " + exitIP + "; then echo " + controlMarker + "; fi",
			// ICMP: a single-packet, short-deadline ping. Print the marker ONLY on a reply.
			"if ping -c 1 -W 3 " + mappedHostLoopback + " >/dev/null 2>&1; then echo " + pingRepliedMarker + "; fi",
		}, "; ")
		cfg := jail.Config{
			Ephemeral:           true, // internal one-shot: remove-both, no residue
			Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
			ProxyOnHostLoopback: true,
			Image:               "docker.io/library/alpine:latest",
			ToolArgv:            []string{"sh", "-c", script},
			RunID:               runID("vicmp"),
		}
		res, err := verify.DefaultJailRunner(ctx, cfg)
		if err != nil {
			return verify.ICMPDroppedAssertion(false, err)
		}
		out := res.ToolStdout
		// CONTROL must be up, else ping silence could be a dead probe, not the
		// confinement -> the probe has no verdict.
		if !strings.Contains(out, controlMarker) {
			return verify.ICMPDroppedAssertion(false,
				fmt.Errorf("control leg failed: forced v4 egress did not reach the proxy exit IP %s, so a silent ping is not provably a DROP; output:\n%s", exitIP, out))
		}
		pingReplied := strings.Contains(out, pingRepliedMarker)
		return verify.ICMPDroppedAssertion(pingReplied, nil)
	}}

	rep := verify.Run(ctx, []verify.Check{check})
	t.Logf("icmp-dropped report:\n%s", rep.String())
	if !rep.Ok() {
		t.Fatalf("ICMP from the jail must be dropped (row 4): an ICMP echo (ping) to an off-box address must get no reply (no real-source-IP ICMP packet reaches the network):\n%s", rep.String())
	}
}
