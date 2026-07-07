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

// otherLoopbackMarker is printed by the jailed probe IFF a TCP connect to a
// DIFFERENT loopback service (a host service reached via the pasta host-loopback
// reachback on a NON-proxy port) egressed the jail. That is the Tails row-6 leak
// (another 127.0.0.1 destination used as an escape hatch); the pasta reachback is
// narrowed to EXACTLY the proxy port (ADR-0002), so this connect must be DROPPED
// and the marker must be ABSENT.
const otherLoopbackMarker = "OTHER-LOOPBACK-REACHED"

// startPlainTCPEcho serves a tiny TCP service on host loopback that closes the
// connection after writing a fixed byte, so a jailed `nc -z` that SUCCEEDS in
// connecting proves the pasta reachback carried a NON-proxy-port loopback
// connection to the host (a LEAK). It is a REAL, up host service on its own port,
// so a failed connect through the jail is provably the firewall DROP, not an
// unreachable/absent service. Returns the chosen port.
func startPlainTCPEcho(t *testing.T) (port string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("other-loopback echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("x"))
			}(c)
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p, func() { ln.Close() }
}

// TestVerify_JailLoopbackConfined is the Tails row-6 live assertion (a different
// loopback service used as an escape hatch): from inside the jail, a connection
// to a DIFFERENT 127.0.0.1 service is DROPPED, while the jail's OWN intended
// loopback (the in-jail DNS-over-SOCKS forwarder) IS reachable. It proves the
// jail is confined to its own loopback:
//
//   - OTHER LOOPBACK (the leak leg): a `nc -z` from the jail to the pasta-mapped
//     host loopback (mappedHostLoopback) on a NON-proxy port aims at a REAL, up
//     host TCP service. ADR-0002 narrows the reachback to EXACTLY the proxy port
//     (`-p tcp -d <map> --dport <proxy> -j ACCEPT`, then `-d <map> -j DROP`), so
//     the connect is DROPPED and otherLoopbackMarker never comes back. A real,
//     listening service makes the silence provably a DROP, not an absent host.
//   - FORWARDER (the non-vacuity leg): the jail's own resolv.conf resolver
//     (127.0.0.1:53, the DNS-over-SOCKS forwarder) resolves uniqueName to the
//     proxy-side answer, printing forwarderReachableMarker. This confirms the
//     INTENDED loopback works, so "everything on loopback is dropped" cannot pass
//     trivially and hide a broken forwarder.
//
// The PASS is confinement: only the intended loopback works. The assertion INTENT
// mirrors anonctl's `bypass-loopback-closure` (only the intended loopback,
// everything else dropped). The most leak-prone seam is the pasta host-loopback
// reachback (ADR-0002 flags it as the single most leak-prone seam), so this
// off-target loopback probe is a meaningful test.
//
// Isolated to a throwaway EPHEMERAL probe container (remove-both, no residue) via
// the shared verify integration harness; the host is untouched.
func TestVerify_JailLoopbackConfined(t *testing.T) {
	requirePodman(t)

	// The fixture is the DNS-over-SOCKS upstream so the jail's loopback forwarder
	// resolves uniqueName proxy-side (the FORWARDER / non-vacuity leg). It is a
	// host-loopback proxy, so the pasta host-loopback reachback (the seam under
	// test) is active.
	resolverPort := startDNSOverTCP(t)
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:     exitIP,
		KnownHosts: map[string]string{upstreamName: resolverIP},
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	// A REAL, up host TCP service on ITS OWN (non-proxy) loopback port: reached via
	// the pasta map it is the OTHER 127.0.0.1 service the jail must NOT pivot to. A
	// listening service makes a failed connect through the jail provably a DROP.
	otherPort, stopOther := startPlainTCPEcho(t)
	defer stopOther()
	if otherPort == proxyPort {
		t.Skipf("other-loopback echo port %s collided with the proxy port; rerun", otherPort)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	check := verify.Check{Name: "jail-loopback-confined", Run: func(ctx context.Context) verify.Assertion {
		// Two legs in one jailed probe:
		//   OTHER LOOPBACK: a `nc -z` to the pasta map on a NON-proxy port -> must be
		//     DROPPED. Prints otherLoopbackMarker ONLY if the connect succeeded (the
		//     jail reached a different loopback service, the leak).
		//   FORWARDER: the jail's own resolv.conf resolver (127.0.0.1:53) resolves the
		//     unique name proxy-side; the forwarder-leg marker is emitted below iff it
		//     resolved to the proxy-side answer.
		// The `-w` bound keeps a dropped connect from hanging the probe.
		script := strings.Join([]string{
			// OTHER LOOPBACK: connect to a DIFFERENT loopback service (pasta map, a
			// non-proxy port). A success means the jail pivoted to another 127.0.0.1
			// destination (a LEAK).
			"if nc -z -w 4 " + mappedHostLoopback + " " + otherPort + " 2>/dev/null; then echo " + otherLoopbackMarker + "; fi",
			// FORWARDER: the jail's own loopback resolver resolves the unique name.
			"nslookup " + uniqueName + " 2>&1 || true",
		}, "; ")
		cfg := jail.Config{
			Ephemeral:           true, // internal one-shot: remove-both, no residue
			Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
			ProxyOnHostLoopback: true,
			Image:               "docker.io/library/alpine:latest",
			DNSUpstream:         upstreamName + ":" + resolverPort,
			ToolArgv:            []string{"sh", "-c", script},
			RunID:               runID("vloop"),
		}
		res, err := verify.DefaultJailRunner(ctx, cfg)
		if err != nil {
			return verify.JailLoopbackConfinedAssertion(false, false, err)
		}
		out := res.ToolStdout
		otherLoopbackReached := strings.Contains(out, otherLoopbackMarker)
		// The forwarder leg is reachable iff it resolved uniqueName to the proxy-side
		// answer AND the proxy actually saw the lookup (proof it went proxy-side).
		forwarderReachable := strings.Contains(out, answerIP) && sawHost(fx.ResolvedHosts(), upstreamName)
		// A dropped OTHER-loopback with a dead forwarder would pass VACUOUSLY under a
		// naive "everything is dropped" check; make the missing-forwarder case an
		// explicit error so it is never mistaken for confinement.
		if !otherLoopbackReached && !forwarderReachable {
			return verify.JailLoopbackConfinedAssertion(false, false,
				fmt.Errorf("non-vacuity leg failed: the jail's OWN loopback forwarder did not resolve %s proxy-side, so a dropped other-loopback connect is not provably confinement; output:\n%s", uniqueName, out))
		}
		return verify.JailLoopbackConfinedAssertion(otherLoopbackReached, forwarderReachable, nil)
	}}

	rep := verify.Run(ctx, []verify.Check{check})
	t.Logf("jail-loopback-confined report:\n%s", rep.String())
	if !rep.Ok() {
		t.Fatalf("the jail must be confined to its own loopback (row 6): a connection to a DIFFERENT 127.0.0.1 service must be dropped while the jail's own DNS-over-SOCKS forwarder still resolves:\n%s", rep.String())
	}
}
