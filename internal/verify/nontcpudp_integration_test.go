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

// udpReplyMarker is the ASCII payload a reachable host UDP echo replies with, so
// a jailed `nc -u` that sends AND receives it proves a raw UDP datagram egressed
// the jail to the real host network (a LEAK). netcage hard-drops ALL UDP
// (ADR-0003), so the reply must NEVER come back and the marker must be ABSENT.
const udpReplyMarker = "UDP-EGRESSED"

// startUDPEcho serves a UDP echo on host loopback (127.0.0.1:<ephemeral>),
// replying to every datagram with udpReplyMarker. Reached through the jail at the
// pasta-mapped host loopback (mappedHostLoopback), it is the reply source that
// makes a raw-UDP leak OBSERVABLE: if the jail's UDP drop failed, the datagram
// would reach this echo and the marker would come back. Returns the chosen port.
func startUDPEcho(t *testing.T) (port string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = pc.WriteTo([]byte(udpReplyMarker), addr)
			_ = n
		}
	}()
	_, p, _ := net.SplitHostPort(pc.LocalAddr().String())
	return p, func() { pc.Close() }
}

// TestVerify_NonTCPUDPDropped is the Tails row-5 live assertion (raw non-53 UDP
// incl. UDP/443 QUIC): from inside the jail, a raw non-53 UDP datagram to an
// off-box host, AND specifically a UDP/443 (QUIC / HTTP-3) datagram, are DROPPED.
// It proves both raw-UDP egress paths fail closed:
//
//   - GENERIC UDP: a `nc -u` send-and-receive against a host UDP echo (reached at
//     the pasta-mapped host loopback on a non-53, non-443 port) gets NO reply.
//     netcage's firewall drops ALL egress UDP (ADR-0003, `-p udp -j DROP`), so the
//     echo is never reached and udpReplyMarker never comes back.
//   - UDP/443 (QUIC): a `nc -u` datagram aimed at :443 of the same pasta-mapped
//     host loopback gets NO reply either; the QUIC destination port is dropped
//     like every other UDP port (the drop is port-agnostic).
//
// This does NOT conflict with DNS: DNS still works DESPITE the UDP drop because
// it is a client-side UDP->TCP conversion via the in-jail DNS-over-SOCKS
// forwarder (ADR-0003 / dns-through-socks-is-tcp-not-udp.md), and this probe
// targets NON-53 UDP, so it never touches the DNS path.
//
// It is the black-hole/counter shape (like the row-3 IPv6 probe), NOT the naive
// "a UDP send must time out": the CONTROL leg proves forced v4 TCP egress is
// genuinely UP (a v4 by-IP fetch through the jail reaches the proxy's exit IP),
// so the UDP SILENCE is the firewall DROP, not a dead probe or an unreachable
// echo. The GENERIC leg is the strong reply-based proof (a real echo would answer
// if UDP egressed); the :443 leg proves the QUIC destination port is dropped the
// same way. The assertion INTENT mirrors anonctl's equivalent non-tcp-udp-drop
// assertion (UDP dropped, not proxied); a real client is expected to degrade to
// TCP, which is client behaviour (a docs note), not asserted here.
//
// Isolated to throwaway EPHEMERAL probe containers (remove-both, no residue) via
// the shared verify integration harness; the host is untouched.
func TestVerify_NonTCPUDPDropped(t *testing.T) {
	requirePodman(t)

	// The CONTROL leg's proxy + a stand-in "public" v4 echo: a CONNECT to any IP is
	// redirected to a host echo dialed from the fixture's known exit IP, so a v4
	// by-IP fetch through the jail exits via the proxy. This proves the jail is live
	// and forced TCP egress works, so a silent UDP attempt is provably a DROP.
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

	// The host UDP echo: reached through the jail at the pasta map, it is the reply
	// source that would make a raw-UDP leak observable. On a non-53, non-443 port so
	// the GENERIC leg is a genuine "raw non-53 UDP" attempt.
	udpPort, stopUDP := startUDPEcho(t)
	defer stopUDP()
	if udpPort == proxyPort || udpPort == "53" || udpPort == "443" {
		t.Skipf("UDP echo port %s collided with a reserved/proxy port; rerun", udpPort)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	const (
		controlMarker = "V4-CONTROL-UP"
		udpMarker     = udpReplyMarker
	)

	check := verify.Check{Name: "non-tcp-udp-dropped", Run: func(ctx context.Context) verify.Assertion {
		// Three legs in one jailed probe:
		//   CONTROL: a v4 by-IP fetch through the jail reaches the proxy exit IP
		//     (forced TCP egress is UP), so UDP silence below is a genuine drop.
		//   GENERIC UDP: `nc -u` send-and-receive to the host UDP echo (pasta map, a
		//     non-53/non-443 port); prints udpReplyMarker ONLY if the reply came back
		//     (i.e. the datagram egressed the jail).
		//   UDP/443 (QUIC): `nc -u` to :443 of the same host; prints udpReplyMarker
		//     ONLY if a reply came back (the QUIC destination port egressed).
		// The `-w` bound keeps a dropped datagram from hanging the probe.
		script := strings.Join([]string{
			// CONTROL: forced v4 egress reaches the proxy exit IP.
			"if wget -qO- -T 8 http://" + placeholder + ":" + echoPort + "/ 2>/dev/null | grep -q " + exitIP + "; then echo " + controlMarker + "; fi",
			// GENERIC non-53 UDP: send a byte to the host UDP echo and read the reply. If
			// the reply (udpReplyMarker) comes back, raw UDP egressed the jail (a LEAK).
			"echo probe | nc -u -w 4 " + mappedHostLoopback + " " + udpPort + " 2>/dev/null | grep -q " + udpMarker + " && echo " + udpMarker + "-GENERIC || true",
			// UDP/443 (QUIC): same, aimed at :443. A reply means the QUIC dport egressed.
			"echo probe | nc -u -w 4 " + mappedHostLoopback + " 443 2>/dev/null | grep -q " + udpMarker + " && echo " + udpMarker + "-QUIC || true",
		}, "; ")
		cfg := jail.Config{
			Ephemeral:           true, // internal one-shot: remove-both, no residue
			Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
			ProxyOnHostLoopback: true,
			Image:               "docker.io/library/alpine:latest",
			ToolArgv:            []string{"sh", "-c", script},
			RunID:               runID("vudp"),
		}
		res, err := verify.DefaultJailRunner(ctx, cfg)
		if err != nil {
			return verify.NonTCPUDPDroppedAssertion(false, false, err)
		}
		out := res.ToolStdout
		// CONTROL must be up, else UDP silence could be a dead probe, not a drop ->
		// the probe has no verdict.
		if !strings.Contains(out, controlMarker) {
			return verify.NonTCPUDPDroppedAssertion(false, false,
				fmt.Errorf("control leg failed: forced v4 egress did not reach the proxy exit IP %s, so a silent UDP attempt is not provably a DROP; output:\n%s", exitIP, out))
		}
		udpReached := strings.Contains(out, udpMarker+"-GENERIC")
		quic443Reached := strings.Contains(out, udpMarker+"-QUIC")
		return verify.NonTCPUDPDroppedAssertion(udpReached, quic443Reached, nil)
	}}

	rep := verify.Run(ctx, []verify.Check{check})
	t.Logf("non-tcp-udp-dropped report:\n%s", rep.String())
	if !rep.Ok() {
		t.Fatalf("raw non-53 UDP incl. UDP/443 (QUIC) must be dropped (row 5): a generic UDP datagram and a UDP/443 datagram from the jail must both fail to reach the real network:\n%s", rep.String())
	}
}
