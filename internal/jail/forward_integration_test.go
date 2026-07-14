//go:build integration
// +build integration

package jail_test

import (
	"context"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/forward"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/socks5hfixture"
)

// TestJail_Forward_KeepsForcedEgressTight is the podman-gated ACCEPTANCE PROOF
// that a `netcage forward` active against a real jail does NOT weaken forced
// egress (spec story 10, ADR-0014): with the forward ATTACHED and reaching the
// in-jail server, the forced-egress three-point leak-test still passes. This
// makes "the forward adds no OUTPUT rule / does not touch forced egress" a TESTED
// property, not merely a design claim.
//
// It reuses the EXISTING leak-test harness (the socks5h fixture, the exit-echo,
// the DNS-over-TCP resolver, the graphroot-isolated TestMain) rather than
// building a parallel one, and asserts, all WHILE the forward is active:
//
//  1. Host access: the host reaches the in-jail server on 127.0.0.1:<hostPort>
//     (the forward's own property).
//  2. Exit IP is the PROXY's: a probe INSIDE the jail exits from the fixture's
//     exit IP, not the host's (forced TCP egress holds).
//  3. DNS is proxy-side: a unique name resolves PROXY-SIDE (the fixture's
//     resolver sees the lookup), never at the host resolver.
//  4. Fail-closed on proxy-kill: with the proxy killed, an in-jail probe does NOT
//     egress (no fallback to the host network).
//
// The exit-IP proof needs a by-IP RedirectTarget fixture and the DNS proof needs
// a clean DNS-over-TCP resolver (RedirectTarget would hijack the resolver dial),
// so they run as separate PHASES that swap the fixture on the SAME proxy port
// (tun2socks dials the proxy per outbound connection, so the swap is seen by the
// next in-jail probe). The jail stays UP and the FORWARD stays ATTACHED across
// every phase: this is the whole point, the leak assertions hold with a forward
// active. A regression that let the forward add an OUTPUT rule / touch egress
// would flip assertion 2, 3, or 4 and FAIL this test.
//
// Shared-write isolation (podman is host-global state): the jail is EPHEMERAL
// (ctx-cancel removes both, no residue), a unique run-id names the pair, and
// t.Cleanup force-removes it even on failure. The forward is a host process torn
// down by cancelling its ctx; the test asserts its host listener is gone
// afterwards, so no host networking state is left behind.
func TestJail_Forward_KeepsForcedEgressTight(t *testing.T) {
	requirePodman(t)

	echoPort, stopEcho := startExitEcho(t)
	defer stopEcho()
	resolverPort := startResumeDNSOverTCP(t)

	// A single fixed proxy port shared across all phases: reserve an ephemeral
	// port, release it, then re-bind the SAME port for each fixture, so every
	// in-jail probe egresses through whatever fixture is currently bound there.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve proxy port: %v", err)
	}
	proxyPort := strconv.Itoa(pl.Addr().(*net.TCPAddr).Port)
	pl.Close()
	proxyAddr := "127.0.0.1:" + proxyPort
	proxyCfg := cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort}

	// The forward maps host <port> -> in-jail <port> for the SAME port value (the
	// `netcage forward <container> <port>` contract: one named port, ListenArgs uses
	// cfg.Port for both the host bind and the in-jail connect). So the in-jail server
	// and the host listener share one port number. Reserve a free ephemeral port and
	// release it, so the in-jail server can bind it inside the netns and the forward's
	// socat can bind it on the host loopback.
	hl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve forward port: %v", err)
	}
	fwdPort := hl.Addr().(*net.TCPAddr).Port
	hl.Close()
	const serverBody = "HELLO-FROM-JAIL-FORWARD" // the in-jail server's reply body
	const placeholderIP = "198.51.100.10"        // routable, so the jail's TUN captures it
	uniqueName := startUniqueName                // resolved proxy-side by startResumeDNSOverTCP
	const exitIP = startExitIP                   // the fixture's known exit IP (loopback alias)

	runID := "fwd" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	t.Cleanup(func() { forceRemoveStartPair(runID) })

	// The tool is a LONG-LIVED jail: it starts a fixed-response HTTP server on
	// 127.0.0.1:<serverPort> (a busybox `nc` accept loop, the shape the spike
	// proved) so the forward has an in-jail server to reach, then blocks so the
	// container stays RUNNING for the whole leak-test. The leak PROBES run via
	// `podman exec` into this running jail (below), not by re-running the tool.
	server := "while true; do printf '%s' " +
		"'HTTP/1.0 200 OK\\r\\nContent-Length: " + strconv.Itoa(len(serverBody)) +
		"\\r\\nConnection: close\\r\\n\\r\\n" + serverBody + "' | nc -l -p " + strconv.Itoa(fwdPort) + " 127.0.0.1; done"
	toolArgv := []string{"sh", "-c", server}

	cfg := jail.Config{
		Proxy:               proxyCfg,
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            toolArgv,
		RunID:               runID,
		DNSUpstream:         startUpstreamName + ":" + resolverPort,
		Ephemeral:           true, // ctx-cancel removes both: no residue
	}

	toolName := "netcage-run-" + runID + "-tool"

	// The sidecar's firewall is VERIFIED at boot (the run path's fail-closed
	// preflight), so the proxy must be REACHABLE on the shared port while the jail
	// comes up. Bind a plain exit-IP fixture there BEFORE jail.Run and hold it
	// through startup + assertions 1-2; the per-assertion phases below swap the
	// fixture on this SAME port.
	bootFx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:         exitIP,
		AllowIPConnect: true,
		RedirectTarget: "127.0.0.1:" + echoPort,
	})
	if err := bootFx.Start(proxyAddr); err != nil {
		t.Fatalf("boot fixture start: %v", err)
	}
	bootFxClosed := false
	closeBootFx := func() {
		if !bootFxClosed {
			bootFx.Close()
			bootFxClosed = true
		}
	}
	t.Cleanup(closeBootFx)

	// --- Stand up the long-lived jail. jail.Run blocks (the tool loops), so run it
	// in a goroutine and tear it down by cancelling its ctx at the end. ---
	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		// A non-nil error after cancel is the expected interruption, not a failure.
		_, _ = jail.Run(runCtx, jail.ExecRunner{}, cfg)
	}()
	t.Cleanup(func() { cancelRun(); <-runDone })

	waitToolRunning(t, toolName)
	// Give the in-jail server's accept loop a moment to bind, so the forward's
	// connect side (and assertion 1) has a server to reach.
	waitInJailListening(t, toolName, fwdPort)

	// --- Stand up the FORWARD (loopback default) in a goroutine; it blocks for its
	// lifetime, torn down by cancelling its ctx (the Ctrl-C path). ---
	fwdCtx, cancelFwd := context.WithCancel(context.Background())
	fwdDone := make(chan struct{})
	go func() {
		defer close(fwdDone)
		_ = forward.Run(fwdCtx, jail.ExecRunner{},
			forward.Config{Container: toolName, Port: fwdPort, Bind: "127.0.0.1"},
			forward.IO{Stdout: io.Discard, Stderr: io.Discard})
	}()

	// --- Assertion 1: HOST ACCESS. The host reaches the in-jail server through the
	// forward at 127.0.0.1:<fwdPort>. ---
	if body := hostGetWithin(t, "127.0.0.1:"+strconv.Itoa(fwdPort), 20*time.Second); !strings.Contains(body, serverBody) {
		cancelFwd()
		<-fwdDone
		t.Fatalf("host must reach the in-jail server through the forward at 127.0.0.1:%d; got body %q", fwdPort, body)
	}

	// --- Assertion 2: EXIT IP IS THE PROXY'S (forced TCP egress holds with the
	// forward active). The boot exit-IP fixture is still bound on the shared proxy
	// port; a by-IP fetch INSIDE the jail must echo the fixture's exit IP. ---
	exitOut := execInJail(t, toolName, "wget -qO- -T 8 http://"+placeholderIP+":"+echoPort+" 2>&1 || true")
	closeBootFx() // free the shared port for the DNS fixture phase
	if !strings.Contains(exitOut, exitIP) {
		cancelFwd()
		<-fwdDone
		t.Fatalf("with the forward ACTIVE, an in-jail fetch must exit from the PROXY's IP %s (forced egress holds); got:\n%s", exitIP, exitOut)
	}

	// --- Assertion 3: DNS IS PROXY-SIDE. Bind the DNS fixture on the shared proxy
	// port; a unique name must resolve to the proxy-side answer AND the fixture must
	// record the upstream lookup (DNS went through the in-jail forwarder to the
	// proxy, not the host resolver). ---
	dnsFx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:     exitIP,
		KnownHosts: map[string]string{startUpstreamName: startResolverIP},
	})
	if err := dnsFx.Start(proxyAddr); err != nil {
		cancelFwd()
		<-fwdDone
		t.Fatalf("dns fixture start: %v", err)
	}
	dnsOut := execInJail(t, toolName, "nslookup "+uniqueName+" 2>/dev/null | grep -F "+startAnswerIP+" || true")
	resolved := dnsFx.ResolvedHosts()
	dnsFx.Close()
	if !strings.Contains(dnsOut, startAnswerIP) {
		cancelFwd()
		<-fwdDone
		t.Fatalf("with the forward ACTIVE, %s must resolve PROXY-SIDE to %s; got:\n%s", uniqueName, startAnswerIP, dnsOut)
	}
	if !sawHost(resolved, startUpstreamName) {
		cancelFwd()
		<-fwdDone
		t.Fatalf("with the forward ACTIVE, the proxy never saw the upstream resolver %q proxy-side; DNS did not go through the in-jail forwarder (saw=%v)", startUpstreamName, resolved)
	}

	// --- Assertion 4: FAIL-CLOSED ON PROXY-KILL. With NOTHING bound on the proxy
	// port (proxy killed), an in-jail by-IP fetch must NOT egress. ---
	failOut := execInJail(t, toolName, "wget -qO- -T 8 http://"+placeholderIP+":"+echoPort+" 2>&1 || true")
	if strings.Contains(failOut, exitIP) || strings.Contains(failOut, serverBody) {
		cancelFwd()
		<-fwdDone
		t.Fatalf("with the proxy KILLED and the forward active, the jail LEAKED (it egressed); it must be fail-closed; got:\n%s", failOut)
	}

	// --- Teardown: cancel the forward (the Ctrl-C path); its host listener must be
	// gone afterwards (no host networking state left behind). ---
	cancelFwd()
	<-fwdDone
	if hostListenerUp("127.0.0.1:"+strconv.Itoa(fwdPort), 3*time.Second) {
		t.Fatalf("after the forward is torn down, the host listener on 127.0.0.1:%d must be GONE (no leftover listener)", fwdPort)
	}
}

// waitToolRunning polls until the tool container reports .State.Running=true (or
// fails the test after a timeout), so the forward + the in-jail probes run against
// a jail that is up. Local to this file (the manage suite has its own copy). The
// budget is generous: the sidecar comes up first and the tool image can pull on a
// cold cache before the tool container reaches Running.
func waitToolRunning(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("podman", podmanTestArgs("inspect", "--format", "{{ .State.Running }}", name)...).CombinedOutput()
		if strings.TrimSpace(string(out)) == "true" {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("container %s did not reach Running within the timeout", name)
}

// waitInJailListening polls (via podman exec) until a TCP server is listening on
// 127.0.0.1:<port> inside the tool container, so the forward's connect side has a
// server to reach.
func waitInJailListening(t *testing.T, toolName string, port int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out := execInJail(t, toolName, "nc -z -w 1 127.0.0.1 "+strconv.Itoa(port)+" && echo UP || true")
		if strings.Contains(out, "UP") {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("in-jail server never came up on 127.0.0.1:%d", port)
}

// execInJail runs a shell command INSIDE the tool container's netns (a plain
// `podman exec`, so it shares the jail's forced-egress firewall) and returns its
// combined output. It is the seam the leak PROBES run through while the forward is
// attached and the jail stays up.
func execInJail(t *testing.T, toolName, shellCmd string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "podman",
		podmanTestArgs("exec", toolName, "sh", "-c", shellCmd)...).CombinedOutput()
	return string(out)
}

// hostGetWithin dials addr on the host and does a minimal HTTP GET, retrying until
// deadline, returning the response body (or "" on timeout). Used to assert the
// host reaches the in-jail server through the forward.
func hostGetWithin(t *testing.T, addr string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if body := hostGetOnce(addr); body != "" {
			return body
		}
		time.Sleep(300 * time.Millisecond)
	}
	return ""
}

func hostGetOnce(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"); err != nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(c, 4096))
	return string(b)
}

// hostListenerUp reports whether SOMETHING is accepting connections on addr on the
// host within a short window, used to assert the forward's listener is GONE after
// teardown.
func hostListenerUp(addr string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
