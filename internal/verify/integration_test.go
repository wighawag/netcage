//go:build integration
// +build integration

package verify_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/devimage"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/socks5hfixture"
	"github.com/wighawag/netcage/internal/verify"
)

// TestMain builds the netcage-dns helper once (the sidecar execs it in-jail,
// ADR-0006) and points the jail at it via NETCAGE_DNS_BIN, mirroring the jail
// package's own integration TestMain so verify's DNS assertion has the helper.
// It MUST be a STATIC build (CGO_ENABLED=0): the helper execs inside the
// musl-based sidecar image, which cannot load a glibc-dynamic binary.
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("podman"); err == nil {
		dir, err := os.MkdirTemp("", "netcage-dns-bin")
		if err == nil {
			defer os.RemoveAll(dir)
			bin := filepath.Join(dir, "netcage-dns")
			build := exec.Command("go", "build", "-o", bin, "github.com/wighawag/netcage/cmd/netcage-dns")
			build.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, berr := build.CombinedOutput(); berr == nil {
				os.Setenv("NETCAGE_DNS_BIN", bin)
			} else {
				os.Stderr.Write(out)
			}
		}

		// SHARED-WRITE ISOLATION (the graphroot relocation task): isolate the jail's
		// podman graphroot under a per-run SCRATCH dir so the verify leak-test stands
		// up real storage WITHOUT touching the developer's default store. Torn down
		// with `podman --root <tmp> system reset --force` (a plain rm -rf fails on the
		// id-mapped overlay diff/ tree, ADR-0013). Test-side podman calls route through
		// podmanTestArgs to look in the SAME store the product's ExecRunner writes into.
		if store, serr := os.MkdirTemp("/var/tmp", "netcage-verify-itest-store"); serr == nil {
			os.Setenv("NETCAGE_GRAPHROOT", store)
			defer func() {
				resetCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				_ = exec.CommandContext(resetCtx, "podman", "--root", store, "system", "reset", "--force").Run()
				_ = os.RemoveAll(store)
			}()
		}
	}
	os.Exit(m.Run())
}

// podmanTestArgs prefixes a test-side `podman` argv with `--root $NETCAGE_GRAPHROOT`
// when the suite isolated storage under a scratch graphroot (TestMain), so a
// test-side podman call looks in the SAME store the product's ExecRunner writes
// into. A plain pass-through when the env is unset.
func podmanTestArgs(args ...string) []string {
	if store := os.Getenv("NETCAGE_GRAPHROOT"); store != "" {
		return append([]string{"--root", store}, args...)
	}
	return args
}

func requirePodman(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not found; skipping verify integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "podman", "info").Run(); err != nil {
		t.Skip("podman not usable; skipping verify integration test")
	}
}

const (
	exitIP       = "127.0.0.2"           // the fixture's known exit IP (loopback alias)
	uniqueName   = "unique.netcage.test" // a name only the proxy-side resolver knows
	answerIP     = "203.0.113.55"        // the proxy-side answer for uniqueName
	upstreamName = "dns.netcage.test"    // the DNS resolver name, resolved proxy-side
	resolverIP   = "127.0.0.3"           // where the test DNS-over-TCP resolver binds
	placeholder  = "198.18.5.5"          // in-TUN-subnet target so the jail's TUN captures it
)

func runID(prefix string) string {
	return prefix + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
}

// startHTTPExitEcho serves HTTP/1.0 on host loopback, replying with the client's
// observed source IP, so an exit-IP probe through the jail can be checked.
func startHTTPExitEcho(t *testing.T) (port string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("exit echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(make([]byte, 1024))
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Length: "+
					strconv.Itoa(len(host))+"\r\nConnection: close\r\n\r\n"+host)
			}(c)
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p, func() { ln.Close() }
}

// startDNSOverTCP serves DNS-over-TCP on resolverIP:<ephemeral>, answering ONLY
// uniqueName. Returns the chosen port.
func startDNSOverTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", resolverIP+":0")
	if err != nil {
		t.Fatalf("dns resolver listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				resp := buildAResponse(msg, decodeName(msg[12:]))
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = c.Write(out)
			}(c)
		}
	}()
	return port
}

// TestVerify_ExitIPIsProxys is leak assertion #1: an IP-echo through the jail
// observes the FIXTURE's exit IP, not the host's.
func TestVerify_ExitIPIsProxys(t *testing.T) {
	requirePodman(t)

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

	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 8 http://" + placeholder + ":" + echoPort + "/ 2>&1 || true"},
		RunID:               runID("vexit"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	observed, err := verify.ExitIPProbe(ctx, verify.DefaultJailRunner, cfg)
	if err != nil {
		t.Fatalf("exit-IP probe: %v", err)
	}
	if observed != exitIP {
		t.Fatalf("observed exit IP %q; want the proxy's exit IP %q", observed, exitIP)
	}
}

// TestVerify_DNSResolvesProxySideNotHost is leak assertion #2: a unique hostname
// resolves PROXY-SIDE (the proxy's resolver sees the lookup), NOT via the host
// resolver. The host resolver returns NXDOMAIN for the fake TLD, so a successful
// resolution to the proxy-side answer can only have come through the proxy; the
// fixture's ResolvedHosts confirms the proxy did the lookup.
func TestVerify_DNSResolvesProxySideNotHost(t *testing.T) {
	requirePodman(t)

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

	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		DNSUpstream:         upstreamName + ":" + resolverPort,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "nslookup " + uniqueName + " 2>&1 || true"},
		RunID:               runID("vdns"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	out, err := verify.DNSProbe(ctx, verify.DefaultJailRunner, cfg)
	if err != nil {
		t.Fatalf("dns probe: %v", err)
	}

	// Resolved to the proxy-side answer.
	if !strings.Contains(out, answerIP) {
		t.Fatalf("unique name did not resolve to the proxy-side answer %s; output:\n%s", answerIP, out)
	}
	// The host resolver must NOT know this fake TLD: prove it returns no answer.
	if hostResolverKnows(t, uniqueName) {
		t.Fatalf("host resolver unexpectedly resolved %q; the test's no-host-leak premise is void", uniqueName)
	}
	// The proxy saw the lookup (proof it went proxy-side).
	if !sawHost(fx.ResolvedHosts(), upstreamName) {
		t.Fatalf("proxy never resolved %q proxy-side; DNS did not go through the proxy (saw=%v)", upstreamName, fx.ResolvedHosts())
	}
}

// TestVerify_DNSResolvesOverTCPForGlibc guards the glibc `use-vc`/TCP DNS path:
// glibc's getaddrinfo (getent) honours resolv.conf's `options use-vc` and
// queries DNS over TCP, so it exercises the forwarder's TCP listener. A UDP-only
// forwarder answers alpine/musl but leaves glibc images (node/debian/
// buildpack-deps) unable to resolve; this test (verify's glibc DNS-probe image =
// small debian:*-slim = glibc) fails if that regresses. It complements the musl
// nslookup test above.
func TestVerify_DNSResolvesOverTCPForGlibc(t *testing.T) {
	requirePodman(t)

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

	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		DNSUpstream:         upstreamName + ":" + resolverPort,
		Image:               devimage.DNSProbeImageReference(), // small debian:*-slim: glibc + getent
		ToolArgv: []string{
			"sh", "-c",
			"getent ahostsv4 " + uniqueName + " 2>&1 || true",
		},
		RunID: runID("vdnsglibc"),
	}
	// The small debian:*-slim probe image still allows a generous cold-pull budget.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out, err := verify.DNSProbe(ctx, verify.DefaultJailRunner, cfg)
	if err != nil {
		t.Fatalf("glibc dns probe: %v", err)
	}
	// glibc getaddrinfo, over TCP (use-vc), resolved the unique name to the
	// proxy-side answer. A UDP-only forwarder would leave this empty/unresolved.
	if !strings.Contains(out, answerIP) {
		t.Fatalf("glibc getent did not resolve %q to the proxy-side answer %s (forwarder not answering over TCP?); output:\n%s",
			uniqueName, answerIP, out)
	}
	if !sawHost(fx.ResolvedHosts(), upstreamName) {
		t.Fatalf("proxy never resolved %q proxy-side over the glibc/TCP path (saw=%v)", upstreamName, fx.ResolvedHosts())
	}
}

// TestVerify_FailsClosedWhenProxyKilled is leak assertion #3: with the proxy
// killed, a probe through the jail FAILS CLOSED (no egress) rather than falling
// back to the host network.
func TestVerify_FailsClosedWhenProxyKilled(t *testing.T) {
	requirePodman(t)

	// A host echo that, if ever reached, prints a distinctive marker. If the
	// probe ever prints it, the jail leaked to the host network (fail-open).
	const marker = "LEAKED-TO-HOST"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("marker echo listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Length: "+
					strconv.Itoa(len(marker))+"\r\nConnection: close\r\n\r\n"+marker)
			}(c)
		}
	}()
	_, markerPort, _ := net.SplitHostPort(ln.Addr().String())

	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:         exitIP,
		AllowIPConnect: true,
		RedirectTarget: "127.0.0.1:" + markerPort,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	// KILL the proxy before the probe: fail-closed must hold with it down.
	fx.Close()

	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 6 http://" + placeholder + ":" + markerPort + "/ 2>&1 || true"},
		RunID:               runID("vclosed"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	egressed, err := verify.FailClosedProbe(ctx, verify.DefaultJailRunner, cfg, marker)
	if err != nil {
		t.Fatalf("fail-closed probe: %v", err)
	}
	if egressed {
		t.Fatal("probe egressed with the proxy killed: the jail FAILED OPEN (leaked to the host network); want fail-closed")
	}
}

// TestVerify_FullReportGreenAndExitsZero composes all three assertions through
// the verify orchestrator (the shape `netcage verify` uses) and asserts the
// Report is Ok and ExitCode is 0. This is the CI-gating contract: a fully
// leak-proof jail yields a green report and a zero exit; any failure would flip
// ExitCode to non-zero (proven by the unit tests).
func TestVerify_FullReportGreenAndExitsZero(t *testing.T) {
	requirePodman(t)

	echoPort, stopEcho := startHTTPExitEcho(t)
	defer stopEcho()
	resolverPort := startDNSOverTCP(t)

	// One fixture serves the exit-IP + DNS checks; the fail-closed check uses its
	// own killed fixture (below) so it does not disturb this one.
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:         exitIP,
		AllowIPConnect: true,
		KnownHosts:     map[string]string{upstreamName: resolverIP},
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())
	base := func() jail.Config {
		return jail.Config{
			Ephemeral:           true, // internal one-shot: remove-both, no residue
			Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
			ProxyOnHostLoopback: true,
			Image:               "docker.io/library/alpine:latest",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	checks := []verify.Check{
		{Name: "exit-ip-is-proxys", Run: func(ctx context.Context) verify.Assertion {
			// The exit-IP check needs the fixture to redirect every CONNECT to the
			// echo, so it uses its own dedicated redirect fixture.
			return exitIPAssertion(ctx, t, echoPort)
		}},
		{Name: "dns-resolves-proxy-side", Run: func(ctx context.Context) verify.Assertion {
			cfg := base()
			cfg.RunID = runID("vall-dns")
			cfg.DNSUpstream = upstreamName + ":" + resolverPort
			cfg.ToolArgv = []string{"sh", "-c", "nslookup " + uniqueName + " 2>&1 || true"}
			out, err := verify.DNSProbe(ctx, verify.DefaultJailRunner, cfg)
			if err != nil {
				return verify.Assertion{Ok: false, Err: err}
			}
			ok := strings.Contains(out, answerIP) && sawHost(fx.ResolvedHosts(), upstreamName) && !hostResolverKnows(t, uniqueName)
			return verify.Assertion{Ok: ok, Detail: "resolved " + uniqueName + " proxy-side"}
		}},
		{Name: "fails-closed-on-proxy-kill", Run: func(ctx context.Context) verify.Assertion {
			return failClosedAssertion(ctx, t)
		}},
	}

	rep := verify.Run(ctx, checks)
	t.Logf("verify report:\n%s", rep.String())
	if !rep.Ok() {
		t.Fatalf("full verify report is not Ok:\n%s", rep.String())
	}
	if rep.ExitCode() != 0 {
		t.Fatalf("green report must exit 0; got %d", rep.ExitCode())
	}
}

// mappedHostLoopback is the pasta-mapped host-loopback address the jail reaches
// host services at (jail.mappedHostLoopback, unexported; mirrored here for the
// external test). It is link-local (169.254.0.0/16), hence a valid --allow
// entry, and is the ONE host-service address a jail netns can reach
// deterministically without a real LAN host. The direct-reachability probe uses
// it to reach the fixture as the stand-in LAN host.
const mappedHostLoopback = "169.254.1.1"

// allowlist169 builds a split-tunnel allowlist that names the pasta-mapped
// host-loopback address on the given port, so the run is SPLIT-TUNNEL ACTIVE
// (SidecarRunArgs adds the excluded route, firewallScript emits the accept + RFC1918
// drops). This is how verify proves the three core assertions still hold WITH an
// allowlist active (story 8), deterministically and without a real LAN host.
func allowlist169(port string) []cli.DirectAllow {
	p, _ := strconv.Atoi(port)
	return []cli.DirectAllow{{
		Network: &net.IPNet{IP: net.ParseIP(mappedHostLoopback), Mask: net.CIDRMask(32, 32)},
		Port:    p,
		Raw:     mappedHostLoopback + ":" + port,
	}}
}

// TestVerify_SplitTunnelReportGreenOnlyWhenLeakTightAndDirectReachable is the
// split-tunnel acceptance seam (spec story 8): with an allowlist ACTIVE, the
// verify report is green ONLY when (a) the named direct is reachable AND (b) all
// three core leak assertions STILL hold for non-allowlisted traffic. It composes
// the three existing probes (ExitIPProbe / DNSProbe / FailClosedProbe) into core
// Checks that each run through a SPLIT-TUNNEL-ACTIVE jail (Config.AllowDirect
// set), plus a direct-reachability Check (DirectReachableProbe), via
// SplitTunnelChecks, and asserts the composed Report is Ok and exits 0.
//
// The direct endpoint is the socks5hfixture reached at the pasta-mapped host
// loopback (mappedHostLoopback), the one host-service address the jail netns can
// reach deterministically without a real LAN host (see the task Decisions). The
// genuine split-tunnel-accept-over-the-real-NIC proof (an RFC1918 peer reached
// via the firewall accept) lives in the jail package's
// TestJail_SplitTunnel_DirectReachableRestForcedThroughProxy; here the point is
// that the COMPOSED report is green only when the directs work AND the jail is
// still leak-tight outside the allowlist, proven end-to-end against real podman.
//
// The report-fails-on-a-non-allowlisted-leak and no-allowlist-unchanged
// properties are proven at the (podman-free) composition seam in
// verify_test.go (TestSplitTunnelChecks_*); this podman-gated case proves the
// GREEN end-to-end path genuinely passes with a split-tunnel active.
func TestVerify_SplitTunnelReportGreenOnlyWhenLeakTightAndDirectReachable(t *testing.T) {
	requirePodman(t)

	echoPort, stopEcho := startHTTPExitEcho(t)
	defer stopEcho()
	resolverPort := startDNSOverTCP(t)

	// One fixture serves the DNS check + is the stand-in DIRECT endpoint (reached
	// at mappedHostLoopback:<its port>). The exit-IP and fail-closed checks use
	// their own dedicated fixtures (they need a redirect / a killed proxy).
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:         exitIP,
		AllowIPConnect: true,
		KnownHosts:     map[string]string{upstreamName: resolverIP},
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	// The allowlist names the fixture (at the pasta map) as the direct, so every
	// core probe below runs through a SPLIT-TUNNEL-ACTIVE jail.
	allow := allowlist169(proxyPort)
	base := func() jail.Config {
		return jail.Config{
			Ephemeral:           true, // internal one-shot: remove-both, no residue
			Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
			ProxyOnHostLoopback: true,
			Image:               "docker.io/library/alpine:latest",
			AllowDirect:         allow,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	core := []verify.Check{
		{Name: "exit-ip-is-proxys", Run: func(ctx context.Context) verify.Assertion {
			return exitIPAssertionAllow(ctx, t, echoPort, allow)
		}},
		{Name: "dns-resolves-proxy-side", Run: func(ctx context.Context) verify.Assertion {
			cfg := base()
			cfg.RunID = runID("vst-dns")
			cfg.DNSUpstream = upstreamName + ":" + resolverPort
			cfg.ToolArgv = []string{"sh", "-c", "nslookup " + uniqueName + " 2>&1 || true"}
			out, err := verify.DNSProbe(ctx, verify.DefaultJailRunner, cfg)
			if err != nil {
				return verify.Assertion{Ok: false, Err: err}
			}
			ok := strings.Contains(out, answerIP) && sawHost(fx.ResolvedHosts(), upstreamName) && !hostResolverKnows(t, uniqueName)
			return verify.Assertion{Ok: ok, Detail: "resolved " + uniqueName + " proxy-side (split-tunnel active)"}
		}},
		{Name: "fails-closed-on-proxy-kill", Run: func(ctx context.Context) verify.Assertion {
			return failClosedAssertionAllow(ctx, t)
		}},
	}

	const directMarker = "DIRECT-REACHED"
	direct := []verify.Check{
		{Name: "direct-is-reachable", Run: func(ctx context.Context) verify.Assertion {
			cfg := base()
			cfg.RunID = runID("vst-direct")
			// Reach the fixture (the stand-in LAN host) at the pasta map: a successful
			// TCP connect prints the marker, proving the named direct answered.
			cfg.ToolArgv = []string{"sh", "-c", "nc -z -w 4 " + mappedHostLoopback + " " + proxyPort + " && echo " + directMarker + " || echo DIRECT-DOWN"}
			reached, err := verify.DirectReachableProbe(ctx, verify.DefaultJailRunner, cfg, directMarker)
			if err != nil {
				return verify.Assertion{Ok: false, Err: err}
			}
			return verify.Assertion{Ok: reached, Detail: "direct endpoint " + mappedHostLoopback + ":" + proxyPort + " reachable"}
		}},
	}

	checks := verify.SplitTunnelChecks(core, direct)
	if len(checks) != 4 {
		t.Fatalf("split-tunnel-active composition must be 3 core + 1 direct = 4 checks; got %d", len(checks))
	}

	rep := verify.Run(ctx, checks)
	t.Logf("split-tunnel verify report:\n%s", rep.String())
	if !rep.Ok() {
		t.Fatalf("split-tunnel report must be green (directs reachable AND leak-tight outside the allowlist):\n%s", rep.String())
	}
	if rep.ExitCode() != 0 {
		t.Fatalf("green split-tunnel report must exit 0; got %d", rep.ExitCode())
	}
}

// TestVerify_AllowDirectIsNotAClearDNSHole is the row-2 (Tails leak catalogue)
// live assertion, re-expressed for the EXACT-PORT exemption (ADR-0020: the
// all-ports form was dropped). With --allow ACTIVE for an EXACT non-53 port, a
// clear DNS query (tcp AND udp 53) aimed DIRECTLY at the allowed LAN resolver
// does NOT get a clear answer from the LAN (it is dropped: :53 is not the allowed
// port, so it falls to the link-local range DROP), while the jail's loopback
// DNS-over-SOCKS forwarder STILL resolves. This proves --allow cannot be used as
// a clear-DNS hole to a LAN resolver (which could reveal the local network's
// public IP). The exact-port shape makes clear DNS un-allowable by construction:
// only the one named port is ever accepted, and it is never 53 (an explicit :53
// is refused at the CLI).
//
// It is the black-hole/counter probe mandated by ADR-0003 and
// dns-through-socks-is-tcp-not-udp.md, NOT the naive "a direct dig must time
// out": the CONTROL leg proves the direct host/route is genuinely UP (a TCP
// connect to the ALLOWED exact port SUCCEEDS over the split-tunnel), so the
// SILENCE on port 53 is the firewall DROP, not an unreachable host. The stand-in
// allowed LAN host is the pasta-mapped host loopback (mappedHostLoopback), the
// one host-service address a jail netns reaches deterministically without a real
// LAN peer (the same stand-in the other split-tunnel verify cases use). The allow
// names the control service's EXACT port, so the run is split-tunnel active AND
// the exact-port shape is what is under test.
func TestVerify_AllowDirectIsNotAClearDNSHole(t *testing.T) {
	requirePodman(t)

	// A reachable non-53 TCP service at the allowed LAN host (the pasta map -> host
	// loopback): the CONTROL leg connects to it to prove the direct host is UP, so
	// silence on :53 is a DROP not an unreachable host. Its EXACT port is what the
	// allow names, so the control connect exercises the exact-port hole itself.
	controlPort, stopControl := startHTTPExitEcho(t)
	defer stopControl()

	// The fixture is the DNS-over-SOCKS upstream so the jail's loopback forwarder
	// resolves uniqueName proxy-side (the DNS-still-served leg).
	resolverPort := startDNSOverTCP(t)
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:         exitIP,
		AllowIPConnect: true,
		KnownHosts:     map[string]string{upstreamName: resolverIP},
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	// The allow names the control service's EXACT port on the pasta map, so the run
	// is split-tunnel active. :53 is NOT allowed (only this one port), so a direct
	// clear-DNS query has no accept and is dropped by the range DROP. This is the
	// exact-port replacement for the removed all-ports 53-exclusion.
	controlPortNum, _ := strconv.Atoi(controlPort)
	allowExactPort := []cli.DirectAllow{{
		Network: &net.IPNet{IP: net.ParseIP(mappedHostLoopback), Mask: net.CIDRMask(32, 32)},
		Port:    controlPortNum,
		Raw:     mappedHostLoopback + ":" + controlPort,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	const (
		controlMarker   = "CONTROL-UP"
		directDNSMarker = "DIRECT-DNS-ANSWERED"
	)

	check := verify.Check{Name: "allow-not-a-dns-hole", Run: func(ctx context.Context) verify.Assertion {
		// Three legs in one jailed probe:
		//   CONTROL: a non-53 TCP connect to the allowed host succeeds (host is UP).
		//   DIRECT-DNS: clear DNS (nslookup names the LAN resolver as the server) on
		//     tcp AND udp 53 to the allowed host -> must get NO answer (dropped). It
		//     prints directDNSMarker ONLY if a direct clear query answered (the leak).
		//   FORWARDER: the ordinary loopback resolver resolves uniqueName proxy-side.
		script := strings.Join([]string{
			"if nc -z -w 4 " + mappedHostLoopback + " " + controlPort + " 2>/dev/null; then echo " + controlMarker + "; fi",
			// TCP clear DNS straight at the LAN resolver on :53 (nslookup uses TCP for
			// -vc); if it answers, the hole is open.
			"if nslookup -vc -type=A -timeout=3 example.com " + mappedHostLoopback + " >/dev/null 2>&1; then echo " + directDNSMarker + "; fi",
			// UDP clear DNS straight at the LAN resolver on :53; if it answers, the hole is open.
			"if nslookup -type=A -timeout=3 example.com " + mappedHostLoopback + " >/dev/null 2>&1; then echo " + directDNSMarker + "; fi",
			// The forwarder leg: the jail's own resolv.conf resolver (loopback) resolves the unique name.
			"nslookup " + uniqueName + " 2>&1 || true",
		}, "; ")
		cfg := jail.Config{
			Ephemeral:           true, // internal one-shot: remove-both, no residue
			Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
			ProxyOnHostLoopback: true,
			Image:               "docker.io/library/alpine:latest",
			DNSUpstream:         upstreamName + ":" + resolverPort,
			AllowDirect:         allowExactPort,
			ToolArgv:            []string{"sh", "-c", script},
			RunID:               runID("vdnshole"),
		}
		res, err := verify.DefaultJailRunner(ctx, cfg)
		if err != nil {
			return verify.NoClearLANDNSAssertion(false, false, err)
		}
		out := res.ToolStdout
		// CONTROL must be up, else silence on :53 could be an unreachable host, not a
		// drop -> the probe has no verdict.
		if !strings.Contains(out, controlMarker) {
			return verify.NoClearLANDNSAssertion(false, false,
				fmt.Errorf("control leg failed: the allowed host %s was not reachable on the non-53 port, so a silent :53 is not provably a DROP; output:\n%s", mappedHostLoopback, out))
		}
		directAnswered := strings.Contains(out, directDNSMarker)
		forwarderResolved := strings.Contains(out, answerIP) && sawHost(fx.ResolvedHosts(), upstreamName)
		return verify.NoClearLANDNSAssertion(directAnswered, forwarderResolved, nil)
	}}

	rep := verify.Run(ctx, []verify.Check{check})
	t.Logf("no-clear-LAN-DNS report:\n%s", rep.String())
	if !rep.Ok() {
		t.Fatalf("--allow must NOT be a clear-DNS hole (row 2): direct clear DNS to the LAN resolver must be dropped while the forwarder still resolves:\n%s", rep.String())
	}
}

// exitIPAssertion runs the exit-IP probe against a dedicated redirect fixture.
func exitIPAssertion(ctx context.Context, t *testing.T, echoPort string) verify.Assertion {
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP: exitIP, AllowIPConnect: true, RedirectTarget: "127.0.0.1:" + echoPort,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())
	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 8 http://" + placeholder + ":" + echoPort + "/ 2>&1 || true"},
		RunID:               runID("vall-exit"),
	}
	observed, err := verify.ExitIPProbe(ctx, verify.DefaultJailRunner, cfg)
	if err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	return verify.Assertion{Ok: observed == exitIP, Detail: "observed exit IP " + observed}
}

// failClosedAssertion runs the proxy-killed probe against a marker echo.
func failClosedAssertion(ctx context.Context, t *testing.T) verify.Assertion {
	const marker = "LEAKED-TO-HOST"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Length: "+
					strconv.Itoa(len(marker))+"\r\nConnection: close\r\n\r\n"+marker)
			}(c)
		}
	}()
	_, markerPort, _ := net.SplitHostPort(ln.Addr().String())
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP: exitIP, AllowIPConnect: true, RedirectTarget: "127.0.0.1:" + markerPort,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())
	fx.Close() // kill the proxy BEFORE the probe
	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 6 http://" + placeholder + ":" + markerPort + "/ 2>&1 || true"},
		RunID:               runID("vall-closed"),
	}
	egressed, err := verify.FailClosedProbe(ctx, verify.DefaultJailRunner, cfg, marker)
	if err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	return verify.Assertion{Ok: !egressed, Detail: "no egress with proxy killed"}
}

// exitIPAssertionAllow is exitIPAssertion with a split-tunnel allowlist ACTIVE on
// the probe config: it proves the exit-IP assertion (exit IP is the proxy's for
// non-allowlisted traffic) STILL holds with the split-tunnel open. The probe
// target (placeholder, an in-TUN routable IP) is NOT on the allowlist, so it is
// still forced through the proxy; the allowlist entry (the pasta map) only opens
// the direct hole, it must not loosen this.
func exitIPAssertionAllow(ctx context.Context, t *testing.T, echoPort string, allow []cli.DirectAllow) verify.Assertion {
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP: exitIP, AllowIPConnect: true, RedirectTarget: "127.0.0.1:" + echoPort,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())
	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 8 http://" + placeholder + ":" + echoPort + "/ 2>&1 || true"},
		RunID:               runID("vst-exit"),
		AllowDirect:         allowlist169(proxyPort), // this fixture's own port, so the run is split-tunnel active
	}
	observed, err := verify.ExitIPProbe(ctx, verify.DefaultJailRunner, cfg)
	if err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	return verify.Assertion{Ok: observed == exitIP, Detail: "observed exit IP " + observed + " (split-tunnel active)"}
}

// failClosedAssertionAllow is failClosedAssertion with a split-tunnel allowlist
// ACTIVE: it proves fail-closed STILL holds with the proxy killed even when the
// split-tunnel is open. The probe target is NOT on the allowlist, so with the
// proxy down it must still fail closed (no fall-back to the host network); the
// allowlist hole must not become a fail-open path for non-allowlisted traffic.
func failClosedAssertionAllow(ctx context.Context, t *testing.T) verify.Assertion {
	const marker = "LEAKED-TO-HOST"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Length: "+
					strconv.Itoa(len(marker))+"\r\nConnection: close\r\n\r\n"+marker)
			}(c)
		}
	}()
	_, markerPort, _ := net.SplitHostPort(ln.Addr().String())
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP: exitIP, AllowIPConnect: true, RedirectTarget: "127.0.0.1:" + markerPort,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())
	fx.Close() // kill the proxy BEFORE the probe
	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "wget -qO- -T 6 http://" + placeholder + ":" + markerPort + "/ 2>&1 || true"},
		RunID:               runID("vst-closed"),
		AllowDirect:         allowlist169(proxyPort),
	}
	egressed, err := verify.FailClosedProbe(ctx, verify.DefaultJailRunner, cfg, marker)
	if err != nil {
		return verify.Assertion{Ok: false, Err: err}
	}
	return verify.Assertion{Ok: !egressed, Detail: "no egress with proxy killed (split-tunnel active)"}
}

// ---- helpers ----

func sawHost(hosts []string, name string) bool {
	for _, h := range hosts {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	return false
}

// hostResolverKnows reports whether the HOST resolver can resolve name. The test
// names use a fake TLD (.test) so this must be false; it guards the no-host-leak
// premise of assertion #2.
func hostResolverKnows(t *testing.T, name string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	return err == nil && len(addrs) > 0
}

func buildAResponse(query []byte, name string) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2], resp[3] = 0x81, 0x80
	if !strings.EqualFold(name, uniqueName) {
		resp[3] = 0x83
		return resp
	}
	resp[6], resp[7] = 0, 1
	ans := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	ans = append(ans, net.ParseIP(answerIP).To4()...)
	return append(resp, ans...)
}

func decodeName(b []byte) string {
	var parts []string
	for len(b) > 0 {
		n := int(b[0])
		if n == 0 || 1+n > len(b) {
			break
		}
		parts = append(parts, string(b[1:1+n]))
		b = b[1+n:]
	}
	return strings.Join(parts, ".")
}
