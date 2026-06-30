package verify_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/tooljail/internal/cli"
	"github.com/wighawag/tooljail/internal/jail"
	"github.com/wighawag/tooljail/internal/socks5hfixture"
	"github.com/wighawag/tooljail/internal/verify"
)

// TestMain builds the tooljail-dns helper once (the jail launches it in-netns)
// and points the jail at it via TOOLJAIL_DNS_BIN, mirroring the jail package's
// own integration TestMain so verify's DNS assertion has the helper.
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("podman"); err == nil {
		dir, err := os.MkdirTemp("", "tooljail-dns-bin")
		if err == nil {
			defer os.RemoveAll(dir)
			bin := filepath.Join(dir, "tooljail-dns")
			build := exec.Command("go", "build", "-o", bin, "github.com/wighawag/tooljail/cmd/tooljail-dns")
			if out, berr := build.CombinedOutput(); berr == nil {
				os.Setenv("TOOLJAIL_DNS_BIN", bin)
			} else {
				os.Stderr.Write(out)
			}
		}
	}
	os.Exit(m.Run())
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
	exitIP       = "127.0.0.2"            // the fixture's known exit IP (loopback alias)
	uniqueName   = "unique.tooljail.test" // a name only the proxy-side resolver knows
	answerIP     = "203.0.113.55"         // the proxy-side answer for uniqueName
	upstreamName = "dns.tooljail.test"    // the DNS resolver name, resolved proxy-side
	resolverIP   = "127.0.0.3"            // where the test DNS-over-TCP resolver binds
	placeholder  = "198.18.5.5"           // in-TUN-subnet target so the jail's TUN captures it
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
// the verify orchestrator (the shape `tooljail verify` uses) and asserts the
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
