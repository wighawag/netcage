package jail_test

import (
	"context"
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
)

// TestMain builds the tooljail-dns helper once (the in-netns DNS forwarder the
// jail launches via nsenter) and points the jail at it via TOOLJAIL_DNS_BIN, so
// the integration tests have the helper without a separate install step.
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

// requirePodman skips the test unless a working rootless podman is present, so
// the plain `go test ./...` gate stays green on a host without podman. The jail
// is a system-mutating integration; it runs only where the runtime exists.
func requirePodman(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not found; skipping jail integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "podman", "info").Run(); err != nil {
		t.Skip("podman not usable; skipping jail integration test")
	}
}

// startExitEcho starts an HTTP server on host loopback that replies with the
// client's observed source IP in the response body, so a probe through the jail
// (a plain `wget`) can be checked to exit from the proxy's IP. It speaks HTTP/1.0
// (not a bare-IP write) so an ordinary HTTP tool can parse the response: the
// wrapped tool stays proxy-unaware and realistic. Returns its port.
func startExitEcho(t *testing.T) (port string, stop func()) {
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
				// Drain the request line/headers (best-effort) before replying.
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\nContent-Length: "+
					strconv.Itoa(len(host))+"\r\nConnection: close\r\n\r\n"+host)
			}(c)
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p, func() { ln.Close() }
}

// TestJail_ForcedEgress_ExitIPIsProxys is the highest-value assertion: a tool
// run THROUGH the jail against the controllable socks5h fixture exits from the
// FIXTURE's exit IP, not the host's. It is RED until forced egress is wired.
//
// It binds the fixture on host loopback (the host-loopback proxy case), runs the
// jail with a tiny wget tool that fetches the echo BY IP, and asserts the echoed
// source IP equals the fixture's exit IP. The DNS-through-proxy assertion is
// owned by verify-leak-test; this test proves forced TCP egress without
// entangling DNS resolution (it fetches by IP, the tun2socks-tunnelled-by-IP
// path, which the fixture allows via AllowIPConnect).
func TestJail_ForcedEgress_ExitIPIsProxys(t *testing.T) {
	requirePodman(t)
	// The end-to-end forced-egress path now works in the Option-A shared-netns +
	// pasta topology. The wall recorded in
	// work/notes/observations/jail-tun2socks-shared-netns-no-packets.md was NOT
	// "tun2socks gets no packets" (it does) but two sidecar-env issues, now wired
	// in SidecarRunArgs: CLONE_MAIN=0 (so the TUN table does not clone the
	// pasta-copied real-NIC routes and storm) and TUN_EXCLUDED_ROUTES=<proxy>/32
	// (so tun2socks's own dialer reaches the proxy over the real NIC instead of
	// looping back through the TUN, which pasta reset). See
	// work/notes/findings/spike-jail-forced-egress-clone-main-and-excluded-route.md.

	echoPort, stopEcho := startExitEcho(t)
	defer stopEcho()

	const exitIP = "127.0.0.2" // the fixture's known exit IP (loopback alias)
	// The tool targets a ROUTABLE placeholder IP (TEST-NET-2) so the jail's TUN
	// captures it (loopback 127.x would stay in the netns and never reach the
	// proxy). The fixture redirects every CONNECT to the real host echo, dialed
	// from ExitIP, so the echo observes the proxy's exit IP.
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

	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		// fetch the routable placeholder BY IP; tun2socks tunnels it to the proxy,
		// which redirects to the echo and dials from the exit IP. The echo replies
		// with the source IP it observed, which must be the fixture's exit IP.
		ToolArgv: []string{"sh", "-c", "wget -qO- -T 8 http://" + placeholderIP + ":" + echoPort + " 2>&1 || true"},
		RunID:    "itest" + strings.ReplaceAll(time.Now().Format("150405.000"), ".", ""),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err != nil {
		t.Fatalf("jail.Run: %v", err)
	}

	if !strings.Contains(res.ToolStdout, exitIP) {
		t.Fatalf("tool observed exit IP %q in output; want the fixture's exit IP %q\nfull output: %q",
			extractIP(res.ToolStdout), exitIP, res.ToolStdout)
	}
}

// TestJail_TeardownLeavesNoResidue asserts that after a run, no run-attributable
// containers remain (the teardown invariant's focused check here; the full
// invariant across error/SIGINT is the teardown-invariant task).
func TestJail_TeardownLeavesNoResidue(t *testing.T) {
	requirePodman(t)

	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	runID := "teardown" + strings.ReplaceAll(time.Now().Format("150405.000"), ".", "")
	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"true"},
		RunID:               runID,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, _ = jail.Run(ctx, jail.ExecRunner{}, cfg)

	// No container named for this run should remain.
	out, _ := exec.CommandContext(ctx, "podman", "ps", "-a", "--format", "{{.Names}}").CombinedOutput()
	if strings.Contains(string(out), "tooljail-run-"+runID) {
		t.Fatalf("run-attributable containers left after teardown:\n%s", out)
	}
}

func extractIP(s string) string {
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ' ' }) {
		if net.ParseIP(strings.TrimSpace(line)) != nil {
			return line
		}
	}
	return s
}
