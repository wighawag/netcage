package jail_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wighawag/tooljail/internal/cli"
	"github.com/wighawag/tooljail/internal/devimage"
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

// TestJail_DefaultDevImage_ForcedEgressAndNoResidue is the podman-gated proof for
// the default-dev-image ergonomic: the PINNED default dev image (the one
// `tooljail run` injects when no positional image is given) runs THROUGH the jail
// with its egress FORCED through the proxy (the observed exit IP is the fixture's,
// not the host's), and the run leaves NO run-attributable residue. It mirrors
// TestJail_ForcedEgress_ExitIPIsProxys but pins Config.Image to
// devimage.ImageReference() so the leak guarantee is proven for the image an
// out-of-the-box `tooljail run -it -v <repo>:/work bash` actually uses.
//
// The default dev image (buildpack-deps) is large; the pull can be slow on a cold
// cache, so the test budget is generous. It is podman-gated (t.Skip without
// podman) and isolates to throwaway, run-attributable resources.
func TestJail_DefaultDevImage_ForcedEgressAndNoResidue(t *testing.T) {
	requirePodman(t)

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

	runID := "defimg" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		// The default dev image the CLI injects when no positional image is passed.
		Image: devimage.ImageReference(),
		// buildpack-deps carries curl; fetch the routable placeholder BY IP so
		// tun2socks tunnels it to the proxy, which redirects to the echo and dials
		// from the exit IP. The echo replies with the source IP it observed.
		ToolArgv: []string{"sh", "-c", "curl -s -m 8 http://" + placeholderIP + ":" + echoPort + " || true"},
		RunID:    runID,
	}

	// Generous budget: the default dev image is large and may pull on a cold cache.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err != nil {
		t.Fatalf("jail.Run with the default dev image: %v", err)
	}
	if !strings.Contains(res.ToolStdout, exitIP) {
		t.Fatalf("tool observed exit IP %q; want the fixture's exit IP %q (default image egress not forced through the proxy)\nfull output: %q",
			extractIP(res.ToolStdout), exitIP, res.ToolStdout)
	}

	// No run-attributable container for this run should remain (no residue).
	out, _ := exec.CommandContext(ctx, "podman", "ps", "-a", "--format", "{{.Names}}").CombinedOutput()
	if strings.Contains(string(out), "tooljail-run-"+runID) {
		t.Fatalf("run-attributable containers left after the default-dev-image run:\n%s", out)
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

// TestJail_PropagatesToolExitCode backs the `tooljail run` exit-code contract:
// a wrapped tool that exits non-zero has that exit code surfaced in
// Result.ToolExit (not swallowed, not reported as a jail error), so the CLI can
// propagate it as tooljail's own exit code.
func TestJail_PropagatesToolExitCode(t *testing.T) {
	requirePodman(t)

	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", "exit 42"},
		RunID:               "exitcode" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", ""),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err != nil {
		t.Fatalf("jail.Run returned a jail error for a tool that merely exited non-zero: %v", err)
	}
	if res.ToolExit != 42 {
		t.Fatalf("ToolExit = %d, want 42 (the wrapped tool's exit code must propagate)", res.ToolExit)
	}
}

// TestJail_StreamsToolOutputLiveThroughRun: end-to-end proof (podman-gated) that
// the wrapped tool's stdout is streamed to Config.ToolStdout AS IT ARRIVES, not
// buffered until exit, while Result.ToolStdout still captures it for the probes.
// The tool prints a marker then sleeps; the marker must appear on the live sink
// while the tool is still running (before jail.Run returns).
func TestJail_StreamsToolOutputLiveThroughRun(t *testing.T) {
	requirePodman(t)

	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	var live safeBuf
	const marker = "TOOLJAIL-LIVE-MARKER"
	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		// Print the marker immediately, then keep running so we can observe the
		// marker BEFORE the tool exits.
		ToolArgv:   []string{"sh", "-c", "echo " + marker + "; sleep 6"},
		ToolStdout: &live,
		RunID:      "stream" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", ""),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	type outcome struct {
		res jail.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
		done <- outcome{res, err}
	}()

	// The marker must appear on the live sink while the tool's 6s sleep is still
	// running (i.e. before Run returns). Poll up to ~4s.
	deadline := time.Now().Add(4 * time.Second)
	seen := false
	for time.Now().Before(deadline) {
		if strings.Contains(live.String(), marker) {
			seen = true
			break
		}
		select {
		case o := <-done:
			t.Fatalf("jail.Run returned before the marker was observed live (buffered, not streamed): res=%q err=%v", o.res.ToolStdout, o.err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !seen {
		t.Fatalf("marker %q not observed on the live sink while the tool was still running; output is buffered, not streamed.\nlive so far: %q", marker, live.String())
	}

	o := <-done
	if o.err != nil {
		t.Fatalf("jail.Run: %v", o.err)
	}
	// The capture path the probes rely on must still yield the tool's output.
	if !strings.Contains(o.res.ToolStdout, marker) {
		t.Fatalf("Result.ToolStdout lost the tool output (capture-for-assertions broken); got %q", o.res.ToolStdout)
	}
}

// TestJail_UnpullableImageIsSetupError_NotToolExit: a run whose image cannot be
// pulled must return a jail SETUP error (wrapping jail.ErrJailSetup), NOT a
// Result.ToolExit of 125. This is the core of
// distinguish-podman-failure-from-tool-exit: a broken image must not be hidden
// behind a plausible-looking "the tool exited 125".
//
// It needs no live proxy: the sidecar starts, but the TOOL container fails to
// pull, which is the podman-125 path. (The sidecar image is the pinned digest,
// already present; only the tool image is unpullable.)
func TestJail_UnpullableImageIsSetupError_NotToolExit(t *testing.T) {
	requirePodman(t)

	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/tooljail-nonexistent-image-xyz:doesnotexist",
		ToolArgv:            []string{"true"},
		RunID:               "badimg" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", ""),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err == nil {
		t.Fatalf("an unpullable image must be a jail setup ERROR; got nil err, ToolExit=%d", res.ToolExit)
	}
	if !errors.Is(err, jail.ErrJailSetup) {
		t.Fatalf("unpullable image must wrap jail.ErrJailSetup; got %v", err)
	}
	if res.ToolExit == 125 {
		t.Fatalf("unpullable image must NOT be reported as the tool exiting 125; got ToolExit=125")
	}
}

// TestJail_CommandNotFoundIsSetupError_NotToolExit: a run whose tool COMMAND is
// not found in the image (podman/crun 127) must be a setup/exec failure, not
// silently "tool exited 127".
func TestJail_CommandNotFoundIsSetupError_NotToolExit(t *testing.T) {
	requirePodman(t)

	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"tooljail-no-such-command-xyz"},
		RunID:               "badcmd" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", ""),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err == nil {
		t.Fatalf("a command-not-found must be a jail setup/exec ERROR; got nil err, ToolExit=%d", res.ToolExit)
	}
	if !errors.Is(err, jail.ErrJailSetup) {
		t.Fatalf("command-not-found must wrap jail.ErrJailSetup; got %v", err)
	}
	if res.ToolExit == 127 {
		t.Fatalf("command-not-found must NOT be reported as the tool exiting 127; got ToolExit=127")
	}
}

// safeBuf is a concurrency-safe buffer so the live-streaming test can read the
// sink from the test goroutine while jail.Run writes it from another.
type safeBuf struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func extractIP(s string) string {
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ' ' }) {
		if net.ParseIP(strings.TrimSpace(line)) != nil {
			return line
		}
	}
	return s
}
