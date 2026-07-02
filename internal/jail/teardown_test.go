//go:build integration
// +build integration

package jail_test

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/socks5hfixture"
)

// residueFor returns the run-attributable podman container names still present
// for runID (the enumeration the teardown invariant asserts is empty). The
// netns + nft ruleset are lifecycle-bound to the sidecar container, so once no
// netcage-run-<id>-* container remains, neither does any netns/nft for the run.
func residueFor(t *testing.T, runID string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "podman", "ps", "-a", "--format", "{{.Names}}").CombinedOutput()
	var left []string
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name != "" && strings.Contains(name, "netcage-run-"+runID) {
			left = append(left, name)
		}
	}
	return left
}

func newKilledFixtureCfg(t *testing.T, runID string, argv []string) jail.Config {
	t.Helper()
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	t.Cleanup(func() { fx.Close() })
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())
	return jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            argv,
		RunID:               runID,
	}
}

// TestTeardown_NormalExitLeavesNoResidue: a clean run leaves no run-attributable
// container (and thus no netns/nft) behind.
func TestTeardown_NormalExitLeavesNoResidue(t *testing.T) {
	requirePodman(t)
	runID := "tdnormal" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	cfg := newKilledFixtureCfg(t, runID, []string{"true"})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := jail.Run(ctx, jail.ExecRunner{}, cfg); err != nil {
		t.Fatalf("jail.Run (normal): %v", err)
	}
	if left := residueFor(t, runID); len(left) != 0 {
		t.Fatalf("residue after normal exit: %v", left)
	}
}

// TestTeardown_ErrorExitLeavesNoResidue: a run that errors mid-flight (here the
// reachback diagnostic fails because the host-loopback proxy is down, AFTER the
// sidecar/netns/nft are already up) still tears everything down and surfaces the
// error.
func TestTeardown_ErrorExitLeavesNoResidue(t *testing.T) {
	requirePodman(t)
	runID := "tderror" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	// Bind a fixture to claim a port, then CLOSE it so the port is dead: the
	// sidecar still starts (it does not connect at start), but the in-Run
	// reachback check (story 14) fails -> a real Run error on a path AFTER the
	// sidecar/netns/nft exist, exercising error-path teardown.
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())
	fx.Close() // kill the proxy: the reachback check will fail

	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"true"},
		RunID:               runID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err == nil {
		t.Fatal("expected an error from the dead-proxy reachback check; got nil")
	}
	if !errors.Is(err, jail.ErrReachback) {
		t.Logf("note: error was %v (not ErrReachback, but still an error path)", err)
	}
	if left := residueFor(t, runID); len(left) != 0 {
		t.Fatalf("residue after error exit: %v", left)
	}
}

// TestTeardown_ContextCancelLeavesNoResidue: cancelling the run context mid-flight
// (the mechanism a SIGINT handler uses via signal.NotifyContext) still tears
// everything down. This is the SIGINT path at the unit boundary: the CLI maps
// SIGINT -> context cancel, and Run must leave zero residue when its ctx is
// cancelled.
func TestTeardown_ContextCancelLeavesNoResidue(t *testing.T) {
	requirePodman(t)
	runID := "tdsigint" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	// A long-running tool so the cancel lands DURING the tool run.
	cfg := newKilledFixtureCfg(t, runID, []string{"sleep", "60"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(6 * time.Second) // after the sidecar/nft/tool are up
		cancel()
	}()
	_, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err == nil || !errors.Is(err, context.Canceled) {
		// The tool was killed by the cancel; Run may return a wrapped error. We
		// only require that it returned (did not hang) and tore down.
		t.Logf("jail.Run returned err=%v (cancel path)", err)
	}
	// Give teardown a moment to complete after the cancel.
	time.Sleep(1 * time.Second)
	if left := residueFor(t, runID); len(left) != 0 {
		t.Fatalf("residue after context cancel (SIGINT path): %v", left)
	}
}

// TestTeardown_Idempotent: calling Teardown twice is safe and the second call is
// a no-op (no error from removing already-gone resources).
func TestTeardown_Idempotent(t *testing.T) {
	requirePodman(t)
	runID := "tdidem" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	cfg := newKilledFixtureCfg(t, runID, []string{"true"})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, _ = jail.Run(ctx, jail.ExecRunner{}, cfg)

	// A second explicit teardown after the run already tore down must not error.
	if err := jail.Teardown(context.Background(), jail.ExecRunner{}, cfg); err != nil {
		t.Fatalf("second teardown must be idempotent (no error); got %v", err)
	}
	if left := residueFor(t, runID); len(left) != 0 {
		t.Fatalf("residue after idempotent teardown: %v", left)
	}
}
