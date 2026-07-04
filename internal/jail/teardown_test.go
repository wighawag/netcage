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
// netns + firewall + in-sidecar DNS forwarder are lifecycle-bound to the sidecar
// container, so once no netcage-run-<id>-* container remains, nothing of the run
// remains.
func residueFor(t *testing.T, runID string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "podman", podmanTestArgs("ps", "-a", "--format", "{{.Names}}")...).CombinedOutput()
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
		// The teardown-invariant tests assert the EPHEMERAL (remove-both) path leaves
		// no residue on every exit path. A KEPT run deliberately leaves the pair
		// behind (proven separately by TestLifecycle_KeptRunLeavesBoth...).
		Ephemeral: true,
	}
}

// TestTeardown_NormalExitLeavesNoResidue: a clean run leaves no run-attributable
// container (and thus no netns/firewall) behind.
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
// sidecar/netns/firewall are already up) still tears everything down and surfaces the
// error.
func TestTeardown_ErrorExitLeavesNoResidue(t *testing.T) {
	requirePodman(t)
	runID := "tderror" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	// Bind a fixture to claim a port, then CLOSE it so the port is dead: the
	// sidecar still starts (it does not connect at start), but the in-Run
	// reachback check (story 14) fails -> a real Run error on a path AFTER the
	// sidecar/netns/firewall exist, exercising error-path teardown.
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
		Ephemeral:           true, // ephemeral path: error-exit must still leave no residue
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
		time.Sleep(6 * time.Second) // after the sidecar/firewall/tool are up
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

// containerLabel returns the value of a podman container LABEL, or "" if the
// container or label is absent. Used to assert a kept pair carries the
// netcage.managed (+ role + run id) labels introduced by this task.
func containerLabel(t *testing.T, name, key string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "podman", podmanTestArgs("inspect",
		"--format", "{{ index .Config.Labels \""+key+"\" }}", name)...).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// forceRemovePair removes a kept tool+sidecar pair even on failure. `rm -f
// --depend` of the sidecar cascades to its `--network container:` dependent tool
// (the only way to drop the sidecar), so the test cleans up after ITSELF: the
// PRODUCT deliberately leaves the pair (that is the feature under test), the TEST
// must not orphan it or collide with a concurrent run (podman is host-global).
func forceRemovePair(runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "podman", podmanTestArgs("rm", "-f", "--depend", "netcage-run-"+runID+"-sidecar")...).Run()
	_ = exec.CommandContext(ctx, "podman", podmanTestArgs("rm", "-f", "-i", "netcage-run-"+runID+"-tool")...).Run()
	// Sweep the durable resolv.conf too, so a kept-pair test cleans fully after
	// itself and leaves no $TMPDIR orphan.
	jail.RemoveResolvConf(runID)
}

// TestLifecycle_KeptRunLeavesBothEphemeralLeavesNone is the podman-gated proof of
// the podman-fidelity split (ADR-0009): a KEPT run (Ephemeral=false, a plain
// `netcage run`) leaves the STOPPED tool container AND its stopped sidecar
// behind, both carrying the netcage.managed (+ role + run id) label; an EPHEMERAL
// run (Ephemeral=true, the netcage `--rm` flag / every internal one-shot) leaves
// NONE.
//
// Shared-write isolation (podman is host-global state): the kept run DELIBERATELY
// leaves the pair (the feature), so a unique run-id names it AND t.Cleanup does
// `podman rm -f --depend` of the pair even on failure, so the test cleans up
// after itself and cannot orphan containers or collide with a concurrent run.
func TestLifecycle_KeptRunLeavesBothEphemeralLeavesNone(t *testing.T) {
	requirePodman(t)

	t.Run("kept run (no --rm) leaves the stopped tool + sidecar, labelled", func(t *testing.T) {
		runID := "keptrun" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
		cfg := newKilledFixtureCfg(t, runID, []string{"true"})
		cfg.Ephemeral = false // KEPT: leave both behind
		// Register removal FIRST so a failure anywhere below still cleans up the pair
		// the product deliberately leaves behind.
		t.Cleanup(func() { forceRemovePair(runID) })

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := jail.Run(ctx, jail.ExecRunner{}, cfg); err != nil {
			t.Fatalf("jail.Run (kept): %v", err)
		}

		// Both containers must remain (podman-run fidelity: a stopped, inspectable
		// tool + its stopped sidecar).
		left := residueFor(t, runID)
		if len(left) != 2 {
			t.Fatalf("kept run must LEAVE both the tool and the sidecar behind; got %d container(s): %v", len(left), left)
		}

		// Both must carry the netcage.managed (+ role + run id) label introduced here.
		toolName := "netcage-run-" + runID + "-tool"
		sidecarName := "netcage-run-" + runID + "-sidecar"
		if got := containerLabel(t, toolName, "netcage.managed"); got != "true" {
			t.Fatalf("kept tool %s missing netcage.managed=true label; got %q", toolName, got)
		}
		if got := containerLabel(t, toolName, "netcage.role"); got != "tool" {
			t.Fatalf("kept tool %s must carry netcage.role=tool; got %q", toolName, got)
		}
		if got := containerLabel(t, toolName, "netcage.run-id"); got != runID {
			t.Fatalf("kept tool %s must carry netcage.run-id=%s; got %q", toolName, runID, got)
		}
		if got := containerLabel(t, sidecarName, "netcage.managed"); got != "true" {
			t.Fatalf("kept sidecar %s missing netcage.managed=true label; got %q", sidecarName, got)
		}
		if got := containerLabel(t, sidecarName, "netcage.role"); got != "sidecar" {
			t.Fatalf("kept sidecar %s must carry netcage.role=sidecar; got %q", sidecarName, got)
		}
	})

	t.Run("ephemeral run (--rm) leaves no residue", func(t *testing.T) {
		runID := "ephrun" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
		cfg := newKilledFixtureCfg(t, runID, []string{"true"}) // newKilledFixtureCfg sets Ephemeral:true
		// Belt-and-braces cleanup in case the assertion fails BEFORE proving no residue.
		t.Cleanup(func() { forceRemovePair(runID) })

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := jail.Run(ctx, jail.ExecRunner{}, cfg); err != nil {
			t.Fatalf("jail.Run (ephemeral): %v", err)
		}
		if left := residueFor(t, runID); len(left) != 0 {
			t.Fatalf("ephemeral run must leave NO residue; got: %v", left)
		}
	})
}
