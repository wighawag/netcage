//go:build integration
// +build integration

package manage_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/manage"
	"github.com/wighawag/netcage/internal/socks5hfixture"
)

// TestMain builds the netcage-dns helper (the in-jail DNS forwarder the sidecar
// execs, ADR-0006) as a STATIC binary and points the jail at it via
// NETCAGE_DNS_BIN, so this file can stand up a REAL kept pair to manage. Mirrors
// the jail integration test's TestMain.
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
	}
	os.Exit(m.Run())
}

// requirePodman skips unless a working rootless podman is present (the whole file
// is behind the `integration` build tag; run with `go test -tags integration`).
func requirePodman(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not found; skipping manage integration test")
	}
}

// forceRemovePair removes a kept tool+sidecar pair even on failure. `rm -f
// --depend` of the sidecar cascades to its `--network container:` dependent tool
// (the only way to drop the sidecar), so the test cleans up after ITSELF: the
// PRODUCT deliberately leaves the pair (that is the feature under test), the TEST
// must not orphan it or collide with a concurrent run (podman is host-global).
func forceRemovePair(runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "podman", "rm", "-f", "--depend", "netcage-run-"+runID+"-sidecar").Run()
	_ = exec.CommandContext(ctx, "podman", "rm", "-f", "-i", "netcage-run-"+runID+"-tool").Run()
	// Sweep the durable resolv.conf too, so a kept-pair test cleans fully after
	// itself and leaves no $TMPDIR orphan.
	jail.RemoveResolvConf(runID)
}

// residueFor returns the run-attributable podman container names still present
// for runID.
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

// keptPairCfg builds a KEPT-run jail.Config against an in-process socks5h
// fixture, so jail.Run leaves the stopped tool + sidecar behind for the manage
// verbs to act on.
func keptPairCfg(t *testing.T, runID string) jail.Config {
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
		ToolArgv:            []string{"true"},
		RunID:               runID,
		Ephemeral:           false, // KEPT: leave the pair behind for the verbs to manage
	}
}

// TestManageVerbs_PsShowsKeptPairAndRmRemovesIt is the podman-gated proof: a KEPT
// run leaves a labelled tool + sidecar; `netcage ps` lists the pair (label-scoped)
// and `netcage rm <tool>` removes BOTH (no orphaned sidecar).
//
// Shared-write isolation (podman is host-global state): the kept run DELIBERATELY
// leaves the pair, so a unique run-id names it AND t.Cleanup does `podman rm -f
// --depend` of the pair even on failure, so the test cannot orphan containers or
// collide with a concurrent run.
func TestManageVerbs_PsShowsKeptPairAndRmRemovesIt(t *testing.T) {
	requirePodman(t)

	runID := "mgmt" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	cfg := keptPairCfg(t, runID)
	// Register cleanup FIRST so any failure below still removes the leftover pair.
	t.Cleanup(func() { forceRemovePair(runID) })

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := jail.Run(ctx, jail.ExecRunner{}, cfg); err != nil {
		t.Fatalf("jail.Run (kept): %v", err)
	}
	if left := residueFor(t, runID); len(left) != 2 {
		t.Fatalf("kept run must leave the tool + sidecar; got %d: %v", len(left), left)
	}

	toolName := "netcage-run-" + runID + "-tool"
	sidecarName := "netcage-run-" + runID + "-sidecar"

	// `netcage ps` lists the pair, label-scoped. It shows netcage-managed
	// containers (both roles); assert at least the tool of THIS run appears.
	var psOut bytes.Buffer
	if err := manage.Run(ctx, jail.ExecRunner{}, "ps", nil, manage.IO{Stdout: &psOut, Stderr: &psOut}); err != nil {
		t.Fatalf("netcage ps: %v", err)
	}
	if !strings.Contains(psOut.String(), toolName) {
		t.Fatalf("netcage ps must list the kept netcage-managed tool %s; got:\n%s", toolName, psOut.String())
	}

	// The NAMED verbs (logs/inspect/stop) must actually WORK against podman, not
	// just build a plausible argv: podman only accepts `--filter` on `ps`, so a
	// named verb that carried a filter would fail live (`unknown flag: --filter` /
	// `--filter takes no arguments`). Exercise each one against the real kept
	// container so that regression cannot slip past the argv-only unit tests.
	for _, verb := range []string{"inspect", "logs", "stop"} {
		var vout bytes.Buffer
		if err := manage.Run(ctx, jail.ExecRunner{}, verb, []string{toolName}, manage.IO{Stdout: &vout, Stderr: &vout}); err != nil {
			t.Fatalf("netcage %s %s must succeed against the kept container (podman rejects --filter on this verb): %v\noutput:\n%s", verb, toolName, err, vout.String())
		}
	}
	// `netcage exec` argv must be ACCEPTED by podman (no --filter, which podman
	// rejects on exec). The kept tool ran `true` and is stopped, so exec fails with
	// podman's "container is not running" - that is fine; what must NOT appear is the
	// `--filter` rejection this fix removes. This pins that exec is a plain
	// pass-through into the existing container (never a fresh --network run).
	var execOut bytes.Buffer
	err := manage.Run(ctx, jail.ExecRunner{}, "exec", []string{toolName, "echo", "netcage-exec-ok"}, manage.IO{Stdout: &execOut, Stderr: &execOut})
	if err != nil && strings.Contains(strings.ToLower(err.Error()+execOut.String()), "unknown flag: --filter") {
		t.Fatalf("netcage exec must be a plain `podman exec` with NO --filter (podman rejects it); got: %v\noutput:\n%s", err, execOut.String())
	}
	if s := execOut.String(); strings.Contains(s, "--filter takes no arguments") {
		t.Fatalf("netcage exec must not carry --filter; got:\n%s", s)
	}

	// A non-netcage container must be REFUSED (guard by label): create a plain
	// alpine container carrying no netcage label and assert rm/logs refuse it.
	unmanaged := "netcage-mgmt-unmanaged-" + runID
	_ = exec.CommandContext(ctx, "podman", "create", "--name", unmanaged, "docker.io/library/alpine:latest", "true").Run()
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", "-i", unmanaged).Run() })
	if err := manage.Run(ctx, jail.ExecRunner{}, "rm", []string{unmanaged}, manage.IO{}); err == nil {
		t.Fatalf("netcage rm of a non-netcage container %s must be refused", unmanaged)
	}

	// `netcage rm <tool>` removes the WHOLE pair (rm -f --depend the sidecar
	// cascades to the tool): no orphaned sidecar.
	if err := manage.Run(ctx, jail.ExecRunner{}, "rm", []string{toolName}, manage.IO{Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		t.Fatalf("netcage rm %s: %v", toolName, err)
	}
	if left := residueFor(t, runID); len(left) != 0 {
		t.Fatalf("netcage rm must remove BOTH the tool and sidecar (no residue); left: %v", left)
	}
	_ = sidecarName
}
