package jail

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// recordRunner records every podman invocation Teardown makes, so the
// remove-both-vs-leave-both split is unit-testable at the Runner seam WITHOUT a
// real podman (mirrors how the jail wiring is tested podman-free elsewhere).
type recordRunner struct{ calls [][]string }

func (r *recordRunner) Run(_ context.Context, spec RunSpec) (string, string, error) {
	r.calls = append(r.calls, spec.Args)
	return "", "", nil
}

func teardownCfg(ephemeral bool) Config {
	return Config{
		Proxy:     cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
		Image:     "docker.io/library/alpine:latest",
		ToolArgv:  []string{"true"},
		RunID:     "td01",
		Ephemeral: ephemeral,
	}
}

// TestTeardown_RemovesBothOnEphemeralLeavesBothOnKept pins the jail-lifecycle
// split at the Runner seam: an EPHEMERAL run (Ephemeral=true: the netcage `--rm`
// flag and every internal one-shot) removes BOTH the tool and the sidecar (no
// residue, as today). A KEPT run (Ephemeral=false: a plain `netcage run`) removes
// NEITHER, leaving the stopped tool + sidecar behind (the podman-fidelity
// feature; the pair is fail-closed via the baked EXTRA_COMMANDS firewall).
//
// "Remove the sidecar but keep the tool" is NOT reachable (the `--network
// container:` edge blocks removing the sidecar while the tool exists, and
// `--depend` cascades to the tool - see the finding), so the only two coherent
// end-states are both-gone (ephemeral) and both-kept (kept).
func TestTeardown_RemovesBothOnEphemeralLeavesBothOnKept(t *testing.T) {
	t.Run("ephemeral removes both tool and sidecar", func(t *testing.T) {
		c := teardownCfg(true)
		r := &recordRunner{}
		if err := Teardown(context.Background(), r, c); err != nil {
			t.Fatalf("Teardown (ephemeral): %v", err)
		}
		joined := joinAll(r.calls)
		for _, want := range []string{c.toolName(), c.sidecarName()} {
			if !strings.Contains(joined, "rm -f -i "+want) {
				t.Fatalf("ephemeral teardown must rm -f both containers; missing %q\ncalls: %s", want, joined)
			}
		}
	})

	t.Run("kept removes neither (leaves both behind)", func(t *testing.T) {
		c := teardownCfg(false)
		r := &recordRunner{}
		if err := Teardown(context.Background(), r, c); err != nil {
			t.Fatalf("Teardown (kept): %v", err)
		}
		if len(r.calls) != 0 {
			t.Fatalf("kept teardown must NOT remove the tool or sidecar (leave both behind); got podman calls: %s", joinAll(r.calls))
		}
	})
}

// TestTeardown_SweepsResolvConfOnEphemeralKeepsItOnKept pins that the
// run-attributable resolv.conf file (the tool's durable bind-mount source) is
// swept on the EPHEMERAL path (whatever removes the pair also removes the file,
// so it does not orphan under $TMPDIR) but LEFT durable on the KEPT path (so a
// later `netcage start` can re-mount it). `netcage rm` performs the same sweep
// via jail.RemoveResolvConf; this covers the Teardown half.
func TestTeardown_SweepsResolvConfOnEphemeralKeepsItOnKept(t *testing.T) {
	t.Run("ephemeral sweeps the resolv.conf", func(t *testing.T) {
		c := teardownCfg(true)
		path := resolvConfPathFor(c.RunID)
		if err := writeResolvConfAt(path); err != nil {
			t.Fatalf("seed resolv.conf: %v", err)
		}
		t.Cleanup(func() { os.Remove(path) })
		if err := Teardown(context.Background(), &recordRunner{}, c); err != nil {
			t.Fatalf("Teardown (ephemeral): %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("ephemeral teardown must remove the resolv.conf %s (got stat err %v); it would otherwise orphan", path, err)
		}
	})

	t.Run("kept leaves the resolv.conf durable", func(t *testing.T) {
		c := teardownCfg(false)
		path := resolvConfPathFor(c.RunID)
		if err := writeResolvConfAt(path); err != nil {
			t.Fatalf("seed resolv.conf: %v", err)
		}
		t.Cleanup(func() { os.Remove(path) })
		if err := Teardown(context.Background(), &recordRunner{}, c); err != nil {
			t.Fatalf("Teardown (kept): %v", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("kept teardown must LEAVE the resolv.conf %s durable (so netcage start can re-mount it); got stat err %v", path, err)
		}
	})
}

// TestRemoveResolvConf_IsIdempotent pins that RemoveResolvConf is a safe no-op on
// a missing file and an empty run id, so it can be called on every exit path and
// by `netcage rm` without guarding.
func TestRemoveResolvConf_IsIdempotent(t *testing.T) {
	RemoveResolvConf("")                   // empty run id: no-op, must not panic
	RemoveResolvConf("no-such-run-id-xyz") // missing file: no-op
}

// TestTeardown_SweepsHostsOnEphemeralKeepsItOnKept mirrors the resolv.conf sweep
// test for the sanitized /etc/hosts bind-mount source (Leak 1, ADR-0013): swept
// on the EPHEMERAL path so it does not orphan under $TMPDIR, LEFT durable on the
// KEPT path so a later `netcage start` can re-mount it. `netcage rm` performs the
// same sweep via jail.RemoveHosts.
func TestTeardown_SweepsHostsOnEphemeralKeepsItOnKept(t *testing.T) {
	t.Run("ephemeral sweeps the hosts file", func(t *testing.T) {
		c := teardownCfg(true)
		path := hostsPathFor(c.RunID)
		if err := writeHostsAt(path); err != nil {
			t.Fatalf("seed hosts: %v", err)
		}
		t.Cleanup(func() { os.Remove(path) })
		if err := Teardown(context.Background(), &recordRunner{}, c); err != nil {
			t.Fatalf("Teardown (ephemeral): %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("ephemeral teardown must remove the hosts file %s (got stat err %v); it would otherwise orphan", path, err)
		}
	})

	t.Run("kept leaves the hosts file durable", func(t *testing.T) {
		c := teardownCfg(false)
		path := hostsPathFor(c.RunID)
		if err := writeHostsAt(path); err != nil {
			t.Fatalf("seed hosts: %v", err)
		}
		t.Cleanup(func() { os.Remove(path) })
		if err := Teardown(context.Background(), &recordRunner{}, c); err != nil {
			t.Fatalf("Teardown (kept): %v", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("kept teardown must LEAVE the hosts file %s durable (so netcage start can re-mount it); got stat err %v", path, err)
		}
	})
}

// TestRemoveHosts_IsIdempotent pins that RemoveHosts is a safe no-op on a missing
// file and an empty run id (like RemoveResolvConf), so it can be called on every
// exit path and by `netcage rm` without guarding.
func TestRemoveHosts_IsIdempotent(t *testing.T) {
	RemoveHosts("")                   // empty run id: no-op, must not panic
	RemoveHosts("no-such-run-id-xyz") // missing file: no-op
}

// TestWriteHostsAt_IsLocalhostOnly pins the synthesized /etc/hosts contains ONLY
// localhost entries and NO host machine name / `127.0.1.1 <host>` line (the leak
// this fix closes). It is the per-run temp fixture the tool bind-mounts.
func TestWriteHostsAt_IsLocalhostOnly(t *testing.T) {
	path := hostsPathFor("hoststest")
	t.Cleanup(func() { os.Remove(path) })
	if err := writeHostsAt(path); err != nil {
		t.Fatalf("writeHostsAt: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "localhost") {
		t.Fatalf("synthesized hosts must contain the localhost entry; got:\n%s", got)
	}
	if strings.Contains(got, "127.0.1.1") {
		t.Fatalf("synthesized hosts must NOT carry a `127.0.1.1 <host>` line (the leak); got:\n%s", got)
	}
}

func joinAll(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}
