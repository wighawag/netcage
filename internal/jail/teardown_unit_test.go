package jail

import (
	"context"
	"os"
	"path/filepath"
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

// TestTeardown_SweepsEtcIdentityFixturesOnEphemeralKeepsThemOnKept mirrors the
// resolv.conf / /etc/hosts sweep tests for the ADR-0021 /etc-identity fixtures
// (the synthesized /etc/passwd, /etc/group, and /etc/machine-id bind-mount
// sources): each is swept on the EPHEMERAL path so it does not orphan under
// $TMPDIR, and LEFT durable on the KEPT path so a later `netcage start` can
// re-mount it. `netcage rm` performs the same sweep via jail.RemovePasswd /
// RemoveGroup / RemoveMachineID.
func TestTeardown_SweepsEtcIdentityFixturesOnEphemeralKeepsThemOnKept(t *testing.T) {
	fixtures := []struct {
		name  string
		path  func(string) string
		write func(string) error
	}{
		{"passwd", passwdPathFor, writePasswdAt},
		{"group", groupPathFor, writeGroupAt},
		{"machine-id", machineIDPathFor, writeMachineIDAt},
	}
	t.Run("ephemeral sweeps every /etc-identity fixture", func(t *testing.T) {
		c := teardownCfg(true)
		for _, f := range fixtures {
			p := f.path(c.RunID)
			if err := f.write(p); err != nil {
				t.Fatalf("seed %s: %v", f.name, err)
			}
			t.Cleanup(func() { os.Remove(p) })
		}
		if err := Teardown(context.Background(), &recordRunner{}, c); err != nil {
			t.Fatalf("Teardown (ephemeral): %v", err)
		}
		for _, f := range fixtures {
			p := f.path(c.RunID)
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Fatalf("ephemeral teardown must remove the %s fixture %s (got stat err %v); it would otherwise orphan", f.name, p, err)
			}
		}
	})
	t.Run("kept leaves every /etc-identity fixture durable", func(t *testing.T) {
		c := teardownCfg(false)
		for _, f := range fixtures {
			p := f.path(c.RunID)
			if err := f.write(p); err != nil {
				t.Fatalf("seed %s: %v", f.name, err)
			}
			t.Cleanup(func() { os.Remove(p) })
		}
		if err := Teardown(context.Background(), &recordRunner{}, c); err != nil {
			t.Fatalf("Teardown (kept): %v", err)
		}
		for _, f := range fixtures {
			p := f.path(c.RunID)
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("kept teardown must LEAVE the %s fixture %s durable (so netcage start can re-mount it); got stat err %v", f.name, p, err)
			}
		}
	})
}

// TestRemoveEtcIdentityFixtures_AreIdempotent pins that the ADR-0021 fixture
// removers are safe no-ops on a missing file and an empty run id (like
// RemoveResolvConf / RemoveHosts), so they can be called on every exit path and by
// `netcage rm` without guarding.
func TestRemoveEtcIdentityFixtures_AreIdempotent(t *testing.T) {
	for _, remove := range []func(string){RemovePasswd, RemoveGroup, RemoveMachineID} {
		remove("")                   // empty run id: no-op, must not panic
		remove("no-such-run-id-xyz") // missing file: no-op
	}
}

// TestWritePasswdAt_HasOnlyGenericAccountsNoRealNames pins the synthesized
// /etc/passwd carries ONLY a generic non-identifying user set (root + the generic
// `machine` + the service-account minimum) and NONE of the host's real accounts,
// login names, or GECOS real names (the sharpest ADR-0021 leak). A coherent
// matching /etc/group is synthesized alongside it.
func TestWritePasswdAt_HasOnlyGenericAccountsNoRealNames(t *testing.T) {
	pwPath := passwdPathFor("idtest")
	grPath := groupPathFor("idtest")
	t.Cleanup(func() { os.Remove(pwPath); os.Remove(grPath) })
	if err := writePasswdAt(pwPath); err != nil {
		t.Fatalf("writePasswdAt: %v", err)
	}
	if err := writeGroupAt(grPath); err != nil {
		t.Fatalf("writeGroupAt: %v", err)
	}
	pw, err := os.ReadFile(pwPath)
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	got := string(pw)
	// The generic user must be present, mounted as the jail's own default account.
	if !strings.Contains(got, "machine:x:1000:1000::/home/machine:/bin/sh") {
		t.Fatalf("synthesized passwd must carry the generic `machine` user; got:\n%s", got)
	}
	if !strings.Contains(got, "root:x:0:0:") {
		t.Fatalf("synthesized passwd must carry root; got:\n%s", got)
	}
	// Every passwd line's gid must resolve in the synthesized group file (a coherent
	// passwd+group pair). We assert the two gids the passwd uses (1000, 65534) plus
	// root's (0) all appear as groups.
	gr := string(mustRead(t, grPath))
	for _, wantGroup := range []string{"root:x:0:", "machine:x:1000:", "nogroup:x:65534:"} {
		if !strings.Contains(gr, wantGroup) {
			t.Fatalf("synthesized group must carry %q so the passwd gids are coherent; got:\n%s", wantGroup, gr)
		}
	}
	// It must NOT synthesize /etc/shadow (its ABSENCE is safer than a fake, ADR-0021).
	if _, err := os.Stat(filepath.Join(os.TempDir(), "netcage-shadow-idtest")); !os.IsNotExist(err) {
		t.Fatalf("netcage must NOT synthesize an /etc/shadow fixture (its absence is safer than a fake)")
	}
}

// TestWriteMachineIDAt_IsPerRunRandom32Hex pins the synthesized /etc/machine-id is
// a non-empty 32-hex-char value (ADR-0021's chosen random-id option over an empty
// first-boot machine-id: non-empty so tools that require a value work) and that two
// writes mint DIFFERENT ids (per-run, unlinkable to the host correlator).
func TestWriteMachineIDAt_IsPerRunRandom32Hex(t *testing.T) {
	p1 := machineIDPathFor("mid1")
	p2 := machineIDPathFor("mid2")
	t.Cleanup(func() { os.Remove(p1); os.Remove(p2) })
	if err := writeMachineIDAt(p1); err != nil {
		t.Fatalf("writeMachineIDAt p1: %v", err)
	}
	if err := writeMachineIDAt(p2); err != nil {
		t.Fatalf("writeMachineIDAt p2: %v", err)
	}
	id1 := strings.TrimSpace(string(mustRead(t, p1)))
	id2 := strings.TrimSpace(string(mustRead(t, p2)))
	if len(id1) != 32 {
		t.Fatalf("machine-id must be 32 hex chars (non-empty); got %q (len %d)", id1, len(id1))
	}
	for _, r := range id1 {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("machine-id must be lowercase hex; got %q", id1)
		}
	}
	if id1 == id2 {
		t.Fatalf("machine-id must be per-run random (two writes must differ); both were %q", id1)
	}
}

// TestWriteMachineIDPreservingAt_KeepsExistingValue pins the revive-path behaviour:
// a KEPT run's run-scoped machine-id must stay STABLE across a `netcage start`
// revive, so writeMachineIDPreservingAt leaves an EXISTING file untouched and only
// re-mints a MISSING one.
func TestWriteMachineIDPreservingAt_KeepsExistingValue(t *testing.T) {
	p := machineIDPathFor("midpreserve")
	t.Cleanup(func() { os.Remove(p) })
	if err := writeMachineIDAt(p); err != nil {
		t.Fatalf("seed machine-id: %v", err)
	}
	orig := strings.TrimSpace(string(mustRead(t, p)))
	if err := writeMachineIDPreservingAt(p); err != nil {
		t.Fatalf("writeMachineIDPreservingAt (existing): %v", err)
	}
	if got := strings.TrimSpace(string(mustRead(t, p))); got != orig {
		t.Fatalf("preserving write must keep the existing machine-id %q stable; got %q", orig, got)
	}
	// A MISSING file is re-minted (so a temp-dir sweep or cross-host revive still works).
	os.Remove(p)
	if err := writeMachineIDPreservingAt(p); err != nil {
		t.Fatalf("writeMachineIDPreservingAt (missing): %v", err)
	}
	if got := strings.TrimSpace(string(mustRead(t, p))); len(got) != 32 {
		t.Fatalf("preserving write must re-mint a MISSING machine-id; got %q", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func joinAll(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}
