package jail

import (
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// bakedFor builds the bakedSidecarConfig a sidecar CREATED with cfg c would
// carry: the three create-time env values (PROXY / TUN_EXCLUDED_ROUTES /
// EXTRA_COMMANDS) that fully encode the jail's --proxy + --allow-direct config.
// Used by the reconcile tests to synthesise "what the container was created
// with" without running podman.
func bakedFor(c Config) bakedSidecarConfig {
	return bakedSidecarConfig{
		Proxy:          c.sidecarProxyURL(),
		ExcludedRoutes: c.excludedRoutes(),
		ExtraCommands:  c.firewallScript(c.Proxy.Port),
	}
}

// TestReconcileJailConfig_SameConfigRevives is the steady-state resume: when the
// REQUESTED jail config equals the one the container was created with, reconcile
// decides REVIVE (nil error), so `netcage start` brings the existing sidecar back
// up rather than rebuilding it (proven sufficient; see the finding).
func TestReconcileJailConfig_SameConfigRevives(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	c.AllowDirect = []cli.DirectAllow{allow(t, "192.168.1.150", 8080)}

	// The container was created with the SAME config: baked == requested.
	if err := reconcileJailConfig(c, bakedFor(c)); err != nil {
		t.Fatalf("same jail config must REVIVE (nil err); got refuse: %v", err)
	}
}

// TestReconcileJailConfig_DifferentProxyRefuses: a start invoked with a DIFFERENT
// --proxy than the container was created with is REFUSED (never silently revives
// a stale jail), with a clear message pointing at the mismatch.
func TestReconcileJailConfig_DifferentProxyRefuses(t *testing.T) {
	created := cfg()
	created.ProxyOnHostLoopback = true

	requested := created
	requested.Proxy = cli.ProxyConfig{Host: "127.0.0.1", Port: "1080"} // different proxy port

	err := reconcileJailConfig(requested, bakedFor(created))
	if err == nil {
		t.Fatalf("a DIFFERENT --proxy must be REFUSED, never silently revived")
	}
	if !isJailConfigChanged(err) {
		t.Fatalf("a changed proxy must be an ErrJailConfigChanged refusal; got %v", err)
	}
}

// TestReconcileJailConfig_DifferentAllowlistRefuses: a start invoked with a
// DIFFERENT --allow-direct than the container was created with is REFUSED (the
// firewall/excluded-routes it would run differ), so a stale allowlist can never
// be silently revived.
func TestReconcileJailConfig_DifferentAllowlistRefuses(t *testing.T) {
	created := cfg()
	created.ProxyOnHostLoopback = true
	created.AllowDirect = []cli.DirectAllow{allow(t, "192.168.1.150", 8080)}

	requested := created
	requested.AllowDirect = []cli.DirectAllow{allow(t, "10.0.0.5", 443)} // different allowlist

	err := reconcileJailConfig(requested, bakedFor(created))
	if err == nil {
		t.Fatalf("a DIFFERENT --allow-direct must be REFUSED, never silently revived")
	}
	if !isJailConfigChanged(err) {
		t.Fatalf("a changed allowlist must be an ErrJailConfigChanged refusal; got %v", err)
	}
}

// TestReconcileJailConfig_RefusalMessageIsActionable: the refuse message names
// the mismatch AND tells the user the two safe options (remove + re-run, or start
// with the same jail config), so a stale-config refusal is self-correcting rather
// than opaque (the finding's exact policy).
func TestReconcileJailConfig_RefusalMessageIsActionable(t *testing.T) {
	created := cfg()
	created.ProxyOnHostLoopback = true
	requested := created
	requested.Proxy = cli.ProxyConfig{Host: "127.0.0.1", Port: "1080"}

	err := reconcileJailConfig(requested, bakedFor(created))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, want := range []string{"different", "remove", "same jail config"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refuse message must be actionable (mention %q); got: %s", want, msg)
		}
	}
}

// TestSidecarStartArgs_RevivesByName: reviving the sidecar is a plain `podman
// start <sidecar>` of the EXISTING container (podman re-runs its baked
// EXTRA_COMMANDS firewall on start), named run-attributably. No create flags:
// this is a revive, not a fresh create.
func TestSidecarStartArgs_RevivesByName(t *testing.T) {
	c := cfg()
	got := strings.Join(c.SidecarStartArgs(), " ")
	want := "start netcage-run-abc123-sidecar"
	if got != want {
		t.Fatalf("SidecarStartArgs = %q, want %q (a plain revive of the existing sidecar)", got, want)
	}
}

// TestToolStartArgs_StartsExistingToolNotFreshRun: re-entering the kept tool is
// `podman start` of the EXISTING container (preserving its state), NEVER a fresh
// `podman run` (which would lose state and re-create it). Non-interactive attaches
// so the tool's output flows through.
func TestToolStartArgs_AttachesExistingTool(t *testing.T) {
	c := cfg()
	got := strings.Join(c.ToolStartArgs(), " ")
	if !strings.HasPrefix(got, "start ") {
		t.Fatalf("ToolStartArgs must `podman start` the EXISTING tool (not `run` a fresh one); got: %s", got)
	}
	if strings.Contains(got, "--network") || strings.Contains(got, "run ") {
		t.Fatalf("ToolStartArgs must NOT re-create the tool (no `run`/`--network`); got: %s", got)
	}
	if !strings.Contains(got, "-a") {
		t.Fatalf("non-interactive start must ATTACH (-a) so the tool's output flows through; got: %s", got)
	}
	if !strings.Contains(got, c.toolName()) {
		t.Fatalf("ToolStartArgs must name the kept tool %q; got: %s", c.toolName(), got)
	}
}

// TestToolStartArgs_InteractiveAttachesStdin: an interactive start re-enters the
// kept tool with a TTY + stdin (`podman start -ai`) so a human/agent can resume a
// shell in the durable jailed environment.
func TestToolStartArgs_InteractiveAttachesStdin(t *testing.T) {
	c := cfg()
	c.Interactive = true
	got := strings.Join(c.ToolStartArgs(), " ")
	if !strings.HasPrefix(got, "start ") {
		t.Fatalf("interactive ToolStartArgs must still `podman start` the existing tool; got: %s", got)
	}
	if !strings.Contains(got, "-i") {
		t.Fatalf("interactive start must attach stdin (-i); got: %s", got)
	}
}
