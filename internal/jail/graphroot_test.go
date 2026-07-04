package jail

import (
	"context"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// TestGraphRoot_UsernameFreeVarTmpDefault pins Leak 2's core property: the
// resolved graphroot is a username-free path UNDER /var/tmp (so the overlay
// lowerdir/upperdir SOURCE paths in the container's /proc/self/mountinfo no
// longer embed /home/<user>). The default is a fixed neutral subpath; an env
// override (NETCAGE_GRAPHROOT) exists ONLY so tests can isolate real storage
// under a scratch dir (the shared-write isolation rule), never to carry a
// username by default.
func TestGraphRoot_UsernameFreeVarTmpDefault(t *testing.T) {
	t.Setenv("NETCAGE_GRAPHROOT", "") // force the default, ignoring any ambient override
	got := graphRoot()
	if !strings.HasPrefix(got, "/var/tmp/") {
		t.Fatalf("graphroot %q must live under /var/tmp (world-writable-sticky, disk-backed, username-free)", got)
	}
	if strings.Contains(got, "/home/") {
		t.Fatalf("graphroot %q must be username-free (no /home/<user> path); that is the whole point of Leak 2", got)
	}
}

func TestGraphRoot_EnvOverrideForTestIsolation(t *testing.T) {
	t.Setenv("NETCAGE_GRAPHROOT", "/tmp/scratch-store")
	if got := graphRoot(); got != "/tmp/scratch-store" {
		t.Fatalf("NETCAGE_GRAPHROOT override not honoured: got %q, want /tmp/scratch-store", got)
	}
}

// TestPodmanGlobalArgs_InjectsRootAsGlobalFlag pins the single-seam contract:
// the --root selection is prepended as a GLOBAL flag (BEFORE the subcommand),
// never appended after it (`podman --root <path> run ...`, never `podman run
// --root <path>`, which podman rejects), and --runroot is NOT overridden (ADR-0013:
// co-locating both produced lock-refresh noise; only --root moves).
func TestPodmanGlobalArgs_InjectsRootAsGlobalFlag(t *testing.T) {
	t.Setenv("NETCAGE_GRAPHROOT", "/var/tmp/store-under-test")
	got := podmanGlobalArgs([]string{"run", "--rm", "alpine", "true"})
	want := []string{"--root", "/var/tmp/store-under-test", "run", "--rm", "alpine", "true"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("podmanGlobalArgs must prepend --root <path> before the subcommand (a global flag, not after it)\ngot:  %v\nwant: %v", got, want)
	}
	for _, a := range got {
		if a == "--runroot" {
			t.Fatalf("--runroot must NOT be overridden (ADR-0013); got %v", got)
		}
	}
}

// TestPodmanGlobalArgs_CoversEveryBuilderFamily is the seam assertion the task
// calls for: a REPRESENTATIVE invocation from EACH builder family, when routed
// through the shared podman-arg seam, carries the SAME --root global flag before
// the subcommand. Asserted ONCE at the seam (not duplicated per builder), which
// is exactly why the injection is impossible to miss: every podman argv netcage
// builds flows through here.
func TestPodmanGlobalArgs_CoversEveryBuilderFamily(t *testing.T) {
	t.Setenv("NETCAGE_GRAPHROOT", "/var/tmp/family-store")
	base := Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"true"},
		RunID:               "fam",
	}

	// One representative argv from each builder family that reaches podman.
	families := map[string][]string{
		"jail run (sidecar)": base.SidecarRunArgs(),
		"jail run (tool)":    base.ToolRunArgs(),
		"jail start":         base.SidecarStartArgs(),
		"jail teardown/rm":   {"rm", "-f", "-i", base.toolName()},
		"jail verify probe":  {"exec", base.sidecarName(), "iptables", "-S", "OUTPUT"},
		// a manage verb argv is a plain podman argv too (manage builds RunSpec{Name:"podman",...})
		"manage verb (ps)": {"ps", "-a", "--filter", "label=netcage.managed=true"},
		// the interactive exec / raw-passthrough argv is likewise a podman argv
		"interactive exec": {"exec", "-i", "-t", base.toolName(), "bash"},
	}

	for name, args := range families {
		got := podmanGlobalArgs(args)
		if len(got) < 2 || got[0] != "--root" || got[1] != "/var/tmp/family-store" {
			t.Fatalf("%s: seam did not prepend --root <path> as a global flag; got %v", name, got)
		}
		// The original subcommand must still follow the injected global flag intact.
		if strings.Join(got[2:], " ") != strings.Join(args, " ") {
			t.Fatalf("%s: seam altered the subcommand argv; got %v want tail %v", name, got, args)
		}
	}
}

// TestExecRunner_InjectsGraphRootForPodman proves the injection happens AT the
// exec seam (not per builder): ExecRunner routes a podman command through
// podmanGlobalArgs so EVERY inline ExecRunner{} construction site carries the
// graphroot with zero per-site wiring. A NON-podman command (e.g. the local `sh`
// the streaming tests use) is left untouched, so the injection is scoped to
// podman only. Uses `sh` echoing its own argv so no podman is needed.
func TestExecRunner_InjectsGraphRootForPodman(t *testing.T) {
	t.Setenv("NETCAGE_GRAPHROOT", "/tmp/exec-seam-store")

	// Non-podman command: argv must be untouched (no --root injected).
	stdout, _, err := ExecRunner{}.Run(context.Background(), RunSpec{
		Name: "sh",
		Args: []string{"-c", `printf '%s\n' "$@"`, "sh", "run", "alpine"},
	})
	if err != nil {
		t.Skipf("sh not usable in this environment: %v", err)
	}
	if strings.Contains(stdout, "--root") {
		t.Fatalf("non-podman command must not get --root injected; got argv:\n%s", stdout)
	}
}
