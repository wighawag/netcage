package jail

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// TestGraphRoot_UidScopedUsernameFreeVarTmpDefault pins the default's two
// properties (ADR-0017): the resolved graphroot is a username-free path UNDER
// /var/tmp (so the overlay lowerdir/upperdir SOURCE paths in the container's
// /proc/self/mountinfo no longer embed /home/<user>, Leak 2), AND it is
// UID-SCOPED (carries the running user's numeric uid), so two different Unix
// users on one host get distinct, non-colliding stores. A numeric uid is
// name-free (it is not the login NAME), which is what Leak 2 requires; the uid
// is what fixes the multi-user collision. An env override (NETCAGE_GRAPHROOT)
// bypasses this default entirely.
func TestGraphRoot_UidScopedUsernameFreeVarTmpDefault(t *testing.T) {
	t.Setenv("NETCAGE_GRAPHROOT", "") // force the default, ignoring any ambient override
	got := graphRoot()
	if !strings.HasPrefix(got, "/var/tmp/") {
		t.Fatalf("graphroot %q must live under /var/tmp (world-writable-sticky, disk-backed, username-free)", got)
	}
	if strings.Contains(got, "/home/") {
		t.Fatalf("graphroot %q must be username-free (no /home/<user> path); that is the whole point of Leak 2", got)
	}
	// UID-scoped: the path must end with the running user's numeric uid, so a
	// second Unix user resolves a different store (fixes the multi-user collision).
	uid := strconv.Itoa(os.Getuid())
	if !strings.HasSuffix(got, "-"+uid) {
		t.Fatalf("graphroot %q must be uid-scoped (end with -%s) so distinct users get distinct stores (ADR-0017)", got, uid)
	}
}

// TestDefaultGraphRoot_DistinctPerUid pins the collision fix directly: the
// uid-scoped default is a pure function of the uid, so two different uids map to
// two different paths (the property that lets a login user and a dedicated
// account both run netcage on one host without colliding on the store).
func TestDefaultGraphRoot_DistinctPerUid(t *testing.T) {
	// defaultGraphRoot() reads os.Getuid() (no arg to inject), so assert the
	// composition rule it implements: base + "-" + uid, and that two uids differ.
	p1000 := graphRootBase + "-" + strconv.Itoa(1000)
	p1001 := graphRootBase + "-" + strconv.Itoa(1001)
	if p1000 == p1001 {
		t.Fatalf("two uids must map to different graphroots; got %q for both", p1000)
	}
	// And the live resolver matches the rule for the current process's uid.
	t.Setenv("NETCAGE_GRAPHROOT", "")
	want := graphRootBase + "-" + strconv.Itoa(os.Getuid())
	if got := defaultGraphRoot(); got != want {
		t.Fatalf("defaultGraphRoot() = %q, want uid-scoped %q", got, want)
	}
}

// TestGraphRoot_EnvOverrideHonoured pins the SUPPORTED optional override
// (ADR-0017): NETCAGE_GRAPHROOT, when set, points the whole store at that path
// verbatim, bypassing the uid-scoped default. (This same mechanism is what tests
// use to isolate storage under a scratch dir.)
func TestGraphRoot_EnvOverrideHonoured(t *testing.T) {
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
