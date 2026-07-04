//go:build integration
// +build integration

package jail_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/socks5hfixture"
)

// TestJail_Graphroot_MountinfoHasNoHomePath is the podman-gated proof of Leak 2's
// core property (prd story 3, ADR-0013): with the graphroot relocated under
// /var/tmp, a jailed tool reading its own /proc/self/mountinfo sees NO /home/<user>
// path, so it can no longer recover the operator's account name from the podman
// overlay lowerdir/upperdir SOURCE paths. It also positively asserts the overlay
// source IS the relocated (scratch) store, proving the --root injection reached
// the tool container's own storage mounts, not just netcage's bookkeeping.
func TestJail_Graphroot_MountinfoHasNoHomePath(t *testing.T) {
	requirePodman(t)

	store := os.Getenv("NETCAGE_GRAPHROOT")
	if store == "" {
		t.Skip("no scratch graphroot set (NETCAGE_GRAPHROOT); TestMain did not isolate storage")
	}

	// The tool just prints its own mountinfo. The jail still needs its sidecar, so
	// stand up a fixture proxy on host loopback (the tool never egresses; the read
	// is local), and run EPHEMERAL so nothing is left behind.
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	cfg := jail.Config{
		Ephemeral:           true,
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"cat", "/proc/self/mountinfo"},
		RunID:               "mntinfo" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", ""),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err != nil {
		t.Fatalf("jail.Run: %v\nstderr: %s", err, res.ToolStderr)
	}
	mountinfo := res.ToolStdout

	// The username leak: mountinfo must carry no /home/<user> podman storage path.
	if strings.Contains(mountinfo, "/home/") {
		t.Fatalf("jailed /proc/self/mountinfo still embeds a /home/<user> path (the username leaks via podman storage):\n%s", mountinfo)
	}
	// And specifically not THIS operator's home dir, whatever it is.
	if home, herr := os.UserHomeDir(); herr == nil && home != "" && home != "/" {
		if strings.Contains(mountinfo, home) {
			t.Fatalf("jailed mountinfo embeds the operator home %q (username leak):\n%s", home, mountinfo)
		}
	}
	// Positive proof the tool's OWN overlay is served from the relocated store,
	// i.e. the --root injection reached the tool container's storage mounts.
	if !strings.Contains(mountinfo, store) {
		t.Fatalf("jailed mountinfo does not reference the relocated graphroot %q; the tool's overlay may be on the default (home) store:\n%s", store, mountinfo)
	}
}

// TestJail_Graphroot_SingleSharedStore is the podman-gated single-store proof
// (prd story 5, ADR-0013): a container a `netcage run` CREATES is found by a
// SUBSEQUENT netcage-managed listing in the SAME relocated store, and is NOT in
// the developer's real default store (proving the store is SHARED across
// invocations AND relocated, not split). A split store would make `netcage
// ps`/`start` unable to see a `netcage run`'s container.
func TestJail_Graphroot_SingleSharedStore(t *testing.T) {
	requirePodman(t)

	store := os.Getenv("NETCAGE_GRAPHROOT")
	if store == "" {
		t.Skip("no scratch graphroot set (NETCAGE_GRAPHROOT); TestMain did not isolate storage")
	}

	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	runID := "onestore" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	t.Cleanup(func() { forceRemoveStartPair(runID) })

	cfg := jail.Config{
		Ephemeral:           false, // KEPT: leave the pair so a later listing/start can find it
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"true"},
		RunID:               runID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err := jail.Run(ctx, jail.ExecRunner{}, cfg); err != nil {
		t.Fatalf("kept netcage run: %v", err)
	}

	toolName := "netcage-run-" + runID + "-tool"

	// A SUBSEQUENT listing in the SAME (relocated) store must see the kept tool:
	// this is what `netcage ps`/`start` do, so it proves the store is shared, not
	// split. residueFor already scopes its `podman ps` to the scratch store.
	if left := residueFor(t, runID); len(left) < 2 {
		t.Fatalf("a kept `netcage run`'s pair is NOT visible to a subsequent listing in the same relocated store; the store split (got %v)", left)
	}

	// The SAME container must NOT be in the developer's real default store, proving
	// the graphroot actually MOVED (not merely a second path onto the home store).
	def := defaultStoreContainers(ctx, t)
	if strings.Contains(def, toolName) {
		t.Fatalf("the kept container %s appears in the DEFAULT store; the graphroot did not relocate (shared-write isolation broken)", toolName)
	}

	// And `netcage start` must be able to operate the kept container from the same
	// relocated store (the single-store operability half of story 5). A revive of a
	// container the default store cannot see would fail if the store had split.
	res, err := jail.Start(ctx, jail.ExecRunner{}, cfg, toolName)
	if err != nil {
		t.Fatalf("netcage start could not revive the kept container from the relocated store: %v\nstderr: %s", err, res.ToolStderr)
	}
}

// TestJail_Graphroot_RealDefaultStoreUntouched is the shared-write isolation
// assertion the task's acceptance calls for: after an integration jail run, the
// developer's REAL default store (~/.local/share/containers/storage) carries no
// netcage-run-* container (the run went entirely into the scratch graphroot). It
// is the guard that makes running these podman-gated tests on a dev box safe.
func TestJail_Graphroot_RealDefaultStoreUntouched(t *testing.T) {
	requirePodman(t)

	if os.Getenv("NETCAGE_GRAPHROOT") == "" {
		t.Skip("no scratch graphroot set (NETCAGE_GRAPHROOT); TestMain did not isolate storage")
	}

	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	runID := "isolate" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	cfg := jail.Config{
		Ephemeral:           true,
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"true"},
		RunID:               runID,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_, _ = jail.Run(ctx, jail.ExecRunner{}, cfg)

	if def := defaultStoreContainers(ctx, t); strings.Contains(def, "netcage-run-"+runID) {
		t.Fatalf("an integration run leaked a container into the developer's DEFAULT store (shared-write isolation broken):\n%s", def)
	}
}

// defaultStoreContainers lists container names in the developer's REAL DEFAULT
// podman store (NO --root, so podman uses ~/.local/share/containers/storage). It
// is deliberately UNSCOPED by NETCAGE_GRAPHROOT so a test can assert the real
// store is untouched by the relocated-store runs.
func defaultStoreContainers(ctx context.Context, t *testing.T) string {
	t.Helper()
	out, _ := exec.CommandContext(ctx, "podman", "ps", "-a", "--format", "{{.Names}}").CombinedOutput()
	return string(out)
}
