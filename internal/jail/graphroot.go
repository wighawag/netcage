package jail

import "os"

// defaultGraphRoot is netcage's username-free podman graphroot (podman's global
// `--root`): the disk-backed, world-writable-sticky, USERNAME-FREE path under
// /var/tmp where image layers + containers live (Leak 2 of the host-identity
// hardening prd; ADR-0013). Rootless podman's DEFAULT graphroot is
// ~/.local/share/containers/storage, so the overlay lowerdir/upperdir SOURCE
// paths in the container's /proc/self/mountinfo embed /home/<user>, leaking the
// operator's account name. Pointing --root here makes those paths username-free.
//
// Why /var/tmp (ADR-0013 + the tested observation): it is world-writable-sticky
// (drwxrwxrwt, so the user's subdir needs NO root and NO provisioning helper),
// DISK-backed (survives reboots, so kept runs per ADR-0009 and the image cache
// persist, unlike RAM-backed /tmp / $XDG_RUNTIME_DIR), and username-free. The
// subpath is a fixed neutral name (no username, no uid) so mountinfo carries
// neither. Storage semantics are EXACTLY today's home-folder store, only the
// path changes: persistent, self-healing (podman re-inits + re-pulls on demand
// if the dir is wiped), holding the image cache + kept containers.
const defaultGraphRoot = "/var/tmp/netcage-storage"

// graphRootEnv lets a TEST isolate real storage under a scratch dir (the
// shared-write isolation rule: an integration test that stands up real podman
// MUST NOT touch the developer's ~/.local/share/containers/storage). It is NOT a
// user-facing knob: production always resolves to defaultGraphRoot. It mirrors
// NETCAGE_DNS_BIN, the existing test-only env seam in this package.
const graphRootEnv = "NETCAGE_GRAPHROOT"

// graphRoot resolves the podman graphroot path: the NETCAGE_GRAPHROOT test
// override when set, else the fixed username-free defaultGraphRoot. Kept as one
// pure resolver so every podman invocation shares ONE store (never a split), and
// so a test can point it at a scratch dir without touching the real store.
func graphRoot() string {
	if p := os.Getenv(graphRootEnv); p != "" {
		return p
	}
	return defaultGraphRoot
}

// podmanGlobalArgs prepends podman's GLOBAL `--root <graphroot>` flag BEFORE the
// subcommand argv, so the store selection travels with EVERY podman invocation
// netcage makes (`podman --root <path> run ...`, never `podman run --root
// <path>`, which podman rejects). This is the SINGLE injection seam (ADR-0013):
// applying it here at the shared exec seam (ExecRunner.Run) - not in the
// individual arg-builders (ToolRunArgs/SidecarRunArgs/the manage verb builders)
// - is what makes it impossible to miss an invocation and guarantees jail AND
// manage AND verify AND the probe/interactive paths all share ONE store. A
// per-builder edit would SPLIT the store, making `netcage ps`/`start` unable to
// find the containers a `netcage run` created (a correctness break, not just a
// leak).
//
// `--runroot` is deliberately LEFT at its default: co-locating the transient
// runroot with the persistent root and wiping both produced `acquiring lock ...
// file exists` refresh noise in probes (ADR-0013), so only `--root` moves.
func podmanGlobalArgs(args []string) []string {
	out := make([]string, 0, len(args)+2)
	out = append(out, "--root", graphRoot())
	return append(out, args...)
}
