package jail

import (
	"os"
	"strconv"
)

// graphRootBase is the fixed, username-free stem of netcage's podman graphroot
// (podman's global `--root`): the disk-backed, world-writable-sticky path under
// /var/tmp where image layers + containers live (Leak 2 of the host-identity
// hardening prd; ADR-0013). Rootless podman's DEFAULT graphroot is
// ~/.local/share/containers/storage, so the overlay lowerdir/upperdir SOURCE
// paths in the container's /proc/self/mountinfo embed /home/<user>, leaking the
// operator's account name. Pointing --root under /var/tmp makes those paths
// username-free.
//
// Why /var/tmp (ADR-0013 + the tested observation): it is world-writable-sticky
// (drwxrwxrwt, so the user's subdir needs NO root and NO provisioning helper),
// DISK-backed (survives reboots, so kept runs per ADR-0009 and the image cache
// persist, unlike RAM-backed /tmp / $XDG_RUNTIME_DIR), and username-free.
// Storage semantics are EXACTLY today's home-folder store, only the path
// changes: persistent, self-healing (podman re-inits + re-pulls on demand if
// the dir is wiped), holding the image cache + kept containers.
const graphRootBase = "/var/tmp/netcage-storage"

// defaultGraphRoot is the UID-SCOPED default graphroot: graphRootBase with the
// running user's numeric uid appended (`/var/tmp/netcage-storage-<uid>`).
//
// Why uid-scoped, not a single fixed path (ADR-0017): netcage never mkdir's the
// store - podman creates it lazily on first use - so a single shared
// /var/tmp/netcage-storage is created OWNED BY the first user to run netcage,
// and a SECOND Unix user on the same host then collides (rootless podman's
// per-user subuid-owned overlay tree cannot cohabit one path across two users;
// /var/tmp's sticky bit protects only the top level). That broke "two Unix
// accounts run netcage on one host" - the exact case anon-pi hits when it runs
// netcage as a dedicated `anon` user to scrub the operator's login name from the
// -v mount sources. Appending the uid gives each user a distinct, self-owned
// store with zero config, fixing the collision.
//
// A numeric uid in the path is name-free enough for Leak 2 (ADR-0017): Leak 2 is
// about the operator's login NAME, not a uid; the in-jail tool sees
// /var/tmp/netcage-storage-1000, which carries a uid but not the account name.
// This consciously RELAXES ADR-0013's "no username AND no uid" aspiration to "no
// username; a numeric uid is allowed", because a uid keeps the default
// self-healing (an opaque random subdir would force netcage to remember the
// path) while making multi-user operation correct.
func defaultGraphRoot() string {
	return graphRootBase + "-" + strconv.Itoa(os.Getuid())
}

// graphRootEnv is a SUPPORTED, OPTIONAL override (ADR-0017): point netcage's
// whole store at an explicit path (a specific disk, a tmpfs, a deployment
// convention). When unset, netcage resolves the uid-scoped defaultGraphRoot,
// which already handles the multi-user case, so this override is a convenience,
// not a requirement. Tests ALSO use it to isolate real storage under a scratch
// dir (the shared-write isolation rule: an integration test that stands up real
// podman MUST NOT touch the developer's ~/.local/share/containers/storage) - the
// same mechanism, aimed at a temp dir.
const graphRootEnv = "NETCAGE_GRAPHROOT"

// graphRoot resolves the podman graphroot path: the NETCAGE_GRAPHROOT override
// when set, else the uid-scoped defaultGraphRoot. Kept as one pure resolver so
// every podman invocation shares ONE store (never a split), and so a caller (or
// a test) can point it at an explicit path without touching the default store.
func graphRoot() string {
	if p := os.Getenv(graphRootEnv); p != "" {
		return p
	}
	return defaultGraphRoot()
}

// GraphRoot exports the resolved graphroot for the ONE caller that spawns podman
// OUTSIDE the ExecRunner.Run seam: the `forward` verb's host-side socat relay
// runs `podman --root <graphroot> exec -i <tool> ...` as a CHILD of socat, so it
// cannot inherit the automatic --root injection podmanGlobalArgs applies at the
// exec seam and must embed the store explicitly. It resolves through the SAME
// pure resolver (test override honoured), so the forward's connect side reads the
// exact store the jail wrote into (never a split); do NOT fork a second graphroot
// resolver in the forward package.
func GraphRoot() string { return graphRoot() }

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
