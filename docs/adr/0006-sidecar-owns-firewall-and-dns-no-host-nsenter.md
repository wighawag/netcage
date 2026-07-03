# The sidecar owns its firewall and DNS forwarder; netcage never uses host nsenter

**Status:** accepted (refined by ADR-0008: the firewall now rides in the sidecar's create-time `EXTRA_COMMANDS` instead of a runtime `podman exec`, so it self-heals on every restart; netcage's own post-start verification, not the script's `set -e`, is the fail-loud layer. The sidecar still owns its firewall + DNS forwarder; only WHERE/WHEN the firewall is applied moved.)

The jail's two in-netns setup steps, applying the firewall (UDP drop, reachback narrowing, split-tunnel rules) and launching the `netcage-dns` forwarder, run INSIDE the redirector sidecar via `podman exec`, not from the host via `nsenter -t <sidecar-pid>`. The firewall is an iptables script (the pinned sidecar image ships iptables, nf_tables-backed; the sidecar already has `CAP_NET_ADMIN`), and the DNS helper is mounted read-only into the sidecar and started with `podman exec -d`, so it is container-lifecycle-bound (teardown's `podman rm -f` kills it; no host-side process to track).

The original wiring (host `nsenter ... nft -f -` and a host-side `nsenter ... netcage-dns` process, from the pasta-reachback spike) worked but made netcage more than a podman client: it reached into the sidecar's namespaces by host PID, which requires `nsenter` and `nft` on the host, requires netcage to run on the SAME kernel as the containers, and leaves a host process to babysit. The spike notes themselves anticipated this move ("in the real jail the sidecar will own this rule itself").

## Consequences

- **Smaller host requirements on Linux:** the host no longer needs `nsenter` or `nft` binaries; podman is the only runtime dependency netcage invokes besides itself.
- **Every jail step flows through the Runner seam (podman argv only),** so netcage is a pure podman client. This is the enabling change for driving a REMOTE podman (macOS `podman machine`, Windows WSL2) from a native binary later; nothing in the jail's setup assumes netcage shares a kernel with the containers anymore.
- **`netcage-dns` must be a STATIC binary** (release builds already are, `CGO_ENABLED=0`): it now execs inside the musl-based sidecar image, which cannot load a glibc-dynamic build. `go install` users must build it with `CGO_ENABLED=0`; the jail surfaces a pointed error if the exec fails.
- **The firewall language changed from nft to iptables** (what the pinned image ships). The rules are semantically the same set the spikes proved; the nft `inet`-table dual-family UDP drop is mirrored with an explicit `ip6tables` UDP drop. The script runs under `set -e` so a half-applied firewall aborts the run loudly instead of leaking.
- The `verify` leak-test is unchanged and still proves the jail end-to-end on the new wiring.
