# The jail confines NETWORK egress but leaks host-IDENTITY metadata (username, hostname, hardware, NIC, pod names) via /proc, /etc/hosts, and Podman mount paths

type: observation
status: spotted
spotted: 2026-07-04

Captured from a live anon-pi session (pi agent running INSIDE a netcage jail).
Provenance: an interactive transcript, not code I read, so this is a spotted
observation, not a verified finding. It records what a jailed tool could
enumerate about the HOST from inside the cage.

## What was seen

A user asked the jailed pi agent "find anything that could identify you". Without
touching the network at all, the agent read local files/interfaces and recovered
a detailed host fingerprint:

- **Host username `wighawag`** - from Podman storage paths visible in
  `/proc/self/mountinfo` (`/home/wighawag/.local/share/containers/storage/...`).
- **Host machine name `nono`** - from `/etc/hosts` (`127.0.1.1 nono`).
- **Host hardware** - `/proc/cpuinfo` (AMD Ryzen 7 PRO 6850U, 8c/16t),
  `/proc/meminfo` (~30 GB), `/proc/version` + `uname -a` (kernel `6.12.90+deb13.1`).
- **Host NIC** - interface `enxc8a362ba9779` visible in the container, whose
  suffix is (part of) the host NIC MAC.
- **Runtime + topology** - `container=podman` and the netcage pod/container names
  (`netcage-run-<id>-sidecar`, `netcage-run-<id>-tool`) from `/proc/1/environ`.
- **Sidecar env** - `ANON_PI_STAGE`, `SEARXNG_HOME`, DNS on `127.0.0.1:53`, `tun0`.

## Why it matters (and the scope question it raises)

netcage's stated guarantee (CONTEXT.md) is **forced NETWORK egress**: every TCP
and DNS packet is pushed through the socks5h proxy, fail-closed, so the tool
cannot leak the real IP or resolve DNS on the host. Nothing in the transcript
shows that guarantee broken: the agent read *local* interface IPs
(`hostname -I`, `192.168.1.164`, `fd7a:...` tailscale) and local files; it did
not demonstrate a packet escaping the proxy. So the **network** contract may
well still hold.

BUT the transcript exposes a scope gap worth a decision: a recon/scan tool that
netcage is meant to CONFINE can still fingerprint the operator's machine (real
username, hostname, exact CPU/kernel, NIC MAC) purely from `/proc`, `/etc/hosts`,
and the Podman rootless storage mount paths. For netcage's threat model (run
untrusted/aggressive tools without leaking who/where you are), a host fingerprint
this precise is arguably as deanonymizing as an IP leak, even though it is out of
the current "forced egress" framing.

Notable leak surfaces, roughly by how netcage-owned they are:

1. **`/etc/hosts` -> host machine name** (`nono`). netcage refuses user
   `--add-host`/`--hostname` (cli/cli.go) but does not appear to sanitize the
   `/etc/hosts` the tool container inherits. This one looks the most fixable and
   the most clearly in-scope.
2. **Podman storage paths -> host username** in `/proc/self/mountinfo`. Inherent
   to rootless Podman overlay mounts; harder to hide without changing how
   volumes/rootfs are mounted.
3. **Pod/container/env names -> `netcage-run-<id>`, `ANON_PI_STAGE`,
   `SEARXNG_HOME`** in `/proc/1/environ`. netcage owns the naming and the
   sidecar env; it could avoid leaking wrapper-identifying names into `PID 1`'s
   environment.
4. **`/proc/cpuinfo|meminfo|version`, NIC name** - host kernel/hardware, largely
   inherent to sharing the host kernel; masking needs seccomp/masked-paths or a
   different isolation layer, likely out of scope for v1.

## Suggested next step (not taken here)

Decide scope explicitly rather than silently: either (a) an ADR that says
netcage's guarantee is NETWORK egress ONLY and host-identity masking is a
non-goal (documenting the residual fingerprint so users aren't surprised), or
(b) a task to shrink the cheap, clearly-in-scope surfaces first (sanitize
`/etc/hosts`; keep wrapper-identifying names out of PID 1's env), and note the
inherent-to-rootless-Podman ones (mountinfo username, host kernel/hardware) as
accepted residual risk. The `verify` leak-test proves network confinement; it
does NOT currently probe host-identity exposure, so whichever way scope lands,
the acceptance seam may want an explicit "host-fingerprint is/ isn't in scope"
statement.

## Update 2026-07-04 - per-leak discussion + decisions (grounded in the code)

Re-read the actual jail construction to ground this: the tool container is a
plain `podman run --network container:<sidecar>` (jail.go `ToolRunArgs`). netcage
sets NO `--hostname`, does NOTHING to `/etc/hosts`, applies NO seccomp/masked-
paths beyond podman defaults, and shares the host kernel (containers, not VMs).
That one fact explains most leaks below. Framing stands: netcage's contract is
NETWORK egress; nothing in the transcript broke it (the agent read LOCAL files/
interfaces, never showed a packet escaping the proxy). Everything recovered is
host-IDENTITY metadata, a separate guarantee.

Leak-by-leak verdicts (agreed with maintainer):

1. **`/etc/hosts` leaks host machine name (`127.0.1.1 nono`)** - FIX, cheap,
   clearly in-scope. Sharpest inconsistency: netcage already refuses `--add-host`
   and gates `--hostname` because `/etc/hosts` sidesteps proxy-side DNS, yet
   leaves the host's own name in that file. Fix: mount a sanitized `/etc/hosts`
   (`127.0.0.1 localhost` + `::1 localhost`) `:ro`, MIRRORING the existing
   resolv.conf pattern (`resolvConfPath` -> `/etc/resolv.conf:ro`), plus set a
   fixed `--hostname` on the tool container. -> TASK.

2. **Podman storage paths leak host USERNAME (`/home/wighawag/...` in
   `/proc/self/mountinfo`)** - in-scope by threat model, but the leak is a
   `graphroot`-LOCATION problem, not a privilege problem. Rootless podman's
   default graphroot is `$HOME/.local/share/containers/storage`, so the overlay
   lowerdir/upperdir SOURCE paths in mountinfo embed `$HOME` -> the username.

   - **Rootful would "fix" it only incidentally** (rootful default graphroot is
     `/var/lib/containers/storage`, username-free) but detonates the
     architecture: rootless is load-bearing (ADR-0001, ADR-0002, both
     foundational spikes; pasta host-loopback reachback is a rootless mechanism)
     AND rootful worsens the escape/blast-radius threat model. NET LOSS. Not
     doing it.
   - **Right lever, staying rootless:** relocate graphroot to a neutral path via
     a netcage-managed `storage.conf` / `CONTAINERS_STORAGE_CONF` / `--root`.
     Open question a SPIKE must answer: what path is actually reachable rootless
     and does it stay username-free (vs. only uid-free, e.g. `/run/user/<uid>`,
     which swaps username-for-uid = a weaker identifier, arguably an
     improvement)?
   - **Belt-and-suspenders (runtime-agnostic):** MASK the mountinfo family
     (`/proc/self/mountinfo`, `/proc/self/mounts`, `/proc/1/mountinfo`) with an
     empty/`/dev/null` bind. This is the ONLY option that also hides user `-v`
     VOLUME source paths (which no graphroot move can neutralize, since the user
     chose them). Caveat: some tools legitimately read mountinfo.
   -> SPIKE TASK (graphroot relocation) + masking fallback.

3. **Wrapper/topology names (`netcage-run-<id>-*`, `ANON_PI_STAGE`,
   `SEARXNG_HOME`, `container=podman`)** - mostly NOT netcage's. `netcage-run-<id>`
   is netcage-owned but low-sensitivity (the `netcage.managed=true` labels already
   announce it at rest by design, ADR-0009) and hiding it fights the pass-through
   verbs that scope on it. `container=podman` is podman-injected. `ANON_PI_STAGE`/
   `SEARXNG_HOME` come from the ANON-PI wrapper image/entrypoint, not netcage.
   -> CROSS-REPO note to anon-pi (scope those to the build stage, don't bake into
   the jailed tool's env); leave netcage naming as-is.

4. **Host hardware/kernel (`/proc/cpuinfo|meminfo|version`, `uname`)** - shared
   kernel; a container fundamentally cannot hide this from a hostile in-container
   process (`--cpus`/`--memory` change cgroup accounting, NOT what `/proc/cpuinfo`
   reports). Faking it is a brittle rabbit hole; a real fix needs gVisor/Kata (a
   different runtime). -> ACCEPTED RESIDUAL, documented in the scope ADR.

5. **NIC name/MAC (`enxc8a362ba9779`, `tun0`)** - INVESTIGATE provenance first.
   Likely pasta reflecting the host NIC name into the netns (the code sets
   `CLONE_MAIN=0` to stop route-cloning storms; pasta copies host addresses/
   routes). If confirmed, a rename of the in-netns device (or a pasta option)
   neutralizes the MAC-derived name without touching egress (the route out is the
   TUN, not this device's name). -> INVESTIGATION TASK (pin the source before
   proposing a fix).

Cross-cutting: `verify` proves only the network three-point leak-test, never
host-identity exposure. Whichever way scope lands needs an EXPLICIT statement.

### Provisioning constraint (maintainer decision)

Any fix that needs an external directory podman can write to (esp. Leak 2's
relocated graphroot) MUST NOT have netcage silently create privileged/host
state. netcage stays rootless and side-effect-honest: the USER provisions the
neutral storage location (creates the dir, sets ownership/permissions), and
netcage provides a HELPER COMMAND (e.g. a `netcage` subcommand) to make that
provisioning easy and correct. So the split is: netcage EXPLAINS + offers a
one-liner to set it up; the user (not netcage) OWNS the host-state creation.
This constraint applies to the Leak 2 spike/task deliverable.

### Agreed routing

| Leak | Verdict | Deliverable |
| --- | --- | --- |
| 1 `/etc/hosts` | fix, cheap, in-scope | task: sanitized `/etc/hosts` mount + `--hostname` default |
| 2 username via mountinfo | stay rootless; relocate graphroot + mask mountinfo | SPIKE task (reachable neutral path?) + masking fallback + a provisioning helper command |
| 3 env/name leaks | mostly not netcage's | cross-repo note -> anon-pi; leave netcage naming |
| 4 hardware/kernel | out-of-scope | scope ADR: accepted residual (container, not VM) |
| 5 NIC name/MAC | investigate first | investigation task to pin provenance |
| cross-cutting | decide scope | ADR: network egress guaranteed; host-identity masking scope stated per-leak, incl. the provisioning constraint |
