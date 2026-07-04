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

## Update 2026-07-04 - mountinfo masking is opt-in, and the command surface for it

Two maintainer decisions, refining Leak 2 and the provisioning story.

### 1. mountinfo masking is NOT a default

Masking the `/proc/self/mountinfo` family can BREAK tools that legitimately read
it (mount inspectors, some package/build tooling), so it must NOT be on by
default. It is an OPT-IN hardening the user enables knowingly. (The graphroot
relocation, by contrast, is transparent to tools and could be a default once the
spike proves a reachable username-free path; masking stays opt-in regardless.)

### 2. Command surface: `setup-default` stays its own verb; a NEW `setup` verb
### enables the extra hardening

This builds on ADR-0012's existing naming invariant (a netcage-only verb must
never shadow a podman verb; that is why the config WRITER is `setup-default`, not
`init`).

- **`setup-default` KEEPS its own dedicated name** (not folded into a generic
   `setup`). The point of the distinct name is to make the user KNOW they are
   defining a persisted DEFAULT that every later `netcage run` reuses (ADR-0012:
   the name signals the silent-default tradeoff). Collapsing it into a plain
   `setup` would lose that signal. So `setup-default` remains separate.
- **A NEW `setup` verb** is the natural home for enabling the extra host-identity
   hardening that needs host-state provisioning: creating/owning the neutral
   graphroot directory the user must provide (the provisioning-helper from the
   previous update), and opting into the mountinfo masking. `setup` = "prepare
   this host/environment for hardened netcage runs" (provision the writable
   graphroot dir with correct ownership, optionally enable masking); it is
   distinct in MEANING from `setup-default` = "persist my default proxy/allowlist".
   Neither collides with a podman verb (podman has no `setup`), so both satisfy
   ADR-0012's rule.

Net: two sibling verbs with clearly different jobs, not one overloaded one.
`setup-default` -> persisted proxy/allowlist default (the ADR-0012 writer, exists
in the config prd). `setup` -> host provisioning + opt-in hardening toggles (new,
owns the Leak 2 provisioning-helper + the opt-in mountinfo masking). The
provisioning constraint from the prior update lands HERE: `setup` is the helper
that makes the user-owned host-state creation easy and correct, while netcage
itself still never silently creates privileged/host state during a `run`.

Routing delta for Leak 2: the spike/task deliverable now targets `setup` as the
home for (a) the graphroot-relocation provisioning helper and (b) the opt-in
mountinfo-masking toggle (default OFF).

## Update 2026-07-04 - Leak 2 SIMPLIFIED: graphroot in /tmp (no root), tested; masking + `setup` dropped

Maintainer proposed putting the relocated graphroot in `/tmp` so NO root/host
provisioning is needed. TESTED live on this host (rootless podman 5.x):

    podman --root /tmp/netcage-graphroot-<uniq> run --rm --network none alpine \
      sh -c 'cat /proc/self/mountinfo'

Results (throwaway root, reset+removed after):
- Podman picks the **overlay** driver on `/tmp` fine (rootless). Overlay-on-tmpfs
  works.
- The overlay mount line becomes
  `lowerdir=/tmp/netcage-graphroot-.../overlay/...` with **ZERO lines containing
  `/home/wighawag`**. The username leak is GONE.
- `/tmp` is `drwxrwxrwt` (world-writable sticky), so the user creates their subdir
  with **NO privilege**. Kills the "external folder needs root" problem.

So `/tmp` (or a similar user-writable neutral path) is a PROVEN answer, no root.

Two caveats to carry (not blockers):
1. `/tmp` here is a **tmpfs (RAM-backed), wiped on reboot** -> the graphroot
   (image cache + container storage) is EPHEMERAL: images re-pull after reboot,
   and KEPT runs (ADR-0009) would not survive a reboot. Arguably GOOD for an
   anonymity tool (no persistent storage fingerprint), but it changes the
   kept-run promise. Alternatives if persistence matters: `$XDG_RUNTIME_DIR`
   (`/run/user/<uid>`, uid-based not username, `drwx------`) or disk-backed
   `/var/tmp/...`. The ONLY remaining open question is which default
   (persistence-vs-ephemerality tradeoff); `/tmp` proves a working one exists.
2. A tmpfs graphroot competes for RAM (here `/tmp` is 15G); a big image could
   pressure memory. Note, not a blocker.

**User `-v` project folders:** the source path is the user's OWN choice, so
netcage cannot neutralize it without hiding what the user asked for. Correct
answer is DOC GUIDANCE: "if you don't want your username to leak, mount your
project from a path OUTSIDE `$HOME`." A documentation fix, not code.

### The cascade (simpler outcome, agreed)

- graphroot in `/tmp` handles the overlay/rootfs source (no root); docs handle
  the `-v` volume source. Together these cover BOTH things mountinfo masking was
  for, so **DROP the mountinfo-masking option entirely** (it also avoided the
  "breaks tools that read mountinfo" downside for free).
- No masking toggle + no privileged folder to provision => the `setup` verb has
  NOTHING left to do, so **DROP the `setup` verb** proposed in the prior update.
- Command surface therefore stays as-is: `setup-default` remains the ONLY new
  verb (the ADR-0012 config writer); there is NO `setup`.

### Leak 2, final shape

| Prior plan | Final |
| --- | --- |
| relocate graphroot (spike for reachable path) | graphroot -> `/tmp` (or `$XDG_RUNTIME_DIR`/`/var/tmp`), PROVEN, no root |
| mask mountinfo family (opt-in) | DROPPED (unnecessary) |
| `setup` command + provisioning helper | DROPPED |
| user `-v` source leak | DOC guidance: mount from outside `$HOME` |
| open question | only: which neutral default (persistence vs ephemerality) |

Provenance: the two probes above were run live on this host 2026-07-04 with a
throwaway `--root` under `/tmp`, `podman system reset --force` + `rm -rf` after;
no residue, host storage untouched. (Spotted-observation status kept: this note
records a maintainer session's decisions + one local probe, not a full finding.)

## Update 2026-07-04 - default is /var/tmp; graphroot self-heals; runroot split; rm caveat

Maintainer picks **`/var/tmp`** as the graphroot default (disk-backed,
reboot-safe, 189G free here) BECAUSE netcage does NOT `--rm` by default (kept
runs, ADR-0009) so storage + kept pairs + the image cache should survive reboots.
`/tmp`/`$XDG_RUNTIME_DIR` (both tmpfs, wiped on reboot/logout, and XDG is only 3G)
would drop kept runs and re-pull every boot; wrong for a kept-by-default tool.

Tested "what if the folder is wiped: must netcage rebuild it?" -- live probes on a
throwaway `--root`, no residue:

1. Delete just the storage dir, run again -> **podman recreates it + re-pulls**,
   run succeeds.
2. Delete the whole parent (storage AND runroot), run again -> **podman recreates
   the full tree + re-pulls**, run still succeeds.

=> The graphroot is **SELF-HEALING**. netcage needs ZERO rebuild logic: it just
keeps passing `--root <path>`; if the path is missing podman makes it and
re-pulls on demand. A `/var/tmp` wipe therefore costs only a re-pull on the next
run, never a failure.

Two design notes fell out of the probes:

- **Split graphroot from runroot.** `--root` (persistent: images/containers) goes
  on `/var/tmp` (survive reboot). `--runroot` (transient locks/pipes) must stay
  on `$XDG_RUNTIME_DIR` / podman's default `/run`, NOT co-located under the same
  `/var/tmp` dir. Co-locating them and wiping both produced
  `acquiring lock ... file exists` refresh errors (the run still succeeded, but
  it is noise from tearing out live lock state). So: set `--root` only; leave
  `--runroot` default.
- **Rootless graphroot cannot be `rm -rf`'d by the user.** The overlay `diff/`
  tree is owned by id-mapped subuids (rootless userns), so a plain `rm -rf`
  hits permission-denied. A reboot/tmpfiles wipe works (runs as root), but if
  netcage ever tells a user "delete this dir to reset storage" it MUST say
  `podman unshare rm -rf <dir>` or `podman system reset`, never `rm -rf`
  (or provide a helper that shells that). Worth a doc line + possibly a
  `netcage`-side reset convenience.

Provenance: live probes on this host 2026-07-04, throwaway `--root`/`--runroot`
under `/tmp`, cleaned with `podman system reset --force` + `podman unshare rm
-rf`; verified zero leftover probe dirs after. Host storage untouched.

## Update 2026-07-04 - Leak 2 FINAL (minimal): /var/tmp == today's storage minus the username; no cleanup

Clarifying the "rebuild" wording and closing the ephemeral-storage tangent.

**"Podman rebuilds it" meant re-INITIALISE + re-pull-on-demand, NOT restore.**
When the graphroot is missing, podman re-creates EMPTY storage and re-downloads
whatever IMAGE the current run needs. It does NOT bring back prior contents:
images are recoverable (they live in a registry), but KEPT CONTAINERS (ADR-0009)
are NOT (nothing to re-pull them from). So a wipe is harmless for the image
cache, DESTRUCTIVE for kept runs. That is why auto-delete-on-exit cannot be the
default, and the whole ephemeral-storage / "delete on leaving the machine" idea
is DROPPED (it would silently destroy the kept runs `/var/tmp` was chosen to
preserve).

**The correct mental model (maintainer, agreed):** `--root /var/tmp/<neutral>`
behaves EXACTLY like today's `~/.local/share/containers/storage`: persistent,
survives reboots + between runs, holds image cache + kept containers, accumulates
until cleared, self-heals if missing. The ONLY thing that changes is the PATH no
longer contains the username, so `/proc/self/mountinfo` stops leaking it. Nothing
else about storage semantics changes.

Therefore **no auto-cleanup** (netcage doesn't auto-delete the home-folder
storage today; it shouldn't auto-delete `/var/tmp` storage either, same
lifecycle, same non-behaviour).

### Leak 2, minimal final form

- Point podman's graphroot at a username-free path under `/var/tmp` (`--root`);
  leave `--runroot` at its default.
- User `-v` volumes: DOC guidance (mount from outside `$HOME` to keep the
  username out of that source path).
- **No** mountinfo masking, **no** `setup` verb, **no** provisioning helper,
  **no** auto-cleanup.
- ONE doc line on manual clearing: use
  `podman --root /var/tmp/<netcage-storage> system reset --force` (NOT `rm -rf`,
  which fails on the id-mapped overlay `diff/` tree). Doc only, no code.

## Update 2026-07-04 - Leak 5 INVESTIGATED + FIX PROVEN: pasta copies the host NIC NAME (not MAC); rename with `-I`

Investigated the NIC leak end-to-end with live probes (throwaway `--root`, no
residue). Result: root cause pinned, fix proven, egress unaffected.

### What actually leaks (the precise mechanism)

The host's default-route NIC here is `enxc8a362ba9779` - systemd predictable
naming `enx<MAC>`, i.e. the NAME literally encodes the host MAC `c8:a3:62:ba:97:79`
(a USB ethernet adapter).

Probe (podman pasta sidecar + a tool joined via `--network container:`, exactly
netcage's topology): the tool netns shows `/sys/class/net` = `{lo, enxc8a362ba9779}`.
So the tool DOES see the host NIC NAME. BUT the interface's actual MAC inside the
netns is a pasta-SYNTHESISED `d6:02:1b:ea:d8:6c` (varies per run), NOT the host's
real `c8:a3:62:ba:97:79`.

**So the leak is the NAME, not the MAC.** pasta creates its own interface with a
fake MAC but COPIES the host default-route interface's NAME. When that host name
is `enx<MAC>` (systemd's default for a NIC with no other predictable id, common
for USB NICs), the name re-exposes the host MAC even though the live MAC is fake.
Confirmed as pasta's documented default: `pasta --help` shows
`-I, --ns-ifname NAME  default: same interface name as external one`.

### The fix (PROVEN)

pasta's `-I/--ns-ifname` sets the in-netns interface name. netcage already
composes pasta opts through podman as `--network pasta:<opt>,<opt>` (see
`SidecarRunArgs`: `network = "pasta"` or `"pasta:--map-host-loopback,"+addr`).
Adding `-I,netcage0` gives `--network pasta:-I,netcage0[,--map-host-loopback,...]`.

Probed with `--network 'pasta:-I,netcage0'`:
- tool netns `/sys/class/net` = `{lo, netcage0}` - the `enx...` name is GONE.
- host NIC name/MAC no longer appears anywhere in the tool netns.
- egress unaffected: default route is `default via 192.168.1.1 dev netcage0`,
  routing works. Renaming the interface does NOT break pasta connectivity.

### Verdict + where it lands

FIX, small and in-scope. Add a fixed `-I,<stable-name>` (e.g. `netcage0`) to the
pasta network arg netcage builds in `internal/jail/jail.go` `SidecarRunArgs`
(compose it alongside the existing `--map-host-loopback` opt). One-token change to
the arg builder; the wiring test asserts the token is present. No ADR needed (it
does not change the egress model; the route out is still the TUN, this only
re-labels the pasta interface).

### Leak 1 fix de-risked (probed 2026-07-04)

Under the real `--network container:<sidecar>` topology, probed: a `/etc/hosts`
`:ro` bind mount IS accepted (tool sees `127.0.0.1 localhost` only), and
`--hostname netcage` IS accepted (tool `hostname` returns `netcage`). Neither is
refused the way `--dns` is under `--network container:`. So the Leak 1 fix has no
refusal risk to design around. Throwaway `--root`, cleaned after, no residue.

### Residual NOT fixed by this (separate, note only)

The route dump still showed `192.168.1.1` / `192.168.1.0/24` (host LAN
gateway/subnet) on the pasta interface. That is LAN-TOPOLOGY exposure, a DIFFERENT
residual from NIC identity, and in the REAL netcage sidecar the tool's route is
the TUN (`CLONE_MAIN=0` stops the pasta routes cloning into the TUN table), so a
tool reading its default route sees the TUN, not this. Whether the pasta
interface's copied LAN addresses are still readable via `/sys` in the full
tun2socks jail is a smaller follow-up; the NIC-NAME leak (the one the transcript
flagged, and the one that re-exposes the host MAC) is the fixable target and is
now solved. Provenance: live pasta+container probes on this host 2026-07-04,
throwaway `--root`, `system reset` + `unshare rm -rf` after, zero residue.
