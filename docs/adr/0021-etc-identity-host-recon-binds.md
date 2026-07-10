# netcage synthesizes /etc-identity binds (/etc/passwd, /etc/group, /etc/machine-id) to close two more cheap, jail-owned host-recon leaks; still an egress jail, no machine concept

**Status:** accepted (a direct, in-character extension of ADR-0013's host-identity hardening; builds on ADR-0001/0002 rootless design, ADR-0006 Runner seam, ADR-0009 kept pair, ADR-0011 revive)

## Context

ADR-0013 stated netcage's scope: the guarantee is forced NETWORK egress (proven by `verify`), and ON TOP of that netcage closes the host-identity leaks that are cheap AND jail-owned, stating the rest as an explicit non-goal. It closed the host-machine-name leak by mounting a synthesized localhost-only `/etc/hosts` `:ro` and setting a fixed neutral `--hostname`, relocated the graphroot off the username path, and renamed the pasta interface.

A live anon session (recorded in `work/notes/observations/jail-leaks-host-identity-metadata-not-network.md`, and named in anonctl's README "NOT defended" section) showed the same class still leaks two sharp signals ADR-0013 did not close, both readable by a jailed tool with ZERO network access from ordinary unprivileged files:

- **`/etc/passwd` (world-readable).** The host's `/etc/passwd` exposes EVERY host account's login name AND its GECOS real-name field. This is the sharpest of the remaining leaks: a login name plus a real name is directly deanonymizing, and it is readable without any privilege. A stock base image ships its OWN `/etc/passwd`, so the leak occurs when the host's is visible to the tool; the fix is to always present a synthetic minimal one.
- **`/etc/machine-id`.** A stable host correlator (machine-id-grade, like the `btime` boot-epoch ADR-0013 accepts as residual). It ties a jailed tool's observations back to a specific host across runs.

These are the same shape as the ADR-0013 `/etc/hosts` fix: a cheap, jail-owned recon leak closed by a container-create-time `:ro` bind of a synthesized neutral file. They are exactly the "jail-intrinsic `/etc`-identity binds" the machines scope-fork note (`work/notes/ideas/netcage-machines-scope-fork.md`) assigns to netcage.

## Decision

netcage's guarantee remains **network egress only** (unchanged). On top of it, close the two leaks above with container-create-time `:ro` binds on the tool container, mirroring the existing `/etc/hosts` pattern EXACTLY (synthesize a neutral per-run temp fixture, store its stable run-attributable path on the jail config, bind it `:ro`, sweep it ephemeral-only in teardown, re-materialise it on `netcage start` revive). Concretely:

- **`/etc/passwd` + `/etc/group`:** HIDDEN. Mount a synthesized minimal `/etc/passwd` `:ro` containing ONLY a generic non-identifying user (`machine:x:1000:1000::/home/machine:/bin/sh`), `root`, and the conventional service-account minimum (`nobody`). It contains NONE of the host's real accounts, no real login names, and no GECOS real names. `/etc/group` is mounted the same way with a matching minimal set (`root`/`machine`/`nogroup`) so a passwd carrying a gid has a coherent group file. **`/etc/shadow` is DELIBERATELY NOT synthesized:** its ABSENCE is safer than a fake (a fabricated shadow is itself a tell, and there is nothing to authenticate against in a jail).
- **`/etc/machine-id`:** HIDDEN. Mount a per-run RANDOM 32-hex-char id `:ro` (see the decision below).

Each bind is EGRESS-NEUTRAL: it carries NO name resolution and NO hostname->IP pin, so it is inert to egress and reintroduces nothing `--add-host`/`--dns`-like. Like the `/etc/hosts` bind, these are ordinary `:ro` binds ACCEPTED under the `--network container:` shared-netns topology (ADR-0013 live-verified `/etc/hosts:ro` and `--hostname` are accepted there, unlike `--dns`). They do not touch the firewall, the TUN path, or the netns, so the forced-egress three-point leak-test is untouched.

Unlike `--hostname` (a netcage neutral DEFAULT that a vetted user `--hostname` pass-through can override, ADR-0010), these binds have **no user-facing override**: a jailed tool has no legitimate need to inject the host's real accounts or machine-id, so the synthesized fixtures are unconditional (no vetted pass-through flag targets `/etc/passwd`/`/etc/group`/`/etc/machine-id`, and none is added). They are emitted right after the `/etc/hosts` bind in `ToolRunArgs`, before the pass-through flags, keeping the same arg ordering.

### machine-id: per-run RANDOM id, not empty

The choice was between an EMPTY machine-id (systemd "first boot" semantics, tolerated by some tools) and a PER-RUN RANDOM 32-hex-char id. **Chosen: per-run random id.** It is non-empty (so tools that require a value work), stable within one run (so a tool that reads it twice sees a consistent value), and unlinkable to the host's real machine-id (a fresh 128-bit random value per run). An empty machine-id is rejected because it is a weaker compatibility bet (not all tools tolerate the first-boot empty case) and carries no advantage here. The id is minted once per run; on a `netcage start` revive of a KEPT run the EXISTING run-scoped id is PRESERVED (only a missing fixture, e.g. after a temp-dir sweep or a cross-host revive, is re-minted), so a kept machine's machine-id does not change under a tool across logins.

### Why only `/etc/machine-id`, not `/var/lib/dbus/machine-id`

`/var/lib/dbus/machine-id` is conventionally a SYMLINK to `/etc/machine-id`, so on such an image a tool reading the dbus path already resolves to the synthesized value. Binding it unconditionally would BREAK on minimal images that lack the `/var/lib/dbus/` directory (e.g. alpine, which the `verify` leak-test itself uses): podman cannot bind a file into a non-existent parent, which would fail the container create and could weaken the acceptance floor. So netcage binds only `/etc/machine-id`. Residual (accepted): a tool reading a NON-symlinked `/var/lib/dbus/machine-id` on an image that carries a host value there is not covered.

## This is jail-intrinsic host-recon hardening, NOT a machine concept

These binds close a jail-owned recon leak; they add NO machine/account/home/lifecycle concept. That concept lives deliberately in the sibling tools (anonbox/anonseed/anoncore) per `work/notes/ideas/netcage-machines-scope-fork.md`: the partition rule there assigns to netcage ONLY the jail-intrinsic `/etc`-identity binds (a container-create-time bind on the jailed container netcage already owns, same seam as ADR-0013's `/etc/hosts`), and assigns the account/persistence/machine-lifecycle to the sibling tools that DRIVE netcage. netcage stays an egress jail; every consumer (a bare `netcage run`, anon-pi, a future anonbox machine) gets these binds for free and proven by `verify`. netcage does NOT become a machine runtime.

## The residual this does NOT close (unchanged from ADR-0013, plus one new note)

This closes exactly `/etc/passwd` + `/etc/group` + `/etc/machine-id`. It does NOT touch the shared-kernel residual ADR-0013 already accepts, and this ADR does not change that scope:

- **Kernel / hardware / uname** (`/proc/cpuinfo`, `/proc/meminfo`, `/proc/version`, `uname`): OPEN. The kernel is shared; a container is not a VM. Only a sandbox kernel (gVisor/Kata) or a real VM closes it.
- **Host clock / boot-time** (`/proc/uptime`, `/proc/stat` `btime`, `/proc/loadavg`): OPEN. The same shared-kernel `/proc` class; a real fix is a TIME NAMESPACE (`CLONE_NEWTIME`, a separate deferred spike, `work/notes/ideas/time-namespace-clock-boot-fingerprint.md`), explicitly NOT done here.
- **Timing signals** generally (process start times, activity correlation): OPEN, same class.
- **LAN topology** (the pasta interface's copied host LAN addresses/routes, whether readable via `/sys`): SEEN and DEFERRED as a separate follow-up (as ADR-0013 flagged); NOT closed here.
- **`/var/lib/dbus/machine-id`** on an image where it is a NON-symlinked host-value file: OPEN (see the bind decision above).

No PID/mount/user namespace change is added (podman already provides those). No time namespace is added. No account/home/machine concept is added.

## Consequences

- `verify` stays the acceptance floor and stays unweakened: the three-point leak-test (exit IP is the proxy's; a unique hostname resolves proxy-side; proxy-killed fails closed) is green with the new binds, plus the full Tails-catalogue assertions. A wiring test asserts the tool-run args include the three new `:ro` binds and that they are egress-neutral (no `--add-host`/`--dns`, topology unchanged), mirroring how the host-identity work proved the `/etc/hosts` mount was inert.
- The three new per-run fixtures are swept on the ephemeral path (Teardown and `netcage rm`) and left durable on the kept path (so a `netcage start` revive can re-mount them), exactly like the `/etc/hosts` and resolv.conf fixtures.
- The scope line holds: netcage's guarantee is network egress plus a stated, proven set of host-recon hardenings (now `/etc/hosts` + `--hostname` + graphroot + NIC name + `/etc/passwd`/`/etc/group` + `/etc/machine-id`); future changes must not silently erode the closed leaks nor over-claim beyond this set.
