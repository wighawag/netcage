---
title: Give the jail its own clock/boot-time via a time namespace (hide the host uptime/btime fingerprint)
slug: time-namespace-clock-boot-fingerprint
type: idea
status: incubating
created: 2026-07-04
---

# Time namespace for the jail (hide the host clock/boot-time fingerprint)

Proposed idea, captured 2026-07-04 during the `jail-host-identity-hardening` work. NOT tasked; recorded so it does not evaporate. It is the "real fix" for a residual ADR-0013 deliberately left out of scope.

## The residual this addresses

A tool jailed by netcage reads the HOST's clock/boot-time family from the shared-kernel `/proc`, live-probed (see `work/notes/observations/jail-leaks-host-identity-metadata-not-network.md`, "Leak 6"):

- `/proc/uptime` == host uptime,
- `/proc/stat` `btime` == host boot epoch (byte-identical; the strongest correlator, a semi-stable machine id that also ties this container to a specific host boot),
- `/proc/loadavg` == host activity.

ADR-0013 records this as an ACCEPTED residual (same shared-kernel `/proc` class as the hardware/kernel fingerprint) and explicitly REJECTS a lone per-field mask (binding a fake `/proc/uptime`): it is brittle, a static fake is itself a tell, and it would hide `uptime` while `btime` still leaks (looks handled, isn't). This idea is the coherent alternative.

## The idea

Run the jail in its own **time namespace** (`CLONE_NEWTIME`) so the container gets its OWN boot-time/monotonic origin: `/proc/uptime` starts near zero at jail start and `btime` reflects the namespace's boot, not the host's. This closes the uptime + boot-epoch correlator at the kernel level, consistently across the family (no fake-value inconsistency), without brittle per-file `/proc` binds.

Open questions to resolve before this is buildable (hence `incubating`, not a task):

1. **Does rootless podman + pasta expose a time-namespace knob?** Podman has `--timezone` (unrelated) but a `CLONE_NEWTIME` / boot-time offset control is the question. Check what podman/crun actually support rootless, and whether it composes with the existing `--network container:` shared-netns + `/dev/net/tun` sidecar topology (ADR-0001) without breaking the jail.
2. **Scope: full clock family or just boot-time?** A time namespace virtualises `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME` (hence uptime/btime) but NOT `CLOCK_REALTIME` (wall clock) by default, and does not touch `loadavg` or process-table timings. Decide whether the residual left after a time-namespace (wall clock, loadavg) is acceptable or needs more.
3. **Does it break tools?** A tool that expects a plausible uptime/clock should still work, but verify nothing in the default dev-image path (ADR-0004) or common jailed tools depends on host-consistent timing.
4. **Cost/benefit vs the accepted-residual stance.** ADR-0013 already deems this out of scope for v1; this idea would REVISIT that only if the clock/boot fingerprint proves to matter for a real threat.

## Relation to the bigger picture

This is one instance of the general "shared-kernel `/proc` leaks the host" problem. The other instance (host hardware + kernel version) is genuinely unfixable without a sandbox kernel (gVisor/Kata). The time-namespace path is attractive precisely because it is a NARROW, kernel-supported fix for the clock/boot slice specifically, not a whole-runtime swap. If a sandbox-kernel redirector is ever seriously considered, it would subsume this.

Provenance for the leak facts: live probes on this host 2026-07-04 (throwaway `--root`, zero residue), recorded in the observation above.
