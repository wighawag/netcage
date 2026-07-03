---
title: `netcage start` can REVIVE the existing sidecar (stop->start cleanly re-establishes the whole jail); a fresh sidecar is needed ONLY when the jail config changed
slug: netcage-start-sidecar-revive-is-sufficient
source: "spiked live against podman 5.4.2 + the pinned tun2socks sidecar + a real host-loopback socks5 proxy (127.0.0.1:1080), 2026-07-03; commands + outputs in body"
---

## Question spiked

For `netcage start <tool>`: is REVIVING the existing sidecar (a plain `podman
start` of the stopped sidecar) sufficient to re-establish the full jail, or must
`netcage start` tear down and build a FRESH sidecar each time?

## Result: revive is sufficient (when the config is unchanged)

With the firewall baked into `EXTRA_COMMANDS` (see finding
sidecar-firewall-via-extra-commands-survives-restart), a plain `podman start` of
the stopped sidecar cleanly re-establishes EVERYTHING:

- **Across 3 stop->start cycles, every cycle:** public egress = the proxy exit IP
  (188.240.57.227, NOT the host's 147.147.37.112), LAN 192.168.1.1:53 = DROPPED.
  The TUN, the pasta host-loopback mapping, the routing table, and the firewall
  all re-establish on restart. Nothing failed to survive.
- **No iptables rule ACCUMULATION.** After the cycles the sidecar's OUTPUT chain
  has EXACTLY the fixed 8-rule set, not a growing pile: the netns is fresh on each
  `podman start`, so `EXTRA_COMMANDS` applies to a clean table every time
  (idempotent by construction).
- **Fail-closed-on-proxy-kill survives revive.** A revived sidecar pointed at a
  DEAD proxy port yields FAILCLOSED public egress + LAN DROPPED. The invariant
  holds through a restart.

So `netcage start <tool>` = (1) ensure its sidecar is up (`podman start` the
sidecar - a revive, or podman's own dependency auto-revive), (2) re-exec the
`netcage-dns` forwarder into it (the ONE piece not baked into `EXTRA_COMMANDS`,
so it must be restarted explicitly), (3) start/attach the tool. No fresh sidecar
is required for the steady-state resume.

## The ONE case where revive is WRONG: the jail config changed

The sidecar's `PROXY=` and `EXTRA_COMMANDS=` (the firewall, including the
split-tunnel allowlist ACCEPTs) are baked at CREATE time. A plain revive reuses
those ORIGINAL values. So if the next `netcage start` is invoked with a
DIFFERENT `--proxy` or `--allow-direct` than the container was created with, a
revive would silently run the OLD jail config (wrong proxy / stale allowlist).

Decision for the build (no open question): `netcage start` reconciles the
REQUESTED jail config against the container's baked config:

- **Same config -> REVIVE** the existing sidecar (the fast steady-state path).
- **Changed config (different `--proxy` / `--allow-direct`) -> REBUILD**: remove
  the old sidecar+tool via `podman rm -f --depend` (the cascade is fine here - we
  are intentionally replacing) and re-create with the new config. Recreating the
  tool loses in-container state, so surface this loudly (or refuse and tell the
  user to `rm` first) rather than silently discarding state. Simplest safe
  default: if the requested proxy/allowlist differs from the baked one, REFUSE
  with a clear message ("this container was jailed with a different proxy/
  allowlist; remove it and run again, or start it with the same jail config")
  rather than silently rebuild-and-lose-state. The exact reconcile-vs-refuse
  policy is an in-scope build decision to record, not an open blocker.

## Bottom line

Revive-based `netcage start` is PROVEN sufficient and idempotent for the
steady-state resume. The recreate path is needed ONLY on a jail-config change,
and the safe default there is to REFUSE (state-preserving) rather than silently
rebuild. No `needsAnswers` required.
