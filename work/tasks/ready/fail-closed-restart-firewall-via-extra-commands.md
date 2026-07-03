---
title: Bake the jail firewall into the sidecar's EXTRA_COMMANDS so it self-heals on every restart (fail-closed on a raw podman start)
slug: fail-closed-restart-firewall-via-extra-commands
prd: podman-fidelity-and-lifecycle
blockedBy: []
covers: [3, 8]
---

## What to build

Move the jail firewall from a runtime `podman exec` (applied once, after the
sidecar starts) to the sidecar's `EXTRA_COMMANDS` container env, set at sidecar
CREATE time. The pinned tun2socks image's entrypoint runs `EXTRA_COMMANDS` on
EVERY start (before it execs tun2socks), so the firewall then re-applies
automatically whenever the sidecar (re)starts, including when podman AUTO-REVIVES
a stopped sidecar as a `--network container:` dependency of a raw `podman start
<tool>`. This closes a proven leak: today the firewall is exec-applied and is
LOST on a restart, so a leftover tool started outside netcage revives a sidecar
that routes public TCP through the proxy but leaves LAN/RFC1918 + UDP reachable
(a leak).

The firewall script (UDP drop + loopback-UDP accept + host-loopback reachback
narrowing + RFC1918 drops + the split-tunnel ACCEPT rules) is unchanged in
CONTENT; only WHERE it is applied moves (runtime exec -> create-time env).

CRITICAL (spiked, do NOT skip): `EXTRA_COMMANDS` CANNOT fail-close the sidecar.
The image entrypoint runs `sh -c "$EXTRA_COMMANDS"` as a child subshell and does
NOT check its exit before `exec tun2socks`, so a failing/half-applied firewall
leaves tun2socks running with a partial firewall (a LEAK), and neither `set -e`
nor `kill 1` from inside `EXTRA_COMMANDS` can abort it (all TESTED - see the
finding). So use a TWO-LAYER guard:

1. `EXTRA_COMMANDS` self-heals the firewall on every (re)start (the proven
   happy-path mechanism that closes the raw-restart LAN/UDP leak).
2. netcage's OWN run path VERIFIES the firewall AFTER the sidecar is up (a
   `podman exec ... iptables -S` probe asserting the exact expected rule set) and
   ABORTS the jail LOUDLY (fail-closed, tear down) if the rules are missing or
   partial. This preserves the fail-loud guarantee the current `podman exec ...
   'set -e; ...'` gets from its Go-side exit-code check. (`netcage start` runs the
   same verification - see the start task.)

Order the baked firewall so its first effective actions are the broadest safe
DROPs (still letting tun2socks reach the proxy + loopback), so a later-rule
failure leaves MORE dropped, not more open, bounding the residual on the one
unguarded path (a raw `podman start` outside netcage, which has no netcage
process to verify - documented as out-of-contract; the supported reuse path is
`netcage start`, which verifies).

Add a leak assertion to `verify` that proves the raw-bypass path is fail-closed:
after a non-ephemeral run leaves a tool container, a raw `podman start <tool>`
(NOT via netcage) must NOT reach a LAN/RFC1918 host and must NOT egress DNS
(names must not resolve), while public TCP by-IP still exits via the proxy.

This REFINES ADR-0006 (the sidecar still owns its firewall; it now owns it via a
create-time env instead of a runtime exec, so it survives restart). Record the
decision as a new ADR in `docs/adr/` (the durable WHY: fail-closed must survive
podman's dependency auto-revive; `EXTRA_COMMANDS` is the native, image-pin-safe
mechanism; the DNS forwarder stays a separate process so a raw bypass leaves DNS
dead = fail-closed).

## Acceptance criteria

- [ ] The firewall is applied via the sidecar's `EXTRA_COMMANDS` env (set in the
      sidecar run args), NOT a post-start `podman exec`; its content is the same
      rule set as today (UDP drop, loopback-UDP accept, reachback narrowing,
      RFC1918 drops, split-tunnel ACCEPTs).
- [ ] netcage's run path VERIFIES the firewall after the sidecar is up (an
      `iptables -S` probe of the exact expected rule set) and aborts the jail
      LOUDLY (fail-closed, teardown) if a rule is missing/partial - a
      deliberately-broken firewall must FAIL the run, never run a half-applied
      firewall. (This is the fail-loud layer; `EXTRA_COMMANDS` alone cannot abort
      the sidecar - proven in the finding.)
- [ ] Full netcage `run` still passes the existing leak-test (`verify` green):
      exit-IP is the proxy's, DNS is proxy-side, fail-closed on proxy-kill, and
      the split-tunnel directs (when set) still work.
- [ ] New leak assertion: after a run that LEAVES a tool container, a raw
      `podman start <tool>` outside netcage is FAIL-CLOSED - a LAN/RFC1918 probe
      is DROPPED and a DNS lookup does NOT resolve (public TCP by-IP may still
      exit via the proxy; that is not a leak). Reruns are idempotent (no iptables
      rule accumulation across restarts).
- [ ] Firewall rules do NOT accumulate across repeated sidecar restarts (the
      netns is fresh each start; assert a fixed rule count after N cycles).
- [ ] A new ADR in `docs/adr/` records the fail-closed-on-restart decision and
      that it refines ADR-0006.
- [ ] Tests mirror the repo's style: unit tests for the sidecar-run-args wiring
      (the `EXTRA_COMMANDS` value is built without executing podman, like the
      existing `SidecarRunArgs`/`firewallScript` tests), and a podman-gated
      integration test (build tag `integration`) for the raw-bypass leak
      assertion.

## Blocked by

- None - can start immediately. (This is the security foundation the
  leave-a-container-behind work sits on; it must land first.)

## Prompt

> Goal: make a left-behind netcage jail FAIL-CLOSED even against a raw `podman
> start` outside netcage, by moving the firewall from a runtime `podman exec`
> into the sidecar's `EXTRA_COMMANDS` env so it self-heals on every (re)start.
>
> FIRST, check this task against current reality (it is a launch snapshot and may
> have DRIFTED): confirm the firewall is still applied via `podman exec` inside
> the sidecar (look in the jail package's run orchestration - `applyFirewall`,
> around the sidecar-start/firewall/DNS steps) and that the firewall script is
> still assembled in one place (a `firewallScript` method on the jail Config, plus
> the split-tunnel rule writer). Confirm the sidecar run args are assembled in one
> place (`SidecarRunArgs`) and already pass env vars like `CLONE_MAIN`,
> `TUN_EXCLUDED_ROUTES`, `PROXY`. If any of that landed differently, route to
> needs-attention rather than building on the stale premise.
>
> Domain: netcage forces all container TCP egress through a socks5h proxy,
> fail-closed; a tun2socks "sidecar" owns the netns, and the "tool" container
> joins it via `--network container:<sidecar>`. ADR-0006 says the sidecar owns its
> firewall + DNS forwarder and netcage is a pure podman client (no host nsenter).
> The pinned sidecar image is `docker.io/xjasonlyu/tun2socks@sha256:...` (see
> `docs/redirector-pin.md` and `internal/redirector`); its entrypoint runs
> `EXTRA_COMMANDS` on every start (verified: `run()` does create_tun ->
> create_table -> config_route -> `sh -c "$EXTRA_COMMANDS"` -> exec tun2socks).
>
> The proven mechanism + the exact spike results are in
> `work/notes/findings/sidecar-firewall-via-extra-commands-survives-restart.md`
> and `work/notes/findings/podman-network-container-dependency-lifecycle.md`. READ
> THEM FIRST - they carry the tested facts: the LAN/UDP leak on a raw restart, the
> `EXTRA_COMMANDS`-fixes-it (happy-path) result, the no-rule-accumulation result,
> and the DECISIVE caveat - `EXTRA_COMMANDS` CANNOT fail-close the sidecar (the
> entrypoint does not check its exit; `set -e`/`kill 1` were both spiked and do
> NOT abort tun2socks), so the fail-LOUD guarantee MUST come from netcage's own
> post-start firewall VERIFICATION (the two-layer guard), not from the baked
> script aborting.
>
> Where to look / seams to test at: the sidecar-run-args builder (assert the
> `EXTRA_COMMANDS` value is present and equals the firewall script, without
> running podman); the firewall-script assembler (unchanged content); the DNS
> forwarder start (stays a separate `podman exec -d` process - do NOT bake it into
> `EXTRA_COMMANDS`; a raw bypass leaving DNS dead IS fail-closed). Add the
> raw-bypass leak assertion into `internal/verify` following the existing
> fixture-backed, podman-gated leak-test pattern.
>
> Preserve the forced-egress invariant throughout: the jail is always fail-closed;
> a leftover container never gets a working un-jailed network; the existing
> leak-test stays green.
>
> RECORD the durable decision as an ADR in `docs/adr/` (this is a hard-to-reverse,
> surprising-without-context security decision with a real trade-off -> it meets
> the ADR gate): the firewall now lives in the sidecar's create-time env so it
> survives podman's dependency auto-revive, refining ADR-0006. Note any in-scope
> choice you make (e.g. how you assert rule-count stability) in the done record.
>
> Done = the firewall is baked into `EXTRA_COMMANDS`, `verify` is green on the
> full jail, the new raw-bypass leak assertion passes (LAN dropped + DNS dead on a
> raw `podman start`), rules don't accumulate across restarts, and the ADR is
> written.
