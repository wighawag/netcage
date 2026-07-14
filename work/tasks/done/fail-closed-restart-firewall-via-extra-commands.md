---
title: Bake the jail firewall into the sidecar's EXTRA_COMMANDS so it self-heals on every restart (fail-closed on a raw podman start)
slug: fail-closed-restart-firewall-via-extra-commands
spec: podman-fidelity-and-lifecycle
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

DROP-FIRST ordering (spiked - do this): order the baked firewall so its broad
DROPs (all-egress-UDP drop, the RFC1918/link-local drops, the reachback drop)
come BEFORE the narrow trailing ACCEPTs, so a mid-script failure on the one
unguarded path (a raw `podman start` outside netcage, no netcage process to
verify) leaves MORE dropped, not more open. Tested: append-style ordering LEAKED
the LAN gateway on a partial apply; DROP-first DROPPED it. This bounds the
residual with ZERO image change. ORDERING CONSTRAINT (also spiked): the
proxy-port reachback ACCEPT and every split-tunnel direct ACCEPT MUST still
precede the `169.254.0.0/16` link-local drop / the RFC1918 drops respectively,
else the sidecar's own dial to the pasta-mapped proxy (`169.254.1.1:1080`) or an
allowlisted direct is caught by a broad drop (the current `writeSplitTunnelRules`
already emits direct-ACCEPTs before the RFC1918 drops; keep that, and add the
same for the proxy-port ACCEPT vs the link-local drop). Full-success happy path
is unaffected (tested end-to-end).

We do NOT build/wrap a custom sidecar image to make the raw bypass
guaranteed-closed on failure - that is DECLINED in ADR-0007 (it destroys the
registry-verifiable digest pin, adds a build/publish pipeline, and fights
ADR-0006). DROP-first + netcage's verification is the accepted approach; the
supported reuse path is `netcage start` (which verifies), and a raw bypass is
out-of-contract.

Add a leak assertion to `verify` that proves the raw-bypass path is fail-closed:
after a non-ephemeral run leaves a tool container, a raw `podman start <tool>`
(NOT via netcage) must NOT reach a LAN/RFC1918 host and must NOT egress DNS
(names must not resolve), while public TCP by-IP still exits via the proxy.

This REFINES ADR-0006 (the sidecar still owns its firewall; it now owns it via a
create-time env instead of a runtime exec, so it survives restart). ADR context,
as of tasking:

- **ADR-0007 (`no-custom-sidecar-image-keep-the-upstream-digest-pin`) ALREADY
  EXISTS** in `docs/adr/`. It records the DECLINE decision (we do NOT rebuild the
  sidecar image) and names DROP-first + netcage verification as the accepted
  approach. Do NOT rewrite it; align your implementation with it.
- **You MUST WRITE a NEW ADR** for the fail-closed-on-RESTART MECHANISM itself
  (the durable WHY, refining ADR-0006): the firewall moves from a runtime `podman
  exec` into the sidecar's create-time `EXTRA_COMMANDS` so it survives podman's
  dependency auto-revive; `EXTRA_COMMANDS` cannot fail-close the sidecar, so the
  fail-loud guarantee comes from netcage's post-(re)start firewall VERIFICATION;
  the DNS forwarder stays a separate process (a raw bypass leaves DNS dead =
  fail-closed). This is a distinct, hard-to-reverse security decision and meets
  the ADR gate. (ADR-0007 references this mechanism but is scoped to the
  image-rebuild decline; the mechanism deserves its own ADR.)

## Acceptance criteria

- [ ] The firewall is applied via the sidecar's `EXTRA_COMMANDS` env (set in the
      sidecar run args), NOT a post-start `podman exec`; its rule set is today's
      (UDP drop, loopback-UDP accept, reachback narrowing, RFC1918 drops,
      split-tunnel ACCEPTs) re-ordered DROP-FIRST (broad DROPs before the narrow
      trailing ACCEPTs), with the proxy-port and split-tunnel ACCEPTs still
      before their corresponding broad drops.
- [ ] A unit test asserts the DROP-first ORDER of the generated firewall script
      (the broad drops precede the trailing narrow accepts; the proxy-port /
      direct accepts precede the link-local / RFC1918 drops), so the ordering
      that bounds the partial-apply residual cannot silently regress.
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
- [ ] A NEW ADR in `docs/adr/` records the fail-closed-on-RESTART MECHANISM
      (firewall via `EXTRA_COMMANDS` + netcage verification + DNS-forwarder-
      stays-separate) and that it refines ADR-0006. (ADR-0007, the
      decline-custom-image decision, already exists - do not duplicate it.)
- [ ] Tests mirror the repo's style: unit tests for the sidecar-run-args wiring
      (the `EXTRA_COMMANDS` value is built without executing podman, like the
      existing `SidecarRunArgs`/`firewallScript` tests), and a podman-gated
      integration test (build tag `integration`) for the raw-bypass leak
      assertion.
- [ ] **Shared-write isolation (podman is host-global state):** the raw-bypass
      integration test creates containers OUTSIDE `jail.Run` (a raw `podman start`
      does NOT run the deferred Teardown), so it MUST use unique run-id container
      names AND guarantee cleanup via `t.Cleanup`/`podman rm -f --depend` of the
      pair even on failure, so a failing test cannot orphan containers on the
      host or collide with a concurrent run. Assert no `netcage-run-*` residue
      from this test remains after it completes.

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
> RECORD the durable decision as a NEW ADR in `docs/adr/` (hard-to-reverse,
> surprising-without-context, real trade-off -> meets the ADR gate): the firewall
> now lives in the sidecar's create-time `EXTRA_COMMANDS` so it survives podman's
> dependency auto-revive, with netcage's post-start VERIFICATION as the fail-loud
> layer, refining ADR-0006. NOTE: ADR-0007 (decline a custom sidecar image)
> ALREADY EXISTS and is a DIFFERENT decision - do not rewrite or duplicate it;
> this new ADR is the restart-MECHANISM one. Note any in-scope choice you make
> (e.g. how you assert rule-count stability) in the done record.
>
> Done = the firewall is baked into `EXTRA_COMMANDS`, `verify` is green on the
> full jail, the new raw-bypass leak assertion passes (LAN dropped + DNS dead on a
> raw `podman start`), rules don't accumulate across restarts, and the ADR is
> written.
