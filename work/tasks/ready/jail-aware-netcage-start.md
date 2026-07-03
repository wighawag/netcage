---
title: Jail-aware `netcage start` - revive the sidecar (firewall self-heals), re-exec the DNS forwarder, re-enter the kept container; refuse on a changed jail config
slug: jail-aware-netcage-start
prd: podman-fidelity-and-lifecycle
blockedBy: [fail-closed-restart-firewall-via-extra-commands, teardown-split-honour-rm, pass-through-verbs-and-labels]
covers: [7, 9]
---

## What to build

Add `netcage start <name>`, the jail-aware exception to the pass-through verbs:
it resumes a KEPT, netcage-managed tool container with its full jail restored,
so a named reusable jailed container is a durable environment (the primitive a
downstream "machine" is built from).

Sequence (proven sufficient by spiking - see the finding):

1. Resolve `<name>` to a netcage-managed tool container (by label); refuse a
   non-netcage or unknown container with a clear message.
2. RECONCILE the requested jail config against the container's baked config:
   - **Same `--proxy` / `--allow-direct` as the container was created with ->
     REVIVE**: bring the (stopped) sidecar up. Podman also auto-revives it as the
     tool's `--network container:` dependency, and the baked `EXTRA_COMMANDS`
     firewall re-applies automatically (proven idempotent across restarts, no
     rule accumulation). VERIFY the firewall is fully applied after the sidecar
     is up (the same `iptables -S` probe the run path uses - `netcage start` is a
     netcage-driven path, so it gets the fail-loud layer too; abort loudly if
     partial). Then re-exec the `netcage-dns` forwarder INTO the sidecar (it is a
     separate process, NOT part of `EXTRA_COMMANDS`, so a restart leaves it dead
     until this step restores it), then start/attach the tool.
   - **Different `--proxy` / `--allow-direct` -> REFUSE** with a clear message
     ("this container was jailed with a different proxy/allowlist; remove it and
     run again, or start it with the same jail config"). Do NOT silently revive a
     stale jail, and do NOT silently rebuild-and-lose the container's state. (A
     future explicit rebuild flag can be a follow-up; the safe default is refuse.)
3. On exit, the same teardown split applies (kept -> leave both stopped
   fail-closed; ephemeral -> remove both).

The forced-egress invariant is paramount and PROVEN restart-safe: the revived
jail is fail-closed (firewall self-heals via `EXTRA_COMMANDS`; a dead-proxy
revive is fail-closed; public egress stays proxied). `netcage start` is the path
that ALSO restores DNS; a raw `podman start` (no DNS restore) stays fail-closed
(names don't resolve) - never a working un-jailed network.

## Acceptance criteria

- [ ] `netcage start <name>` on a kept netcage tool container REVIVES the sidecar,
      re-execs the DNS forwarder, and re-enters the tool with its state intact
      (a file written in a prior run is still there).
- [ ] `netcage start` VERIFIES the firewall after reviving the sidecar (same
      `iptables -S` probe as the run path) and aborts loudly if partial - the
      fail-loud layer applies to `start`, not just `run`.
- [ ] A verify-style leak assertion holds on the RESTARTED container: exit-IP is
      the proxy's, DNS resolves proxy-side, a LAN/RFC1918 host is DROPPED, and it
      is fail-closed on proxy-kill - i.e. `start` restores a full, leak-tight jail.
- [ ] `netcage start` with a DIFFERENT `--proxy`/`--allow-direct` than the
      container was created with is REFUSED with a clear message; it never revives
      a stale jail and never silently discards container state.
- [ ] `netcage start` on a non-netcage or unknown container is refused clearly.
- [ ] The forced-egress invariant holds throughout: the tool never runs before
      its jail is restored (firewall present + DNS forwarder up); no path yields a
      working un-jailed network.
- [ ] Tests: unit tests for the config-reconcile decision (same -> revive,
      different -> refuse) and the start sequence's argv construction (sidecar
      revive + DNS re-exec + tool start), mirroring the existing arg-builder
      tests; a podman-gated (`integration`) test that a kept container survives a
      run -> `netcage start` cycle with state intact AND passes the restarted-jail
      leak assertion.

## Blocked by

- `fail-closed-restart-firewall-via-extra-commands` - revive relies on the baked
  firewall self-healing on restart.
- `teardown-split-honour-rm` - there is no kept container to start until runs can
  leave one behind.
- `pass-through-verbs-and-labels` - `start` resolves the container by the
  `netcage.managed` label and extends the same verb dispatch (serialised to avoid
  a CLI-dispatch merge conflict).

## Prompt

> Goal: implement `netcage start <name>`, the jail-aware resume verb. It brings a
> kept netcage tool container back up WITH its full forced-egress jail restored,
> so a named reusable jailed container is a durable environment. Reviving the
> EXISTING sidecar is sufficient (proven); a fresh sidecar is only needed when the
> jail config changed, and the safe default there is to REFUSE.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm the three blocking tasks landed - the firewall is baked into
> the sidecar's `EXTRA_COMMANDS` (self-heals on restart), a non-`--rm` run leaves
> a stopped tool+sidecar pair, and netcage-managed containers carry a
> `netcage.managed` label + the verb dispatch exists. If any is missing, do NOT
> build on the stale premise; route to needs-attention.
>
> Domain + PROVEN facts (READ THESE FIRST):
> `work/notes/findings/netcage-start-sidecar-revive-is-sufficient.md` (revive is
> sufficient and idempotent across cycles; fail-closed-on-proxy-kill survives
> revive; the ONE wrong case is a changed proxy/allowlist -> refuse),
> `sidecar-firewall-via-extra-commands-survives-restart.md` (the firewall
> re-applies on every start; the DNS forwarder is a SEPARATE process that
> `netcage start` must re-exec), and
> `podman-network-container-dependency-lifecycle.md` (podman auto-revives the
> sidecar dependency; you cannot keep the tool while removing the sidecar).
> ADR-0006 (sidecar owns firewall + DNS, pure podman client) plus the new
> fail-closed-on-restart ADR from the hardening task constrain this.
>
> Where to look / seams: the CLI subcommand dispatch (add `start`, guard on the
> `netcage.managed` label); the jail package for the sidecar-revive + DNS
> forwarder start (reuse the existing DNS-forwarder exec used at run time) + tool
> start/attach; a config-reconcile helper that compares the REQUESTED proxy/
> allowlist against the container's baked config (inspect the sidecar's env /
> labels) and decides revive-vs-refuse. Test the reconcile decision and the
> built podman argv without running podman (mirror the existing wiring tests);
> add one podman-gated integration test for the run -> start -> state-intact +
> leak-tight cycle.
>
> Preserve the forced-egress invariant: the tool must not start until the jail is
> restored (firewall present via the baked `EXTRA_COMMANDS`, DNS forwarder
> re-exec'd); a changed jail config is REFUSED, never silently revived stale; a
> restarted container must pass the same leak assertions as a fresh run.
>
> RECORD in-scope choices (how you read the baked config to compare, the exact
> refuse message, whether `start` attaches interactively by default) in the done
> record / an ADR if it meets the gate. Done = `netcage start` resumes a kept
> jailed container with state intact and a leak-tight jail, refuses a changed
> config, and the tests prove the resume cycle + the restarted-jail leak
> assertion.
