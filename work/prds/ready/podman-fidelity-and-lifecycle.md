---
title: netcage as a fuller podman replacement (lifecycle + fidelity)
slug: podman-fidelity-and-lifecycle
humanOnly: true
needsAnswers: true
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth:
> `docs/adr/` + the code; remaining work: `work/tasks/`.

<!-- open-questions -->
<!-- TRANSIENT — stripped on full resolution. needsAnswers:true while these block tasking. -->

## Open questions

1. **Flag model width + new-flag policy (the key security call).** We KEEP a
   fail-closed allow-list (unknown flag => refuse), because a security tool must
   fail-closed on the unknown: if a future podman adds a network-relevant flag
   not in our deny-set, pass-through would silently leak. So: how WIDE do we make
   the allow-list (which vetted network-irrelevant flags to add: `--memory`,
   `--cpus`, `-l/--label`, `--tmpfs`, `--read-only`, `--hostname`, `--pull`,
   `--platform`, `--env-file`, `--add-host`(?), `--ulimit`, `--shm-size`, ...),
   and what is the vetting checklist that decides a flag is network/isolation-
   IRRELEVANT and therefore safe to allow? (Explicitly: do NOT invert to
   pass-through-minus-deny-set; widen the allow-list instead.)

2. **Accidental direct `podman` on a netcage-left-behind container (real risk).**
   Once `netcage run` (no `--rm`) leaves a stopped tool container, someone/some
   script/agent could `podman start <name>` it directly, bypassing netcage and
   its jail. MUST VERIFY podman's actual behaviour: the tool container's network
   is `--network container:<sidecar>` and the sidecar is REMOVED at teardown, so
   a raw `podman start` should FAIL or start network-DEAD (fail-closed by
   design). Confirm this is what podman does (error / no network, never a
   working unjailed network). If confirmed, that coupling is a FEATURE and we
   keep it (do not give the tool container its own durable network). Also:
   label netcage-managed containers so they are identifiable, and decide how
   loudly to warn.

3. **First-class `machine`/environment noun in netcage, or just primitives?**
   Do we add a netcage `machine` concept, or only ship the primitives
   (no-forced-`--rm` + named/reusable container + `netcage start` that rebuilds
   the jail) and let a consumer (anon-pi) compose "machines"? (Leaning:
   primitives first; promote to a noun only when a second consumer wants it.)

4. **`netcage start` semantics for a stopped container:** it MUST rebuild the
   sidecar jail before starting the tool (never start a jailed tool network-
   less-but-alive in a way that could later get network). Confirm: `start`
   always creates a fresh sidecar + firewall + DNS, re-links the tool's network
   to it, then starts. A raw `podman start` (no jail) is acceptable ONLY because
   it is network-dead (see Q2).

<!-- /open-questions -->

## Problem Statement

netcage's goal is to be a **drop-in `podman` replacement whose container network
egress is forced through a socks5h proxy, fail-closed**. Today it falls short of
"drop-in" in ways that are NOT required by the security model:

- It **forces `--rm`** and **unconditionally deletes the tool container** at
  teardown, so a plain `netcage run <img>` cannot leave a stopped container to
  inspect / `logs` / `start` again — unlike `podman run`, which keeps it.
- It accepts only a **tiny allow-list** of ~9 run flags and refuses everything
  else, so most network-irrelevant podman flags (`--memory`, `-l/--label`,
  `--tmpfs`, ...) are unusable.
- It has only `run` and `verify` — no `ps`/`logs`/`exec`/`start`/`rm`/... — so
  you cannot inspect or manage netcage containers with familiar verbs.

Finding that motivates this: **`--rm` is hygiene, not security.** Per ADR-0006
the sidecar owns the netns + firewall + DNS forwarder; `Teardown` always removes
the sidecar, which destroys the jail. The tool container is removed twice over
(its `--rm` AND Teardown's explicit `rm -f`); the `--rm` protects nothing.
Forcing it is an un-podman policy choice, not a security requirement.

## Solution

Split the two concerns that are currently conflated, and widen podman fidelity
without weakening forced egress:

- **Jail teardown (ALWAYS, security):** remove the **sidecar** on every exit path
  — netns + firewall + DNS gone — exactly as today. Non-negotiable.
- **Tool-container lifecycle (podman semantics):** honour `--rm`; WITHOUT it,
  LEAVE the stopped tool container (inspectable, restartable), like podman.
- **Widen the (still fail-closed) run-flag allow-list** with vetted network-
  irrelevant flags, and keep the jail-breaching deny-set explicit. Unknown flags
  are REFUSED (fail-closed on the unknown — the correct bias for a security
  tool).
- **Add pass-through verbs** (`ps`/`logs`/`inspect`/`exec`/`stop`/`rm`/`images`)
  scoped to netcage containers, plus a **jail-aware `netcage start`** that
  rebuilds the sidecar before re-entering a kept container.
- Together, a **named, reusable, jailed container** = a durable environment; this
  is the primitive a "machine" is built from (see anon-pi's machines plan).

The forced-egress invariant is unchanged and paramount: **a jailed tool container
never runs without its sidecar jail.** `run` builds both; `start` rebuilds the
sidecar first; a container left stopped is network-dead (safe).

## User Stories

1. As a podman user, I want `netcage run <img>` (no `--rm`) to LEAVE a stopped
   container, so that I can inspect it (`logs`, `inspect`) afterwards like podman.
2. As a podman user, I want `netcage run --rm <img>` to remove the container on
   exit, so `--rm` behaves exactly as in podman.
3. As a security-conscious user, I want the JAIL torn down on every exit
   regardless of `--rm`, so no forced-egress residue (sidecar/netns/firewall/DNS)
   ever survives a run.
4. As a podman user, I want to pass common resource/metadata flags (`--memory`,
   `--cpus`, `-l/--label`, `--tmpfs`, `--read-only`, `--hostname`, `--pull`, ...)
   to `netcage run`, so it feels like podman for everything that cannot breach
   egress.
5. As a security-conscious user, I want an UNKNOWN or network/isolation-relevant
   flag REFUSED by default, so a future podman flag cannot silently open an
   egress path (fail-closed on the unknown).
6. As a user, I want `netcage ps` / `logs` / `inspect` / `exec` / `stop` / `rm`,
   so I can manage netcage containers with familiar podman verbs.
7. As a user, I want `netcage start <name>` to REBUILD the jail (fresh sidecar +
   firewall + DNS) and re-enter the same container with its state intact, so I
   can resume a durable jailed environment safely.
8. As a security-conscious user, I want a netcage container that is accidentally
   `podman start`-ed OUTSIDE netcage to be network-DEAD (its sidecar is gone),
   so bypassing netcage cannot produce a working unjailed network (fail-closed).
9. As a downstream tool (anon-pi), I want a named, reusable, jailed container
   with persistent state, so I can build "machines" on top of netcage instead of
   orchestrating persistence myself.
10. As a macOS/WSL2 user (future), I want netcage to stay a pure podman client
    (ADR-0006), so these lifecycle/verb features work against a remote podman too.

## Implementation Decisions

- **Teardown split** (`internal/jail`): `Teardown` removes the sidecar always;
  the tool container is removed only when `--rm` (or an internal ephemeral run)
  asks. Internal one-shots (verify probes, declarative runs) keep `--rm`
  behaviour explicitly; the change is that a plain user `run` without `--rm`
  no longer force-deletes the tool container.
- **Flag model** (`internal/cli`): keep the allow-list + deny-set structure;
  WIDEN the allow-list with vetted network-irrelevant flags; keep refusing
  unknown flags. Deny-set stays: `--network`, `-p/--publish`, `--dns`,
  `--privileged`, `--cap-add`, `--device`, plus netcage-owned `--name`/`--rm`/
  `--network` semantics. (See Q1 for width + vetting.)
- **Verbs**: `ps`/`logs`/`inspect`/`exec`/`stop`/`rm`/`images` as thin
  pass-throughs to podman (optionally filtered to `netcage-run-*`). `start` is
  the jail-aware exception (rebuilds the sidecar). (See Q4.)
- **Identity/labels**: label netcage-managed containers so they are
  discoverable and flaggable (See Q2).
- **Machines**: named/reusable container is the primitive; whether netcage grows
  a `machine` noun is Q3.

## Testing Decisions

- Teardown split: after a non-`--rm` run the SIDECAR is gone (no netns/firewall/
  DNS residue) but the tool container REMAINS stopped; after a `--rm` run both
  are gone. `verify` stays green (jail still torn down every path).
- Fail-closed flag model: each deny-set flag still refused with its message;
  each newly-allowed vetted flag passes through; an UNKNOWN flag is refused.
- `netcage start` rebuilds a working jail (verify-style leak assertions hold on
  the restarted container); a raw `podman start` of a left-behind container is
  network-dead (Q2 — this is a podman-behaviour assertion to pin down).
- Podman-gated integration for the lifecycle + start-rebuilds-jail paths.

## Out of Scope

- The anon-pi "machines"/init product (lives in `anon-pi/docs/plan-machines-and-
  init.md`); this PRD only provides the netcage primitives it will consume.
- Inverting to full pass-through-minus-deny-set (explicitly rejected in Q1;
  fail-closed on unknown flags is required).

## Further Notes

- Grounded in ADR-0006 (sidecar owns firewall + DNS; netcage is a pure podman
  client), which this PRD extends toward the drop-in goal and remote-podman
  future.
- Sequencing (each shippable independently): (1) teardown split; (2) widen the
  allow-list + explicit deny-set; (3) pass-through verbs; (4) jail-aware `start`
  + named/reusable containers => machines primitive.
- Reviewer caution preserved: the flag model must stay fail-closed on the
  unknown; the accidental-direct-podman risk (Q2) hinges on the network-dead
  property and must be verified against real podman before relying on it.
