---
title: netcage as a fuller podman replacement (lifecycle + fidelity)
slug: podman-fidelity-and-lifecycle
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth:
> `docs/adr/` (decisions) + the code; remaining work: `work/tasks/`. The
> Implementation/Testing detail that was here has been TASKED (it now lives in
> `work/tasks/`), and the open-questions were resolved by spiking real podman
> behaviour (see `work/notes/findings/`) before tasking; the durable rationale
> of the fail-closed-restart decision is recorded as an ADR. This prd settles to
> its durable framing: Problem / Solution / User Stories / Out of Scope.

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

Split the two conflated concerns (jail teardown vs tool-container lifecycle),
widen podman fidelity, and make a leftover jailed container **fail-closed even
against a raw `podman start` outside netcage** — without weakening forced egress:

- **Jail lifecycle (ALWAYS fail-closed, security):** the firewall (UDP drop +
  RFC1918 drops + reachback narrowing + split-tunnel accepts) is baked into the
  sidecar so it **self-heals on every (re)start**, and the jail is fully torn
  down when nothing is being kept. This closes the leak proven by spiking real
  podman: a leftover tool joined by `--network container:<sidecar>` cannot have
  its sidecar removed while it exists, podman AUTO-REVIVES a stopped sidecar on a
  raw `podman start`, and a runtime-only firewall does NOT re-apply on that
  revive — leaving LAN/RFC1918 + UDP reachable (a leak). Baking the firewall into
  the sidecar makes an auto-revived jail drop LAN + UDP and leave DNS dead, so a
  raw bypass is fail-closed. (The public-egress-through-the-proxy property was
  already restart-safe; the LAN/UDP hole is what this closes.)
- **Tool-container lifecycle (podman semantics):** honour `--rm`; WITHOUT it,
  LEAVE the stopped tool container together with its stopped sidecar
  (inspectable, restartable), labelled as netcage-managed. Because the firewall
  is baked in, the left-behind pair is fail-closed at rest and on any restart.
- **Widen the (still fail-closed) run-flag allow-list** with vetted network-
  irrelevant flags, keeping the jail-breaching deny-set explicit and refusing
  unknown flags (fail-closed on the unknown — the correct bias for a security
  tool). A flag is allowable only if it cannot alter the network/netns, add
  capabilities/devices/privilege, publish/bind ports, affect DNS/resolv, or
  collide with a netcage-owned name/lifecycle field.
- **Add pass-through verbs** (`ps`/`logs`/`inspect`/`exec`/`stop`/`rm`/`images`)
  scoped to netcage-managed containers, plus a **jail-aware `netcage start`**
  that REVIVES the sidecar (the baked firewall re-applies), re-execs the DNS
  forwarder, and re-enters the kept container. `netcage start` REFUSES to revive
  when the requested jail config (`--proxy` / `--allow-direct`) differs from the
  one the container was created with, rather than silently running a stale jail.
- Together, a **named, reusable, jailed container** = a durable environment; this
  is the primitive a "machine" is built from downstream (netcage ships only the
  primitive, not a `machine` noun).

The forced-egress invariant is paramount: **a jailed tool container never has a
working un-jailed network.** `run` builds the jail; `netcage start` revives it
(firewall self-heals) before re-entering; a leftover container started any other
way (raw `podman start`) is fail-closed — LAN/UDP dropped, DNS dead, public TCP
still forced through the proxy.

## User Stories

1. As a podman user, I want `netcage run <img>` (no `--rm`) to LEAVE a stopped
   container, so that I can inspect it (`logs`, `inspect`) afterwards like podman.
2. As a podman user, I want `netcage run --rm <img>` to remove the container on
   exit, so `--rm` behaves exactly as in podman.
3. As a security-conscious user, I want the jail's firewall to be fail-closed on
   every exit AND every restart regardless of `--rm`, so no forced-egress hole
   (a LAN/UDP leak, a working un-jailed network) can ever survive or be revived,
   even by a raw `podman start` outside netcage.
4. As a podman user, I want to pass common resource/metadata flags (`--memory`,
   `--cpus`, `-l/--label`, `--tmpfs`, `--read-only`, `--hostname`, `--pull`, ...)
   to `netcage run`, so it feels like podman for everything that cannot breach
   egress.
5. As a security-conscious user, I want an UNKNOWN or network/isolation-relevant
   flag REFUSED by default, so a future podman flag cannot silently open an
   egress path (fail-closed on the unknown).
6. As a user, I want `netcage ps` / `logs` / `inspect` / `exec` / `stop` / `rm`,
   so I can manage netcage containers with familiar podman verbs.
7. As a user, I want `netcage start <name>` to REVIVE the jail (the baked
   firewall re-applies, the DNS forwarder is restarted) and re-enter the same
   container with its state intact, so I can resume a durable jailed environment
   safely; and to be REFUSED if I ask to start it with a different proxy/allowlist
   than it was created with (never a silently-stale jail).
8. As a security-conscious user, I want a netcage container that is accidentally
   `podman start`-ed OUTSIDE netcage to be FAIL-CLOSED (LAN/RFC1918 + UDP
   dropped, DNS dead, public TCP still forced through the proxy), so bypassing
   netcage can never produce a working un-jailed network.
9. As a downstream tool (anon-pi), I want a named, reusable, jailed container
   with persistent state, so I can build "machines" on top of netcage instead of
   orchestrating persistence myself.
10. As a macOS/WSL2 user (future), I want netcage to stay a pure podman client
    (ADR-0006), so these lifecycle/verb features work against a remote podman too.

## Out of Scope

- The anon-pi "machines"/init product (lives in `anon-pi/docs/plan-machines-and-
  init.md`); this PRD ships only the netcage primitives it will consume. netcage
  grows NO `machine` noun here (primitives first; promote to a noun only when a
  second consumer needs it).
- Inverting to full pass-through-minus-deny-set (explicitly rejected; fail-closed
  on unknown flags is required).
- Allowing `--add-host` (it can pin a hostname→IP that sidesteps proxy-side DNS);
  it stays refused for now.

---

_Tasked: the Implementation/Testing detail moved into `work/tasks/` (search
`prd: podman-fidelity-and-lifecycle`). The open questions were resolved by
spiking real podman before tasking — see the findings
`work/notes/findings/podman-network-container-dependency-lifecycle.md`,
`sidecar-firewall-via-extra-commands-survives-restart.md`, and
`netcage-start-sidecar-revive-is-sufficient.md` — and the durable rationale of
the fail-closed-on-restart decision (firewall via the sidecar's `EXTRA_COMMANDS`,
refining ADR-0006) is recorded as an ADR by the first task._
