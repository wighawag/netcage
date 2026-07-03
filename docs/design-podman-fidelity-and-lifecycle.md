# Design note: netcage as a fuller podman replacement (lifecycle + fidelity)

Status: PROPOSED (design note, not yet implemented). Companion to the anon-pi
"machines" plan; this is the netcage-side enabler.

Goal restated (owner): **netcage is a drop-in `podman` replacement whose
container network egress is forced through a socks5h proxy, fail-closed.** The
more faithful to podman netcage is, the better, provided the forced-egress
invariant is never weakened.

This note (a) establishes that `--rm` is NOT security-critical, (b) proposes
splitting jail teardown (always) from tool-container lifecycle (podman
semantics), and (c) catalogs other "be more podman" opportunities, including the
one that turns "machines" into a netcage primitive.

## 1. Finding: `--rm` is hygiene, not security

Read of the current code (post ADR-0006, `internal/jail/run.go` `Teardown`,
`jail.go` `ToolRunArgs`/`SidecarRunArgs`):

- The jail's leak-proofness lives ENTIRELY in the **sidecar**: it owns the
  netns, the firewall (iptables, in-sidecar per ADR-0006), and the `netcage-dns`
  forwarder. Destroying the sidecar destroys the forced-egress jail.
- `Teardown()` explicitly `podman rm -f -i`s BOTH the tool container and the
  sidecar, on every exit path (normal / error / SIGINT), idempotently.
- The **sidecar** is started WITHOUT `--rm` (it is cleaned by Teardown's rm -f).
- The **tool** container is started WITH `--rm` AND is also rm -f'd by Teardown.

So the tool container is removed twice over, and `--rm` protects nothing the
sidecar teardown doesn't already guarantee. **The security model depends on
removing the sidecar, never on `--rm`.** netcage forcing `--rm` (and denying the
user's `--rm`/`--name`) is a policy/hygiene choice, not a security requirement,
and it is un-podman-like (podman keeps stopped containers by default).

## 2. The real limitation: unconditional tool-container teardown

Even if netcage stopped FORCING `--rm`, `Teardown` currently removes the tool
container unconditionally. So netcage cannot today support the plain podman
contract `podman run <img>` -> "leave a stopped container I can inspect /
`podman logs` / `podman start` again". A faithful podman replacement must be able
to leave the tool container behind.

## 3. Proposal: split "jail teardown" from "tool-container lifecycle"

Two independent concerns:

- **Jail teardown (ALWAYS, security):** remove the **sidecar** -> netns +
  firewall + DNS forwarder gone -> forced egress gone -> no leak surface remains.
  Non-negotiable; runs on every exit path exactly as now.
- **Tool container lifecycle (podman semantics):** the tool container's fate
  follows the user's intent:
  - `--rm` given -> remove it on exit (as now).
  - no `--rm` -> LEAVE it stopped (podman default), inspectable and restartable.

Concretely:
- `Teardown` removes the sidecar always; it removes the tool container ONLY when
  `--rm` was requested (or an internal/ephemeral run asks for it).
- Internal runs that want no residue (verify probes, one-shot declarative runs)
  keep `--rm` behaviour explicitly; the CHANGE is only that a plain user
  `netcage run` without `--rm` no longer force-deletes the tool container.

Safety note: a LEFT-BEHIND tool container is stopped and its network was
`--network container:<sidecar>`; once the sidecar is gone, the stopped tool
container has no live network at all. Restarting it later must RE-ESTABLISH the
jail (a new sidecar) or refuse, see "machines" below. A stopped, network-dead
container is not a leak; a naive `podman start` of it (without a sidecar) would
have NO network, which is safe (fail-closed by absence), but netcage should own
"start" so it rebuilds the jail rather than starting it network-less.

## 4. Other "be more podman" opportunities

ADR-0006 already made netcage a **pure podman client** (podman argv only, no
host nsenter/nft), explicitly to enable driving a remote podman (mac/WSL2). These
build on that trajectory.

### 4a. Invert the flag model: pass-through by default, deny the breach set

Today `run` accepts a tiny ALLOW-LIST (~9 flags: -i/-t/-it, -v, -w, -e, -u,
--entrypoint, +--proxy/--allow-direct) and REJECTS everything else. podman has
hundreds of flags, most network-irrelevant (`--memory`, `--cpus`, `-l/--label`,
`--hostname`, `--tmpfs`, `--read-only`, `--pull`, `--platform`, `--env-file`,
`--user`, `--workdir`, ...). A drop-in replacement should INVERT:

- **Pass ALL podman flags through by default**, EXCEPT the jail-breaching
  deny-set, which stays refused with the current pointed messages:
  `--network`, `-p/--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`
  (and netcage-managed `--name`/`--rm`/`--network` which it sets itself).
- This flips netcage from "a curated subset of podman" to "podman minus the
  handful of flags that would breach forced egress." Much closer to drop-in.
- Risk to weigh: pass-through means a NEW podman flag that could breach egress
  arrives un-denied. Mitigation: keep the deny-set as the security boundary and
  review it against "does this touch network/namespaces/capabilities/devices".
  The deny-set is small and stable; the breach surface is well understood
  (network, ports, dns, caps, devices, privileged). Everything else (memory,
  labels, tmpfs, ...) cannot breach forced egress.

This is the single biggest "more podman" win and should be its own task with a
careful deny-set audit.

### 4b. More subcommands (the podman verbs)

Today: only `run` and `verify`. For a real replacement, and to make a
left-behind tool container useful (proposal 3), netcage needs the inspection/
lifecycle verbs, as **thin pass-throughs to podman scoped to netcage-run
containers**:

- `netcage ps` / `logs` / `inspect` / `exec` / `stop` / `rm` -> pass through to
  podman (optionally filtered to `netcage-run-*`). `exec` into a running jailed
  tool is genuinely useful.
- `netcage start <name>` -> the ONE that must be netcage-aware: it must REBUILD
  the jail (fresh sidecar, firewall, DNS) before starting the tool container, or
  refuse, never start a jailed tool with no forced egress.
- `netcage images` etc. -> trivial pass-through.

Scope carefully: pass-through verbs are cheap and high-fidelity; only `run`,
`start`, and teardown are security-load-bearing.

### 4c. `--name` and run-attributable identity (enables "machines")

Today `--name` is denied ("netcage owns it for teardown"). But a podman
replacement should let you NAME a container and refer to it. netcage can OWN the
name scheme (e.g. prefix `netcage-run-` or a user-visible name mapped to it)
while still EXPOSING a stable handle. A named, restartable tool container +
`netcage start` that rebuilds the jail = **a reusable jailed environment**, i.e.
a "machine".

## 5. This makes "machines" a netcage primitive (Architecture B)

The anon-pi plan defined a "machine" = image + persistent home, a durable
environment. Proposals 3 + 4c mean netcage can natively provide the core of it:

- **No forced `--rm`** -> a tool container (its writable layer = its `$HOME`
  state) survives exit.
- **`netcage start <name>`** -> re-establish the jail and re-enter the SAME
  container, state intact. That IS "resume the machine".
- Persistence via the container's own layer OR a `-v` home volume; either works.

So a **netcage "environment/machine"** = a named, reusable, jailed container that
netcage tears the JAIL down around on exit but does not delete, and rebuilds the
jail for on `start`. anon-pi's "machine" becomes "a netcage environment seeded
with pi config", and anon-pi stops orchestrating persistence via
volume-mounts-over-a-throwaway-container.

Whether netcage grows a first-class `machine`/environment noun, or just provides
the primitives (no-forced-rm + named + `start`-rebuilds-jail) and lets anon-pi
compose them, is the open call in section 7.

## 6. Forced-egress invariant (unchanged, restated)

None of this weakens the invariant. The security boundary is precisely:

- egress is `--network container:<sidecar>` + the sidecar's firewall + DNS
  forwarder; and
- ANY path that starts/restarts the tool container MUST have a live sidecar jail
  around it, or refuse.

So the ONE rule for every new lifecycle verb: **a jailed tool container never
runs without its sidecar jail.** `run` builds both; `start` rebuilds the sidecar
before starting the tool; a container left stopped has no network (safe). The
deny-set (network/ports/dns/caps/devices/privileged) is the flag-level boundary
and stays enforced under pass-through.

## 7. Proposed sequencing + open calls

Order (each shippable independently):

1. **Teardown split** (proposal 3): sidecar always; tool container per `--rm`.
   Small, high-fidelity, unblocks left-behind containers. Verify still green.
2. **Flag pass-through with deny-set** (4a): the biggest drop-in win; needs a
   deny-set audit + tests that each breach flag is still refused and that
   network-irrelevant flags pass.
3. **Pass-through verbs** (4b): `ps/logs/inspect/exec/stop/rm/images`; then the
   jail-aware `netcage start` (4c) that rebuilds the sidecar.
4. **Named/reusable containers** -> "machines" primitive (5), once 1-3 land.

Open calls for the owner:
- **(A)** Does netcage grow a first-class `machine`/environment noun, or just the
  primitives (no-forced-rm + named + start-rebuilds-jail) with anon-pi composing?
  (Leaning: primitives first; promote to a noun only if a second consumer wants
  it, same "extract on second user" discipline.)
- **(B)** Flag model: full pass-through-minus-deny-set now, or widen the
  allow-list incrementally? (Leaning: invert to pass-through; it is the honest
  drop-in and the deny-set is the real, small security boundary.)
- **(C)** For a stopped/left-behind tool container, is "no network until
  `netcage start` rebuilds the jail" acceptable behaviour (it is fail-closed), vs
  refusing a bare `podman start` entirely? (Leaning: netcage owns `start`; a raw
  `podman start` giving no network is acceptable because it cannot leak.)

## 8. anon-pi impact (forward pointer)

If proposals 1 + 3-5 land, anon-pi's `docs/plan-machines-and-init.md` THINS:
machines become netcage environments; anon-pi provides only the pi seed
(extensions/models/trust), the LLM/proxy config + `init`, and the project<->
machine binding. Revise that plan to CONSUME netcage machines rather than
build persistence itself, after the netcage lifecycle change is decided.
