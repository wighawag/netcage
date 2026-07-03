---
title: Split jail teardown from tool-container lifecycle - honour --rm, and without it LEAVE the stopped container (+ sidecar) fail-closed
slug: teardown-split-honour-rm
prd: podman-fidelity-and-lifecycle
blockedBy: [fail-closed-restart-firewall-via-extra-commands]
covers: [1, 2, 3]
---

## What to build

Stop forcing `--rm` on the tool container and stop unconditionally deleting it.
Split the two concerns that are conflated today:

- **Tool-container lifecycle = podman semantics.** When the user passes `--rm`,
  the tool container is removed on exit (exactly as podman). WITHOUT `--rm`, the
  stopped tool container is LEFT behind (inspectable, restartable), like `podman
  run`. Today the tool run hard-codes `--rm` in the tool run args AND teardown
  also force-removes it - remove BOTH forced deletions for the non-`--rm` path.
- **Jail lifecycle = fail-closed security.** Because a `--network container:`
  tool cannot be removed while its sidecar exists and `podman rm --depend`
  cascades to the tool (proven - see the finding), "remove the sidecar but keep
  the tool" is NOT reachable. So for a KEPT tool, LEAVE the sidecar too but
  STOPPED, relying on the baked-in `EXTRA_COMMANDS` firewall (from the blocking
  task) to keep it fail-closed at rest and on any restart. For an EPHEMERAL run
  (`--rm`, and every internal one-shot: verify probes, reachback/direct probes,
  declarative runs) tear DOWN both tool and sidecar exactly as today (no
  residue).

Internal one-shots MUST keep the ephemeral (remove-both) behaviour explicitly -
only a plain user `run` without `--rm` changes.

**`--rm` becomes a netcage-owned USER flag (decided): REMOVE it from the
deny-set** and make `netcage run --rm` mean "ephemeral this run" at the netcage
level. netcage OWNS what `--rm` does - it is NOT smuggled through to podman's raw
`--rm`; netcage decides the tool container's lifecycle (name + removal) and maps
its own `--rm` to the ephemeral teardown (remove both tool + sidecar). So if
netcage needs to do something extra on the ephemeral path (its own teardown, its
own labelling), it takes care of it. The invariant is unchanged: netcage owns the
tool container's name + lifecycle; the user never passes a raw podman `--rm`/
`--name`, they pass the netcage `--rm` which netcage interprets.

**This task INTRODUCES the `netcage.managed` label** (+ role + run id) on the
tool and sidecar create args, because it is the first task to leave containers
behind that must be identifiable at rest. The pass-through-verbs task consumes
this label to scope its verbs (it `blockedBy` this task).

## Acceptance criteria

- [ ] netcage-created containers (tool + sidecar) carry a stable
      `netcage.managed` label (+ role + run id) set at create time (introduced
      here).
- [ ] A plain `netcage run <img>` (no `--rm`) LEAVES a stopped tool container and
      its stopped sidecar behind after exit; a subsequent `podman ps -a` shows
      both, carrying the `netcage.managed` label.
- [ ] `netcage run --rm <img>` (or the netcage ephemeral path) removes BOTH the
      tool and the sidecar on exit - no residue (as today).
- [ ] Every INTERNAL one-shot (verify probes, reachback/direct probes, any
      declarative run) still tears down both containers - `verify` stays green
      and leaves no residue.
- [ ] The forced-egress invariant holds: a left-behind pair is fail-closed at
      rest and on restart (the baked firewall from the blocking task drops
      LAN/UDP; DNS is dead until netcage restores it). A raw `podman start` of the
      leftover tool never yields a working un-jailed network.
- [ ] `netcage run --rm` is ACCEPTED (removed from the deny-set) and means the
      netcage-level ephemeral run (removes both tool + sidecar); `--name` stays
      deny-set (netcage owns the run-attributable name). The user's `--rm` is
      netcage's flag, never smuggled to podman's raw `--rm`.
- [ ] Tests: unit tests for the tool-run-args (no forced `--rm` on the kept path;
      `--rm` on the ephemeral path) and teardown (removes both on ephemeral;
      leaves both on kept), mirroring the existing jail tests; a podman-gated
      (`integration`) test that a kept run leaves both containers and an ephemeral
      run leaves none.

## Blocked by

- `fail-closed-restart-firewall-via-extra-commands` - the leftover sidecar is
  only safe to leave because its firewall self-heals on restart; this task must
  not land before that hardening.

(This task INTRODUCES the `netcage.managed` label itself, so it does NOT depend
on the verbs task; the dependency runs the other way - `pass-through-verbs-and-
labels` `blockedBy` THIS task and consumes the label.)

## Prompt

> Goal: make `netcage run` honour podman `--rm` semantics - WITHOUT `--rm`, leave
> the stopped tool container (and its stopped sidecar) behind like `podman run`;
> WITH `--rm` (and for every internal one-shot), remove both on exit as today.
> Stop force-deleting the tool container on the kept path.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm the tool run args still hard-code `--rm` (look in the jail
> Config's tool-run-args builder) AND that teardown still force-removes the tool
> container by name (the teardown routine removes `toolName` then `sidecarName`).
> Confirm the blocking task landed: the firewall must already be baked into the
> sidecar's `EXTRA_COMMANDS` (so a left-behind sidecar is fail-closed on restart).
> If the firewall is still exec-applied, do NOT build this - the leftover would
> leak; route to needs-attention.
>
> Domain + hard podman facts (proven, in the findings - READ FIRST):
> `work/notes/findings/podman-network-container-dependency-lifecycle.md` shows you
> CANNOT remove a sidecar while its `--network container:` tool exists, and
> `podman rm -f --depend` cascades and removes the tool too. So "sidecar gone,
> tool kept" is impossible; the kept path leaves BOTH (sidecar stopped), safe
> because of the baked firewall (finding
> sidecar-firewall-via-extra-commands-survives-restart.md).
>
> Where to look / seams: the jail Config tool-run-args builder (drop the forced
> `--rm` on the kept path; keep it on the ephemeral path); the teardown routine
> (parameterise remove-both vs leave-both by whether the run is ephemeral);
> `internal/verify` and any internal probe runs (they MUST stay ephemeral). REMOVE
> `--rm` from the CLI deny-set (`denyReasons`) and make `netcage run --rm` a
> NETCAGE-owned flag meaning the ephemeral run (remove both tool + sidecar) -
> netcage owns its semantics and does NOT pass it to podman's raw `--rm`. `--name`
> STAYS in the deny-set (netcage owns the run-attributable name). Also INTRODUCE
> the `netcage.managed` (+ role + run id) label on the tool and sidecar create
> args here, since this is the first task that leaves containers behind that must
> be identifiable; the verbs task consumes it. Record any non-obvious in-scope
> choice in the done record / an ADR if it meets the gate.
>
> Preserve the forced-egress invariant: the jail is torn down (or left fail-closed
> via the baked firewall) on every path; a leftover container never runs
> un-jailed; `verify` stays green and residue-free on the ephemeral paths.
>
> Done = kept runs leave both containers (labelled), ephemeral runs and all
> internal one-shots leave none, `verify` is green, and the leftover pair is
> proven fail-closed.
