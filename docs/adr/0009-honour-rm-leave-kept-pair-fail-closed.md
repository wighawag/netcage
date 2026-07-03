# `netcage run` honours `--rm`; without it the stopped tool + sidecar are LEFT behind, fail-closed and labelled

**Status:** accepted

netcage used to force `--rm` on the tool container AND unconditionally force-remove
it (and its sidecar) at teardown, so a plain `netcage run <img>` could never leave
a stopped container to inspect / restart, unlike `podman run`. This ADR splits the
two concerns that forcing conflated:

- **Tool-container lifecycle = podman semantics.** `jail.Config.Ephemeral` now
  drives it. WITH the netcage `--rm` flag (Ephemeral true) the tool runs with
  `--rm` and teardown removes BOTH containers, exactly as before (no residue).
  WITHOUT `--rm` (Ephemeral false, the new default) the tool container omits
  `--rm` and teardown removes NEITHER, so the stopped tool and its stopped sidecar
  are LEFT behind, inspectable/restartable like `podman run`.
- **Jail lifecycle = fail-closed security, unchanged.** A left-behind pair is
  fail-closed at rest and on any restart because the firewall is baked into the
  sidecar's `EXTRA_COMMANDS` (ADR-0008): a raw `podman start` of the leftover tool
  auto-revives the sidecar, which re-applies the firewall (LAN/UDP dropped), and
  DNS stays dead (the forwarder is a separate exec, not baked in). So leaving the
  pair does not weaken forced egress.

## Why "sidecar gone, tool kept" is not an option

Proven against podman 5.4.2 (see
`work/notes/findings/podman-network-container-dependency-lifecycle.md`): podman
REFUSES to remove a `--network container:` sidecar while its dependent tool still
exists, and `podman rm -f --depend` cascades and removes the tool too. So the only
two reachable end-states are both-present and both-gone. The kept path therefore
leaves BOTH (sidecar stopped), which is exactly why the ADR-0008 baked firewall is
load-bearing here.

## `--rm` is a NETCAGE-owned flag, not a smuggled podman `--rm`

`--rm` is REMOVED from the CLI deny-set and parsed into `Command.Rm`. netcage OWNS
what `--rm` means: it interprets its own `--rm` into `Config.Ephemeral` (remove
both tool + sidecar) and NEVER passes a raw podman `--rm` through. netcage still
owns the tool container's name and lifecycle; the user never passes a raw
`--name`/`--rm` to podman, they pass the netcage `--rm` which netcage interprets.
`--name` STAYS in the deny-set (netcage owns the run-attributable name).

## Internal one-shots stay ephemeral, explicitly

Every internal probe run (verify's exit-IP / DNS checks, the reachback/direct
probes, any declarative run) sets `Ephemeral: true`, so they keep the remove-both
behaviour and `verify` stays residue-free. Only a plain user `run` without `--rm`
changes. The zero-value `Config{}` default (Ephemeral false = kept) matches the
user-facing default; callers that need remove-both set it explicitly.

## The `netcage.managed` label (introduced here)

This is the first path that leaves containers behind that must be identifiable at
rest, so the tool and sidecar create args now carry stable labels set at create
time:

- `netcage.managed=true` - the robust discriminator (a label, not the
  `netcage-run-<id>-*` name convention);
- `netcage.role=tool` / `netcage.role=sidecar`;
- `netcage.run-id=<id>`.

The pass-through verbs task (`ps`/`logs`/`inspect`/`exec`/`stop`/`rm`) and
`netcage start` CONSUME this label to scope their operations to netcage-managed
containers; they `blockedBy` this task, so the dependency runs one way (this task
introduces the label, they consume it).

## Consequences

- A plain `netcage run <img>` now leaves a stopped, labelled tool + sidecar behind
  (a USER-VISIBLE default change, matching `podman run`); `netcage run --rm <img>`
  removes both as before.
- Tests that deliberately leave a kept pair MUST clean up after themselves (podman
  is host-global state): a unique run-id names the pair and `t.Cleanup` does
  `podman rm -f --depend` (cascading to the tool) even on failure.
- The forced-egress invariant is unchanged: the jail is torn down (ephemeral) or
  left fail-closed via the baked firewall (kept) on every path; a leftover
  container never runs un-jailed.
