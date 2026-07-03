---
title: Add netcage pass-through verbs (ps/logs/inspect/exec/stop/rm/images) scoped to netcage-managed containers (via the netcage.managed label)
slug: pass-through-verbs-and-labels
prd: podman-fidelity-and-lifecycle
blockedBy: [teardown-split-honour-rm]
covers: [6]
---

## What to build

Give netcage the familiar podman management verbs, scoped to netcage-managed
containers, plus the label that makes that scoping possible:

- **Consume the `netcage.managed` label.** The `netcage.managed` (+ role + run
  id) label on netcage-created containers is INTRODUCED by the
  `teardown-split-honour-rm` task (the first to leave containers behind); this
  task CONSUMES it as the robust discriminator the verbs filter on (a label, not
  the `netcage-run-<id>-*` name convention). If for any reason that task's label
  is not yet present when you build this, add it to the container create args
  here - but the two tasks are serialised (`blockedBy`) so it should already
  exist.
- **Pass-through verbs**: `netcage ps` / `logs` / `inspect` / `exec` / `stop` /
  `rm` / `images` as THIN pass-throughs to podman, FILTERED to netcage-managed
  containers (via the label) so a user manages netcage's containers with podman
  vocabulary without seeing unrelated ones. `ps` defaults to listing
  netcage-managed containers; `logs`/`inspect`/`exec`/`stop`/`rm` operate on a
  named netcage container (resolve/guard by label). These verbs do NOT stand up
  or tear down a jail (that is `run`/`start`); they are inspection/management
  only.
- Extend the subcommand dispatch (currently just `run`/`verify`) to route these
  verbs. Keep the proxy-preflight requirement OFF these management verbs (they
  do not egress; requiring `--proxy` to `ps`/`logs` would be wrong).

`netcage rm` removes a netcage-managed container; because a `--network
container:` tool pins its sidecar, `rm` of a kept pair must remove BOTH (the
`--depend` cascade) so it leaves no half-torn-down residue - mirror the ephemeral
teardown's remove-both.

## Acceptance criteria

- [ ] The verbs filter on the `netcage.managed` label (introduced by the
      blocking teardown task); a container carrying it is in scope, one without it
      is out of scope.
- [ ] `netcage ps` lists only netcage-managed containers (filtered by label);
      `netcage images` shows the images netcage uses; `logs`/`inspect`/`exec`/
      `stop` operate on a named netcage-managed container and REFUSE (clear
      message) a non-netcage container.
- [ ] `netcage rm <name>` removes the named netcage container and, for a kept
      tool+sidecar pair, removes BOTH (no half-removed residue, no orphaned
      sidecar).
- [ ] The management verbs do NOT require `--proxy` and do NOT stand up/tear down
      a jail; they never alter the forced-egress state of a running jail.
- [ ] The forced-egress invariant is untouched: these verbs cannot give a
      container a working un-jailed network (`exec` runs inside the existing
      jailed netns; `start` is deliberately NOT part of this task - it is the
      jail-aware verb built separately).
- [ ] Tests: unit tests for verb dispatch + label-filter arg construction
      (assert the podman argv built for each verb without executing podman,
      mirroring the existing arg-builder tests) and the non-netcage-container
      refusal; a podman-gated (`integration`) test that `ps` shows a kept
      container and `rm` removes the pair.

## Blocked by

- `teardown-split-honour-rm` - the verbs manage LEFT-BEHIND containers, which
  only exist once the teardown split leaves them; and this task adds the label
  the split's leftover pair (and `netcage start`) rely on. Serialised also
  because both touch the CLI subcommand dispatch + the sidecar/tool create args.

## Prompt

> Goal: add netcage management verbs (`ps`/`logs`/`inspect`/`exec`/`stop`/`rm`/
> `images`) as thin pass-throughs to podman, SCOPED via the `netcage.managed`
> label (introduced by the blocking teardown task) so the verbs only touch
> netcage's own containers.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm the CLI still dispatches only `run` and `verify` (the
> subcommand switch in the cli package's parser and in `main.go`), and that
> containers are named `netcage-run-<id>-sidecar`/`-tool` with NO label yet
> (look at the sidecar/tool run-args builders in the jail package). Confirm the
> blocking task landed (kept runs now LEAVE containers behind - otherwise there is
> nothing to manage). If dispatch/naming changed, adapt or route to
> needs-attention.
>
> Domain: netcage is a drop-in podman replacement forcing all egress through a
> socks5h proxy, fail-closed. A run creates a tun2socks "sidecar" (owns the netns
> + firewall + DNS) and a "tool" container joined via `--network
> container:<sidecar>`. After the teardown-split task, a non-`--rm` run leaves
> both stopped. These verbs let a user inspect/manage them with podman vocabulary.
>
> Where to look / seams: the CLI subcommand dispatch (add the verb routes; keep
> proxy-preflight OFF them); the `netcage.managed` label on the container create
> args is ALREADY added by the blocking teardown task - CONSUME it (do not
> re-introduce it; if it is somehow absent, that task drifted -> needs-attention);
> a small helper that builds a label-filtered podman argv per verb. Test at the argv-builder seam (assert the built podman command
> for each verb, including the label filter) without running podman, mirroring the
> existing `SidecarRunArgs`/`ToolRunArgs` wiring tests; add one podman-gated
> integration test.
>
> Preserve the forced-egress invariant: management verbs are inspection/lifecycle
> only - they must not give any container a working un-jailed network, must not
> require or bypass the proxy, and `exec` must run inside the EXISTING jailed
> netns (never a fresh unjailed one). Do NOT implement `netcage start` here (it is
> the jail-aware verb, built in its own task); `stop`/`rm` here are plain
> pass-throughs.
>
> RECORD any in-scope choice (label key names, whether `ps` shows sidecars or only
> tools, how `rm` handles the pair) in the done record. Done = the verbs work
> label-scoped, non-netcage containers are refused, `rm` cleans the pair, no verb
> touches the jail's egress state, and tests cover the argv construction + the
> refusal.
