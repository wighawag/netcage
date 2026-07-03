---
title: Add netcage pass-through verbs (ps/logs/inspect/exec/stop/rm/images) scoped to netcage-managed containers, and label them
slug: pass-through-verbs-and-labels
prd: podman-fidelity-and-lifecycle
blockedBy: [teardown-split-honour-rm]
covers: [6]
---

## What to build

Give netcage the familiar podman management verbs, scoped to netcage-managed
containers, plus the label that makes that scoping possible:

- **Label netcage-managed containers.** Every container netcage creates (the
  tool AND the sidecar) gets a stable label (e.g. `netcage.managed=true` plus a
  role label `netcage.role=tool|sidecar` and the run id) at CREATE time, so they
  are discoverable and filterable. (Today they are only identifiable by the
  `netcage-run-<id>-*` name convention; a label is the robust discriminator the
  verbs and `netcage start` filter on.)
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

- [ ] netcage-created containers (tool + sidecar) carry a stable
      `netcage.managed` label (+ role + run id) set at create time.
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
> `images`) as thin, label-scoped pass-throughs to podman, and LABEL every
> netcage-managed container so the verbs (and the later `netcage start`) can
> filter to netcage's own containers.
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
> proxy-preflight OFF them); the container create args (add the `netcage.managed`
> + role + run-id labels); a small helper that builds a label-filtered podman
> argv per verb. Test at the argv-builder seam (assert the built podman command
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
