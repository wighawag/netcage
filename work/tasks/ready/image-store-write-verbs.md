---
title: Add `netcage build`/`pull`/`load` - the WRITE side of the netcage image store, so `netcage run <locally-built-image>` works again after the graphroot move
slug: image-store-write-verbs
prd: netcage-image-store-write-verbs
blockedBy: []
covers: [1, 2, 3, 4, 5, 6]
---

## What to build

Add three pass-through management verbs - `netcage build`, `netcage pull`,
`netcage load` - that write into netcage's image store (the relocated
`/var/tmp/netcage-storage` graphroot), fixing the v0.7.0 REGRESSION where a
locally-built / pulled tool image is invisible to `netcage run`.

Since the graphroot move (`relocate-graphroot-to-var-tmp-single-store`, #19,
ADR-0013) every netcage podman call is prefixed with `--root <graphroot>` at the
`ExecRunner.Run` seam, so netcage reads/runs from `/var/tmp/netcage-storage`.
`netcage images` (READ) was added, but there is NO WRITE path, so
`podman build`/`pull` into the DEFAULT rootless store leaves the image invisible
to `netcage run` (which tries to pull it as a registry ref and fails/hangs). These
verbs are the write side, mirroring `netcage images`.

Behaviour:

- **`netcage build [args] -t <ref> <context>`** -> `podman --root <graphroot> build [args]`.
- **`netcage pull <ref>`** -> `podman --root <graphroot> pull <ref>`.
- **`netcage load [-i <tar>]`** -> `podman --root <graphroot> load [args]`.

Shape (mirror the existing pass-through verbs `images`/`exec`):

- They are **pass-through management verbs**: they do NOT egress and stand up NO
  jail, so they carry **NO `--proxy`**, NO preflight, and are NOT subject to the
  `run` flag allow-list. They route through the SAME `jail.Runner`/`ExecRunner.Run`
  seam every other podman call uses, so the `--root <graphroot>` injection is
  INHERITED automatically - do NOT hand-add `--root` in the argv builders
  (ADR-0013's single-seam rule; a per-builder `--root` is redundant + risks drift).
- **Args forwarded VERBATIM** to podman (like `exec`'s command tail via
  `ManageArgv`), NOT the single-label-scoped-name shape of `logs`/`inspect`/`stop`.
  Refuse NOTHING from podman's flag surface - there is no jail to breach, so `run`'s
  allow-list does not apply (a build-time `--network` is safe: it produces an
  IMAGE, and that image is STILL forced-egress-jailed when later `netcage run`; the
  jail is applied at run, not build - same declarative-re-gating logic as
  ADR-0012's `commit --change`).
- **The ONE refusal: a user-supplied `--root`** (in any form: `--root x`,
  `--root=x`) is REFUSED with a clear message - netcage OWNS the store location, and
  honouring a user `--root` would re-split the store this fix exists to unify
  (consistent with how `run` owns `--network`/`--name`). This is the single
  fail-closed guard on these otherwise-verbatim verbs.
- **No label scoping / no `guardManaged`.** These operate on IMAGES, not
  netcage-run-labelled containers, so the `netcage.managed` guard does not apply
  (mirroring `images`, which is also unguarded). Forward straight to podman.

Record in the done record: the `--root`-refusal rationale + why build-time
`--network` is safe (jail applied at run). Add a ONE-LINE pointer to ADR-0013's
Consequences ("the write side - build/pull/load - completes the store contract").
No new ADR (this completes ADR-0013's store contract; the read verb existed, this
adds the write verbs).

## Acceptance criteria

- [ ] `netcage build`, `netcage pull`, `netcage load` are accepted subcommands
      that forward to `podman <verb> <args...>` against the netcage store (the
      `--root <graphroot>` is present via the shared seam, NOT hand-added per
      builder), with their args passed VERBATIM.
- [ ] They carry NO `--proxy` and run NO preflight / NO jail (like `images`/`ps`);
      a run-time proxy is neither required nor consulted.
- [ ] A user-supplied `--root` (`--root x` or `--root=x`) is REFUSED with a clear
      message naming that netcage owns the store location; every OTHER podman flag
      is forwarded verbatim (no allow-list).
- [ ] They are UNGUARDED (no `netcage.managed` label check) - they act on images,
      mirroring `netcage images`.
- [ ] Unit tests (no podman): the built argv for each of build/pull/load (verb +
      verbatim args, and that the seam yields `--root <graphroot>` before the
      subcommand), and the `--root`-refusal path - mirroring the existing manage
      arg-builder + refusal tests.
- [ ] One podman-gated (`integration`) test, `build` ONLY: `netcage build -t
      <unique-ref> <tiny-context>` then a subsequent netcage store read/run SEES
      the image (proving build + run share ONE store - the end-to-end regression
      proof). `pull`/`load` are unit-argv-tested only (same seam; `pull` also needs
      flaky registry egress).
- [ ] **Shared-write isolation:** the integration test writes an IMAGE into the
      store, so it MUST use a unique image tag, isolate the store under a scratch
      `NETCAGE_GRAPHROOT` (as the graphroot task's tests do), and `t.Cleanup` must
      `podman --root <store> rmi -f <ref>` (or `system reset --force` the scratch
      store) even on failure, so it cannot orphan an image or touch the real store.

## Blocked by

- None - can start immediately. Builds ONLY on shipped code: the graphroot seam
  (`ExecRunner.Run` + `podmanGlobalArgs`, #19), the `managementVerbs` set + the
  `manage.Run` dispatch, and the verbatim `ManageArgv` capture (all on `main`).

## Prompt

> Goal: add `netcage build`/`pull`/`load` - the WRITE side of the netcage image
> store - so `netcage run <locally-built-image>` works again. This fixes a v0.7.0
> regression: the graphroot move (#19, ADR-0013) relocated podman's store to
> `/var/tmp/netcage-storage` (injected as `--root` at the `ExecRunner.Run` seam),
> which added a READ verb (`netcage images`) but no write path, so a `podman build`
> into the default store is invisible to `netcage run`.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm the graphroot `--root` is still injected at the single
> `ExecRunner.Run` seam via `podmanGlobalArgs` (so a new verb inherits it for
> free); confirm `managementVerbs` (in `internal/cli`) is the verb set + that
> management verbs return early with `ManageArgv = args[1:]` (no proxy, verbatim
> positionals); and that `manage.Run` (in `internal/manage`) dispatches verbs, with
> `images` as the UNGUARDED bare pass-through to mirror. If any landed differently,
> adapt or route to needs-attention.
>
> Domain (see CONTEXT.md + ADR-0013): netcage is a pure podman client through the
> `jail.Runner` seam; the graphroot (`--root`) is the username-free store at
> `/var/tmp/netcage-storage` where images + containers live. `netcage images` is a
> thin `podman --root <graphroot> images` pass-through; these verbs are its write
> siblings.
>
> Where to look / seams: add `build`/`pull`/`load` to `managementVerbs`
> (internal/cli) so they route with NO proxy/preflight/allow-list and their args
> flow through as `ManageArgv` verbatim; add their cases to `manage.Run`
> (internal/manage) as UNGUARDED pass-throughs (no `guardManaged` - they act on
> images, like `images`), building `podman <verb> <verbatim-args>` and streaming it.
> The `--root <graphroot>` is ALREADY prepended by `ExecRunner.Run` - do NOT
> hand-add it. Add the ONE guard: refuse a user-supplied `--root` (both `--root x`
> and `--root=x`) with a clear message. Test at the argv seam (assert the built
> `podman <verb>` argv + the `--root` refusal, no podman) + one podman-gated `build`
> round-trip (unique tag, scratch `NETCAGE_GRAPHROOT`, `t.Cleanup` rmi -f even on
> failure).
>
> Preserve the invariants: these verbs stand up NO jail and MUST NOT (no netns, no
> firewall, no `--proxy`); the store stays SINGLE (refuse user `--root` so it cannot
> be re-split); the graphroot `--root` is inherited from the seam, never duplicated
> per builder (ADR-0013). Refuse NOTHING ELSE from podman's flag surface (no jail to
> breach; a build-time `--network` is safe because the jail is applied at `run`, not
> `build`).
>
> RECORD in the done record: the `--root`-refusal rationale + why build-time
> `--network` is safe; add a one-line pointer in ADR-0013's Consequences. An ADR is
> NOT warranted (this completes ADR-0013's store contract - read verb existed, add
> the write verbs - a straightforward pass-through, not a hard-to-reverse decision).
> Done = `netcage build -t <ref> .` then `netcage run <ref>` finds the image (one
> store); build/pull/load forward verbatim, refuse only user `--root`, carry no
> proxy/jail, are unguarded; tests cover the argv + the refusal + a podman-gated
> build round-trip with unique tag + store isolation + cleanup.
