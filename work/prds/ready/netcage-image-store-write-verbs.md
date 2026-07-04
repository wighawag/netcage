---
title: netcage image-store WRITE verbs (build / pull / load) - restore `netcage run <locally-built-image>` after the graphroot move partitioned the store
slug: netcage-image-store-write-verbs
---

> Launch snapshot - records intent at creation, NOT maintained. Current truth:
> `docs/adr/` (decisions) + the code; remaining work: `work/tasks/`. Settles to
> Problem / Solution / User Stories / Out of Scope once tasked.

## Problem Statement

**This fixes a v0.7.0 REGRESSION.** The graphroot relocation
(`relocate-graphroot-to-var-tmp-single-store`, #19, ADR-0013) correctly moved
podman's store to a username-free `/var/tmp/netcage-storage`, injected at the
`ExecRunner.Run` seam so EVERY netcage podman call carries `--root <graphroot>`.
That closed the operator-username leak (Leak 2) - but it SILENTLY PARTITIONED the
image store: netcage now runs from a store that NOTHING except its own sidecar
bootstrap populates.

So any workflow that supplies its OWN tool image is now broken:

```sh
podman build -t localhost/x/tool:latest .            # lands in the DEFAULT rootless store
netcage run ... localhost/x/tool:latest echo hi      # netcage looks in /var/tmp/netcage-storage
# => "Trying to pull localhost/x/tool:latest..." -> pull failure (image not in the netcage store);
#    interactively this reads as a HANG during the 3x retry before stdio attaches.
```

This USED TO WORK before the move (build store == run store). It is the general
`netcage run <my-locally-built-image>` contract, and anon-pi (which builds its pi
image with plain `podman build` then `netcage run`s it) is the motivating live
break (live-reproduced against netcage 0.7.0; the reproducing session's
observation was consumed into this prd).

Repro:

```sh
podman build -t localhost/x/tool:latest -f Dockerfile .   # default rootless store
netcage run --proxy socks5h://127.0.0.1:1080 localhost/x/tool:latest echo hi
# => "Trying to pull localhost/x/tool:latest..." -> pull failure (image is in the
#    default store; netcage looks in /var/tmp/netcage-storage)
# workaround that unblocks (the reach-around this prd removes):
podman save localhost/x/tool:latest | podman --root /var/tmp/netcage-storage load
```

**The structural gap:** the graphroot move added a READ verb into netcage's store
(`netcage images` -> `podman --root <graphroot> images`) but NO WRITE path. A
caller's only options today are ugly reach-arounds that hardcode netcage's private
path (`podman --root /var/tmp/netcage-storage build ...`, or
`podman save <img> | podman --root /var/tmp/netcage-storage load`), which forces
the caller to know an internal netcage implementation detail - exactly the
coupling the single-store seam was meant to keep INSIDE netcage.

## Solution

Add the WRITE side of the netcage image store as thin, pass-through management
verbs, mirroring the existing `netcage images` (which already pass-throughs
`podman --root <graphroot> images`). Because they route through the same
`ExecRunner.Run` seam, the `--root <graphroot>` injection applies AUTOMATICALLY -
so they write into the SAME store `netcage run`/`netcage images` read, with no
graphroot knowledge required from the caller.

- **`netcage build [podman-build-args] -t <ref> <context>`** ->
  `podman --root <graphroot> build ...`. Build a Dockerfile into the netcage
  store. (anon-pi's motivating path.)
- **`netcage pull <ref>`** -> `podman --root <graphroot> pull <ref>`. Pull a
  registry ref into the netcage store.
- **`netcage load [-i <tar>]`** -> `podman --root <graphroot> load ...`. Load a
  `podman save` tar into the netcage store.

Shape (mirrors the existing pass-through verbs):

- They are **pass-through management verbs** (like `images`/`ps`): they do NOT
  egress and stand up NO jail, so they carry **NO `--proxy`** and NO preflight,
  and are NOT subject to the run flag allow-list. Their positionals + flags pass
  through to podman VERBATIM (like `exec`'s command tail via `ManageArgv`), NOT
  the single-label-scoped-name shape of `logs`/`inspect`/`stop`.
- **No label scoping / no `guardManaged`.** Unlike the container verbs
  (`logs`/`exec`/`rm`), these operate on IMAGES, not netcage-run-labelled
  containers, so the `netcage.managed` guard does not apply (mirroring `images`,
  which is also unguarded). They simply forward to podman against the netcage
  store.
- **`--root` is inherited from the seam, never hand-added** to the argv builders
  (ADR-0013's single-seam rule): a per-builder `--root` would be redundant and
  risk drift; the `ExecRunner.Run` injection already prefixes it.

### Naming (satisfies ADR-0012's invariant)

`build` / `pull` / `load` are all REAL podman verbs - and that is CORRECT here,
NOT a violation. ADR-0012's rule is "a netcage-only verb must never shadow a
podman verb with a DIFFERENT meaning." These are faithful PASS-THROUGHS that mean
exactly what podman means (just scoped to netcage's store), so they belong to the
podman-MIRRORING category (`images`/`ps`/`logs`/`exec`/`commit`), not the
netcage-only category (`verify`/`detect-proxy`/`setup-default`). Same-name +
same-meaning is the intended pattern for pass-throughs.

### Rejected alternative (recorded so it is not re-litigated)

- **`netcage run` falling back to the DEFAULT store on a store-miss:** REJECTED.
  It would re-introduce the username-bearing `/proc/self/mountinfo` paths for that
  image - undoing ADR-0013 (Leak 2) for exactly the case it protects. The write
  verbs put the image into the netcage store instead, keeping the store single +
  username-free.
- **A `netcage graphroot` / `--print-graphroot` query** (so callers do
  `podman --root "$(netcage graphroot)" build ...`): weaker - it still leaks the
  "you must build into our store" coupling to every caller and makes them wire the
  `--root` themselves. The write verbs own that coupling inside netcage. (A
  graphroot query could still be a small future nicety, but it is not the fix.)

## User Stories

1. As a tool-image author, after `netcage build -t localhost/x/tool:latest .`, a
   `netcage run localhost/x/tool:latest` finds the image (same store) and runs it -
   no reach-around, no hardcoded `/var/tmp/netcage-storage`.
2. As a user with a registry image, `netcage pull <ref>` puts it into netcage's
   store so `netcage run <ref>` uses it without a run-time pull.
3. As a user with a `podman save` tar, `netcage load -i img.tar` loads it into
   netcage's store.
4. As the anon-pi maintainer, anon-pi builds its pi image via `netcage build`
   (into netcage's store) instead of `podman build` + a
   `podman save | podman --root <hardcoded> load` reach-around.
5. As any user, these verbs need no `--proxy` (they do not egress) and never
   touch the jail / netns / firewall.
6. As a user, `netcage images` (read) and `netcage build`/`pull`/`load` (write)
   operate on ONE store, so what I write is what `netcage run` reads.

## Out of Scope

- Changing the graphroot decision (ADR-0013 stands: single username-free store).
- Any `netcage run` fallback to the default store (rejected above - would undo the
  username hardening).
- Label-scoping the image verbs (images are not per-run-labelled; mirrors the
  unguarded `images`).
- A `netcage graphroot`/`--print-graphroot` query (possible future nicety, not
  this fix).
- anon-pi's own switch to `netcage build` (that is an anon-pi-repo change, out of
  THIS repo's scope; this prd just makes the verb available).

## Resolved decisions (grilled 2026-07-04)

All open questions resolved; ready to task.

- **ONE task** (`image-store-write-verbs`) covering all three verbs: they are the
  same thin-pass-through change applied three times, all editing `internal/cli` +
  `internal/manage`, so splitting them would only add merge-conflict churn for no
  isolation benefit; "the write side of the store" is one coherent capability.
- **Verbatim pass-through, refuse nothing EXCEPT a user-supplied `--root`.** No
  allow-list (unlike `run`): these verbs stand up NO jail, so there is nothing to
  breach - filtering would cargo-cult `run`'s security model onto an operation it
  does not apply to. `podman build`'s large/evolving flag surface is forwarded
  verbatim (so `netcage build` == `podman build`, scoped to the store). Even
  build-time `--network` is safe: a build produces an IMAGE; that image is STILL
  forced-egress-jailed when later `netcage run` (the jail is applied at run, not
  build - same declarative-is-re-gated logic as ADR-0012's `commit --change`).
  The ONE refusal: a user-supplied `--root` is REFUSED with a clear message
  (netcage owns the store location; honouring it would re-split the store this fix
  exists to unify - consistent with how `run` owns `--network`/`--name`).
- **Tests:** unit-test the argv for all three verbs + the `--root` refusal (no
  podman, mirroring the manage arg-builder tests). ONE podman-gated integration
  test, `build` ONLY: `netcage build -t <unique-ref> <tiny-context>` then assert a
  subsequent netcage store read/run SEES it (the end-to-end regression proof that
  build and run share one store). Behind the `integration` tag, unique tag,
  `t.Cleanup` `rmi -f` even on failure, `NETCAGE_GRAPHROOT` scratch isolation as in
  the graphroot task. `pull`/`load` are unit-argv-tested only (their store-write
  property is the SAME seam the build integration test already proves; `pull` also
  needs flaky registry egress).
- **No new ADR.** This completes ADR-0013's store contract (it added the store +
  the read verb `images`; this adds the write verbs into the same store). A
  done-record note + a one-line pointer added to ADR-0013's Consequences suffices;
  the `--root`-refusal + build-time-network-is-safe rationale go in the done record.

## Task

ONE task in `work/tasks/`:

- `image-store-write-verbs` (blockedBy: []; covers 1-6): add `build`/`pull`/`load`
  to the pass-through management verbs, forwarding args verbatim to
  `podman --root <graphroot> <verb> ...` through the existing `ExecRunner.Run` seam
  (so `--root` is inherited, never hand-added), unguarded (images are not
  per-run-labelled), no proxy/preflight, refusing only a user `--root`. Builds only
  on shipped code (the graphroot seam, `managementVerbs`, `ManageArgv`).
