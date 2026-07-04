---
title: Relocate podman graphroot to a username-free /var/tmp path, injected once at the Runner seam so every netcage podman call shares one store
slug: relocate-graphroot-to-var-tmp-single-store
prd: jail-host-identity-hardening
blockedBy: []
covers: [3, 4, 5]
---

## What to build

Make netcage select a username-free podman graphroot under `/var/tmp` so the host USERNAME stops leaking, applied so uniformly that every netcage subcommand shares ONE store.

Today rootless podman's default graphroot is `~/.local/share/containers/storage`, so the overlay lowerdir/upperdir SOURCE paths that appear in the container's `/proc/self/mountinfo` embed `/home/<user>`, leaking the operator's account name. Pointing podman at a graphroot under `/var/tmp` (world-writable, sticky, no root needed, disk-backed so it survives reboots and preserves kept containers + the image cache exactly like today) makes those paths username-free.

**The critical part is WHERE the selection is injected.** `--root`/`--runroot` are podman GLOBAL flags that must precede the subcommand (`podman --root <path> run ...`, never `podman run --root <path>`). netcage builds podman argv in MANY places: the jail package (sidecar/tool run + start builders, and the inspect/exec/rm/verify/teardown call sites) AND the manage package (the pass-through verbs, which build a RunSpec independently) AND the interactive raw-passthrough exec path. If the graphroot is bolted onto individual arg-builders, some invocations will be missed and the store will SPLIT: a container created by `netcage run` under `/var/tmp` would be INVISIBLE to `netcage ps`/`logs`/`start` (which would look in the default home store). So the store selection MUST be injected ONCE at the shared exec/Runner seam through which all these invocations flow, so it travels with every podman argv.

Decision (ADR-0013): use the global `--root <path>` flag at the Runner seam (NOT a `CONTAINERS_STORAGE_CONF`/`storage.conf` env, and NOT per-builder). Leave `--runroot` at its default (co-locating and wiping both produced `acquiring lock ... file exists` refresh noise in probes). Podman self-heals a missing graphroot (re-inits + re-pulls images on demand), so a `/var/tmp` cleanup costs only a re-pull, never a failure.

**Threading the path into a STATELESS runner (the real mechanism).** The shared seam is `jail.Runner` / `jail.ExecRunner`, and both jail AND manage go through it (`manage.Run` takes a `jail.Runner` and calls `r.Run(RunSpec{Name:"podman",...})`), so injecting there genuinely covers manage. BUT `jail.ExecRunner` is a STATELESS `struct{}` constructed inline as `jail.ExecRunner{}` at every entry (the CLI entrypoint constructs it for the run, start, and manage paths, the verify path constructs its own, and there is a default jail runner for the proxy-exit-IP probes). A stateless runner has NOWHERE to hold the graphroot path, so `ExecRunner{}.Run` cannot self-inject. Pick and implement ONE threading mechanism: (a) give `ExecRunner` a `GraphRoot` field, construct it ONCE at the CLI entrypoint from the resolved store path, and thread that single constructed runner through every `jail.Run`/`jail.Start`/`manage.Run`/`verify` call (replacing the inline `ExecRunner{}` literals); or (b) a decorator Runner that wraps another and prepends the global flags; or (c) a shared arg-prefix helper both jail and manage call to build the `["--root", path, <subcommand>, ...]` prefix. Whichever is chosen, EVERY inline `ExecRunner{}` construction site (including the verify path and the default proxy-exit-IP probe runner) must route through it, or that path silently uses the default home store.

## Acceptance criteria

- [ ] Every podman invocation netcage issues (jail run/start/teardown/verify/exec, the manage pass-through verbs, and the interactive path) carries the same `--root <username-free /var/tmp path>` as a global flag before the subcommand, and does NOT override `--runroot`.
- [ ] Integration: a jailed run's `/proc/self/mountinfo` contains no `/home/<user>` path (the username no longer leaks via storage paths).
- [ ] Integration (single-store proof): a container created by a `netcage run` is visible to a subsequent netcage-managed listing / operable by `netcage start`, proving the store is shared, not split.
- [ ] Unit: the shared seam applies the `--root` selection so a representative invocation from EACH builder family (jail run, jail start, a manage verb, the interactive exec, the verify path, and the proxy-exit-IP probe runner) carries it — asserted at the seam, not duplicated per builder.
- [ ] EVERY inline runner construction site is routed through the graphroot-carrying runner (no stray default-store `ExecRunner{}` left on any path: run, start, manage, verify, and the proxy-exit-IP probe).
- [ ] The `verify` forced-egress leak-test still passes unchanged.
- [ ] Tests that stand up real storage ISOLATE it under a temp/scratch graphroot and assert the developer's real default store (`~/.local/share/containers/storage`) is UNTOUCHED after the run (shared-write isolation rule). Clean up the temp store with `podman --root <tmp> system reset --force` (a plain `rm -rf` fails on the id-mapped overlay `diff/` tree).

## Blocked by

- None — can start immediately.

## Prompt

> Goal: relocate podman's graphroot to a username-free path under `/var/tmp` so the operator's USERNAME stops leaking via container `/proc/self/mountinfo`, injected at ONE seam so every netcage podman call shares a single store. This is Leak 2 of the jail host-identity hardening prd.
>
> Domain vocabulary (see `CONTEXT.md`): netcage is a pure podman client; ADR-0006 routes EVERY jail step through the Runner seam (podman argv only) precisely so netcage could drive a remote podman. The graphroot (podman `--root`) is where image layers + containers live.
>
> Why /var/tmp and why a global flag (see ADR-0013 + `work/notes/observations/jail-leaks-host-identity-metadata-not-network.md`, which carry live-tested provenance): `/var/tmp` is world-writable-sticky (no root, no provisioning helper), disk-backed (survives reboots, preserves kept runs per ADR-0009, unlike RAM-backed `/tmp`/`$XDG_RUNTIME_DIR`), and username-free. The `--root` GLOBAL flag is preferred over a `CONTAINERS_STORAGE_CONF` env because it crosses cleanly to a future remote podman (ADR-0006) and needs no on-disk config file. Rootful podman was REJECTED (would detonate the rootless design); mountinfo masking was REJECTED (unnecessary once the path is username-free, and it breaks tools that read mountinfo).
>
> Where to look: `internal/jail` — the `Runner` interface + `ExecRunner.Run` (where `Name:"podman"` + Args become the process; this is the single seam) and the `runPodman` helper; also `internal/manage` (its verbs build a `jail.RunSpec` and go through the same `jail.Runner`). Inject the `--root <path>` global flag so it precedes the subcommand for EVERY invocation. NOTE `jail.ExecRunner` is a stateless `struct{}` constructed inline (as `jail.ExecRunner{}`) at the CLI entrypoint for run/start/manage, in the verify path, and for the default proxy-exit-IP probe runner — so you cannot inject 'inside' `ExecRunner{}.Run` for free; you must thread the path in (a `GraphRoot` field constructed once + passed everywhere, a decorator runner, or a shared arg-prefix helper). Seams to test at: the exec seam (unit — assert the flag is present for a sample from each builder family, and that NO construction site is left on the default store) and the jail/verify integration path (mountinfo has no home path; a run-created container is visible to a subsequent listing).
>
> CRITICAL: do NOT add `--root` in individual arg-builders (`ToolRunArgs`, `SidecarRunArgs`, the manage verb builders) — that splits the store and breaks `netcage ps`/`start`. Inject once at the Runner/exec seam so it is impossible to miss an invocation.
>
> FIRST, check this task against current reality (drift check): confirm the Runner seam still funnels all podman calls (jail AND manage) through one `Name:"podman"`+Args exec; if manage or start diverged onto a different exec path, that changes where the single injection point is — surface it rather than half-applying.
>
> RECORD non-obvious in-scope decisions (the exact `/var/tmp` subpath naming; how the `--root` is threaded so both jail and manage inherit it) in the done record / PR; ADR-0013 owns the durable why.
