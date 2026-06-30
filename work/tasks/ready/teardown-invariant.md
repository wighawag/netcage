---
title: Teardown invariant — no leftover netns, nft, sidecar, or container after run
slug: teardown-invariant
prd: tooljail
blockedBy: [jail-run-forced-egress]
covers: [9]
---

## What to build

Guaranteed teardown of the jail, tested as an INVARIANT. A botched teardown is itself a leak/footgun (half-applied firewall state, an orphaned sidecar still holding a route), so this is a first-class property, not cleanup-as-afterthought.

The invariant: after `tooljail run` ends in ANY of three ways — **normal exit, error exit, and SIGINT (Ctrl-C)** — there is **no leftover netns, no leftover nft ruleset, no leftover redirector sidecar, and no leftover tool container**. Built on Go's `context` cancellation + signal handling + `defer` cleanup (one of the reasons the prd chose Go: the leak boundary is teardown correctness).

End-to-end thin path: a teardown routine wired to all three exit paths, plus tests that exercise each path and then assert ZERO residue (enumerate netns / nft rules / podman containers attributable to the run and assert none remain).

This MUTATES THE SYSTEM (creates then removes containers/netns/nft). Run with explicit confirmation, not unattended.

## Acceptance criteria

- [ ] Tests written FIRST and RED before the wiring: after normal exit, after an induced error, and after a delivered SIGINT, an enumeration finds NO run-attributable netns, nft rules, sidecar, or tool container.
- [ ] Teardown is wired to all three exit paths (normal / error / SIGINT) via context/signal/defer.
- [ ] The three teardown tests each assert zero residue afterward.
- [ ] Teardown is idempotent and best-effort-complete: a failure to remove one resource still attempts the others and surfaces the failure (no silent partial teardown).
- [ ] Tests cover the new behaviour; system-mutating tests isolate to throwaway containers/netns and assert the host is untouched after (no run-attributable residue).

## Blocked by

- `jail-run-forced-egress` — teardown removes exactly what the jail creates (sidecar, netns, nft, tool container).

## Prompt

> Goal: make jail teardown a guaranteed, tested invariant — after normal exit, error, AND SIGINT, NO leftover netns, nft rules, sidecar, or tool container. Read `CONTEXT.md` (jail, redirector, fail-closed) and the prd (story 9; the Go-for-teardown-correctness rationale and the run-attributable labeling seam now live in the `jail-run-forced-egress` task + ADRs, the prd's technical sections having been trimmed at tasking time).
>
> FIRST, check against current reality: confirm `jail-run-forced-egress` landed and what exactly it creates (sidecar/netns/nft/tool container); read its done-record/ADRs. Teardown must remove precisely those. If the set differs from what this task assumes, route to needs-attention.
>
> This MUTATES THE SYSTEM (creates then removes containers/netns/nft). Do NOT run unattended — get explicit confirmation before creating containers/netns/nft rules.
>
> Write the tests FIRST (testFirst is ON): for each of normal exit / induced error / delivered SIGINT, run the jail then enumerate run-attributable netns + nft rules + podman containers and assert NONE remain. Red until teardown is wired. Then wire teardown to all three paths via Go context cancellation + signal handling + defer, idempotent and best-effort-complete (one failed removal still attempts the rest and surfaces the error).
>
> "Done" means all three teardown tests are green (zero residue on every exit path), teardown is idempotent, and partial-teardown failures are surfaced not swallowed. RECORD non-obvious in-scope decisions (e.g. how resources are made run-attributable for enumeration) per the task-template guidance.
