---
title: Fix the multi-user-host store collision - uid-scope the graphroot default + promote NETCAGE_GRAPHROOT to a supported optional override
slug: uid-scoped-graphroot-multi-user-fix
needsAnswers: true
---

> Launch snapshot - records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions, chiefly ADR-0017 + ADR-0013) + the code; remaining work: `work/tasks/`. The technical detail below seeds the tasking and is trimmed once tasked.

<!-- open-questions -->
<!--
  TRANSIENT BLOCK - stripped by the apply rung on full resolution.
  One open question blocks autonomous tasking (the changeset/verify convention drift). Resolve it, clear needsAnswers, and delete this block.
-->

## Open questions

1. **Does this repo use pnpm changesets, or the Go `.dorfl.json` verify?** The originating request specified a `pnpm changeset` + `pnpm format:check && pnpm changeset status --since=main && pnpm -r build && pnpm -r test` acceptance gate, but this repo's `.dorfl.json` verify is Go-only (`test -z "$(gofmt -l .)" && go vet ./... && go build ./... && go test ./...`) and there is NO `.changeset/` dir and no `package.json`. This PRD ASSUMES the Go verify is the real gate (honour what the repo runs). Confirm before tasking so a task does not add a changeset step that does not exist here. (Flagged as drift, below.)

<!-- /open-questions -->

## Problem Statement

**This is a bug fix.** netcage's container store lives at a FIXED literal `/var/tmp/netcage-storage` (ADR-0013). That single shared path is safe for ONE user per host but BREAKS the moment two different Unix accounts run netcage on the same host.

netcage never `mkdir`s the store: podman creates it lazily on first use (the "no provisioning, self-healing" property `/var/tmp` was chosen for). So the FIRST user to run netcage creates `/var/tmp/netcage-storage` owned by THAT user. A SECOND, different Unix user then hits a store directory owned by the first user, and rootless podman's per-user subuid-owned overlay tree cannot cohabit one path across two users: the second user collides with a confusing permission failure (or a tangled cross-user store). `/var/tmp`'s sticky bit protects only the top level, not the shared `netcage-storage` subdir.

The motivating deployment is anon-pi, which runs netcage AS A DIFFERENT Unix user (`netuser`). It does that to close the OTHER, un-fixed half of Leak 2 (ADR-0013): the `-v` bind-mount SOURCE paths. anon-pi must mount a home + project dirs into the jail, so it cannot follow ADR-0013's "mount from outside `$HOME`" advice; instead it runs as `netuser`, so those mount source paths (and the tool's mountinfo) read `/home/netuser/...`, a throwaway name, never the operator's real login name. But running netcage as `netuser` alongside a login user who already ran it trips the fixed-path collision.

Scope note: this is Leak 2 (the in-jail TOOL reading the operator's login NAME from mountinfo) only. It is NOT about hiding the store from other host processes (a login-user `find`/`grep`); that store-privacy threat model is explicitly out of scope.

## Solution

Uid-scope the graphroot default so netcage runs correctly as any Unix user, and promote the existing env override to supported (decision recorded in ADR-0017). From the user's perspective:

- **The default store path becomes `/var/tmp/netcage-storage-<uid>`** (numeric UID of the running user). Each user gets a distinct, self-owned store with ZERO config, so netcage "just works" as any user (including anon-pi's `netuser`); the multi-user collision is gone.
- A numeric uid in the path is fine for Leak 2 (Leak 2 is about the login NAME, not a uid; the in-jail tool sees `/var/tmp/netcage-storage-1000`, name-free). This is a conscious relaxation of ADR-0013's "no uid" aspiration, justified by multi-user correctness needing the uid and by uid-scoping keeping the store self-healing (an opaque random subdir would not be).
- **`NETCAGE_GRAPHROOT` is promoted from test-only to a supported OPTIONAL override** for callers who want an explicit path (a specific disk, a tmpfs, a deployment convention). The multi-user case no longer NEEDS it (the uid default handles it); it is a convenience, not a workaround.
- Every property `/var/tmp` was chosen for is preserved: no root, no provisioning, self-healing, disk-backed (kept containers + image cache survive reboots), cleared with `podman --root <path> system reset --force`.

No new plumbing (the ADR-0013 `--root` single seam already routes the one resolver everywhere), no change to forced egress, no loosening of the `manage` `--root` refusal, and netcage does NOT touch `-v` source paths (that half of Leak 2 is anon-pi's, via running as `netuser`).

## User Stories

1. As an operator on a multi-user host, I want netcage to work when a SECOND Unix user runs it after the first, so that I do not hit a confusing store-ownership permission failure. (This is the bug being fixed.)
2. As anon-pi, I want to run netcage AS a dedicated Unix user (`netuser`) without the store colliding with the login user's store, so that my run-as-`netuser` strategy (which scrubs the operator's real login name from the `-v` mount sources) actually works.
3. As a single-user operator, I want the store to keep behaving exactly as before (self-healing, disk-backed, under `/var/tmp`, cleared with `podman --root <path> system reset --force`), so that the fix changes nothing observable for me except the path now carries my uid.
4. As the operator, I want Leak 2 to stay closed: the in-jail tool must not learn my login NAME from the store path. A numeric uid in the path is acceptable; my account name is not.
5. As a maintainer, I want the store-cleanup docs and the `manage` `--root`-refusal message to describe the store generically (uid-scoped default or the override), so that they never print a fixed `/var/tmp/netcage-storage` path netcage no longer uses.
6. As an operator who wants an explicit store path, I want `NETCAGE_GRAPHROOT` to be a SUPPORTED override, so that I can point the whole store at a chosen path (a specific disk, a tmpfs) and rely on it across versions.
7. As a maintainer, I want a test that LOCKS the uid-scoped default (the resolver returns a name-free path under `/var/tmp` that carries the running uid when the env is unset; returns the override when set; the single `--root` seam still feeds every podman invocation), so that a future refactor cannot silently reintroduce the fixed-path collision or split the store.
8. As an anon-pi maintainer, I want netcage to run cleanly as a different user, so that anon-pi's run-as-`netuser` deployment is unblocked on the netcage side. (The `-v` source scrubbing stays anon-pi's job.)

### Autonomy notes (the two gate axes)

- **`humanOnly`: OMITTED.** This is a scoped bug fix with the design decided in ADR-0017 (uid-scoped default + promoted optional override, Leak-2-only motivation). Once the one convention question is answered it is straightforwardly agent-taskable; no human must drive the tasking.
- **`needsAnswers: true`:** SET, for the single Open question (the changeset/verify convention drift). Clear it once confirmed the Go `.dorfl.json` verify is the gate.

## Implementation Decisions

Decided at launch (durable rationale in ADR-0017; do not re-litigate):

- **Default becomes uid-scoped: `/var/tmp/netcage-storage-<uid>`** via `os.Getuid()`, resolved in the existing pure resolver (`internal/jail/graphroot.go`, `graphRoot()`). No `mkdir` added; podman keeps creating it lazily (self-heal preserved).
- **Numeric uid in the path is accepted** (name-free is what Leak 2 needs; an opaque random subdir would break self-heal). Conscious relaxation of ADR-0013's "no uid" aspiration.
- **Promote `NETCAGE_GRAPHROOT` to a supported OPTIONAL override** (unset => uid-scoped default; set => that path). Its code comment changes from "test-only / NOT a user-facing knob" to "supported optional override; also used by tests to isolate storage." One resolver, one store (never a second override var: a split-store precedence footgun against the ADR-0013 single-store invariant).
- **No new wiring.** The ADR-0013 `--root` single seam (`podmanGlobalArgs` at `ExecRunner.Run` + `jail.GraphRoot()` for the `forward` socat child) already routes the resolver everywhere. This changes only what `graphRoot()` returns by default.
- **`manage`'s `--root` refusal stays**, but its message must stop naming the fixed `/var/tmp/netcage-storage` literal and describe the store generically (uid-scoped default or override).
- **`--runroot` stays at podman's default.** It is `$XDG_RUNTIME_DIR/containers`, already per-user, so it never had the multi-user collision. Only `--root` uid-scopes.
- **netcage does NOT touch `-v` source paths.** That half of Leak 2 is closed by anon-pi running as `netuser`; out of scope here.

## Testing Decisions

Good tests assert the resolver + seam behaviour (mostly reshaping the existing graphroot unit tests from asserting a FIXED path to asserting a UID-SCOPED one):

- **Resolver default (unit, no podman):** with `NETCAGE_GRAPHROOT` unset, `graphRoot()` returns a path under `/var/tmp` that is name-free (no `/home/<user>`) AND carries the running uid (`os.Getuid()`). This REPLACES the current test that asserts the exact fixed literal.
- **Resolver override (unit):** with `NETCAGE_GRAPHROOT` set, `graphRoot()` returns it verbatim. (Already tested; reframe as the supported override.)
- **Multi-user distinctness (unit):** two different uids resolve to two different default paths (the property that fixes the collision). Exercise the resolver's uid input directly (inject/param the uid, or document that the seam reads `os.Getuid()`), not by actually switching users.
- **Single-seam contract (unit):** `podmanGlobalArgs` prepends `--root <resolved>` as a GLOBAL flag before the subcommand for EVERY podman argv across the builder families (already covered by the seam-family test; keep, it guarantees the whole store moves, never a split).
- **`--runroot` untouched (unit):** the argv never carries `--runroot` (already asserted; keep).
- **`manage` `--root` refusal (unit):** still rejects `--root`/`--root=` on build/pull/load, and its message no longer hardcodes `/var/tmp/netcage-storage` (assert the generic wording).
- **Existing graphroot integration tests stay green:** mountinfo references the (scratch) store, kept container lands in the scratch store. They already prove the relocation works end to end; the uid-scoped default does not change their scratch-`NETCAGE_GRAPHROOT` setup.
- **Docs updates** (README store path + cleanup) are part of the deliverable; no integration test needed for docs.

## Out of Scope

- **anon-pi's `-v` bind-mount SOURCE paths.** The other half of Leak 2, closed by anon-pi RUNNING AS `netuser` (source paths read `/home/netuser/...`). anon-pi's choice, not netcage's; netcage only runs correctly as whatever user launches it.
- **Hiding the store from other host processes (store privacy / Observer 2).** A different threat model, explicitly NOT a goal. No mode-700 enforcement, no world-readable warning, no path-permission validation. netcage runs the store where the uid default or override says; permissions are the environment's business.
- **Any change to forced egress or other ADR-0013 host-identity closures.** Only the store path's default shape changes.
- **Loosening the `manage` verbs' `--root` refusal.** Stays (only its message wording updates).
- **Uid-scoping `--runroot`.** Unnecessary (already per-user via `$XDG_RUNTIME_DIR`) and regressive (co-locating with root reintroduces lock-refresh noise).
- **An opaque random per-user store subdir (fully uid-free path).** Rejected: breaks self-heal. A numeric uid is name-free enough for Leak 2.
- **A `setup`/provisioning verb.** Not needed; the uid-scoped path is still podman-created lazily under sticky `/var/tmp`.

## Further Notes

- **Cross-repo dependency (explicit):** this BLOCKS anon-pi running netcage as `netuser` (without the fix, `netuser`'s store collides with the login user's on the shared `/var/tmp` path). anon-pi's `-v` source scrubbing (running as `netuser`, mounting `netuser`'s home/projects) is anon-pi's OWN half and is NOT fixed here.
- **Framing correction (from the driving idea note's review):** the original idea note (`work/notes/ideas/private-graphroot-for-dedicated-account.md`) framed this as a store-PRIVACY feature (hide the store from host processes running as the login user, a mode-700 "unfindable" path). That framing is WRONG for the actual need: the operator does not care about host-process discoverability (Observer 2); the only concern is Leak 2 (the in-jail tool reading the login NAME). The real problem is a multi-user COLLISION BUG in the fixed `/var/tmp` path, tripped by anon-pi running as `netuser` to scrub the `-v` mount-source login name. This PRD + ADR-0017 reframe it as that bug fix (uid-scoped default) plus a small promoted override, and delete the privacy spine. The idea note should be updated or retired to match.
- **Drift flagged against the idea note:**
  - The note assumed the relocation was about store privacy; corrected above (it is multi-user correctness / Leak 2).
  - The note left the naming fork open ("promote the env var or add a clearer name?"). ADR-0017 closes it: promote `NETCAGE_GRAPHROOT` (one resolver, one store invariant); and it is now an OPTIONAL override, because the uid-scoped default handles the multi-user case without it.
  - The note asked whether `--runroot`/transient state spills world-visible: resolved as irrelevant to the actual (Leak-2/multi-user) framing; `--runroot` is already per-user (`$XDG_RUNTIME_DIR`) and stays at podman's default.
- **Convention drift flagged (see Open question 1):** the request's `pnpm changeset` acceptance gate does not match this repo. `.dorfl.json` verify is Go-only; there is no `.changeset/` or `package.json`. A task must NOT add a pnpm/changeset step that does not exist here.
- **This is a DESIGN + DOCS deliverable at drafting time.** No code changes and no tasking were performed; the drafts (this PRD + ADR-0017) stop here for review.
