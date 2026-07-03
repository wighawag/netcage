---
title: Make the netcage management verbs faithful to their podman counterparts (flag + interactive-stdio fidelity)
slug: podman-fidelity-of-management-verbs
---

A read-only sweep of netcage's verb surface (as of v0.4.0) against what the
corresponding `podman` verb accepts, to find where netcage is NOT podman-faithful.
netcage's stated identity is "podman-native / a drop-in podman replacement", so a
management verb that silently drops the flags a podman user would reach for is a
fidelity gap. Findings below; the load-bearing one (`exec` interactivity) is
promoted to its own task.

## How the management verbs work today

- CLI (`internal/cli`) captures a management verb's args VERBATIM as
  `ManageArgv = args[1:]` (everything after the verb, in order).
- `manage.Run` (`internal/manage`) dispatches per verb:
  - `ps` / `images`: label-scoped listing, no subject, no flags.
  - `logs` / `inspect` / `stop`: `requireName` takes `args[0]` as the container
    name and **DISCARDS the rest** (`name, _, err`); the arg builder is a plain
    `podman <verb> <name>` with NO flags.
  - `exec`: `args[0]` = name, `args[1:]` = the COMMAND (passed verbatim).
  - `rm`: resolves the pair, `podman rm -f --depend <sidecar>`.
- ALL of them run through `stream()`, which wires only `Stdout`/`Stderr` (tee) and
  NEVER sets `Interactive`/`Stdin`. So no management verb has a real TTY / stdin.
- Scoping is the pre-verb `guardManaged` label check (correct; not a `--filter`).

## Gaps found (podman-faithful vs netcage-actual)

1. **`exec` is not interactive and takes no exec-flags (the big one -> its own
   task).** `podman exec` supports `-i`/`-t`/`-w`/`-e`/`-u`; netcage `exec` wires
   none, and `stream()` gives no TTY/stdin, so `netcage exec <c> sh`/`... pi`
   cannot be an interactive shell. Also `netcage exec -it <c> sh` would take
   `-it` as the container NAME (flags before the name are mis-parsed as the
   subject). The interactive `RunSpec{Interactive,Stdin}` mechanism that `run -it`
   / `start -ai` already use is right there to reuse. PROMOTED:
   `exec-verb-podman-faithful-interactive-and-jail-safe`.

2. **`logs` drops its flags.** `podman logs` supports `-f`/`--follow`,
   `--tail N`, `--since`/`--until`, `-t`/`--timestamps`. netcage `logs` discards
   everything after the name, so `netcage logs -f <c>` / `netcage logs --tail 50
   <c>` do nothing podman-ish (the flags are silently dropped or, if before the
   name, mis-parsed as the subject). `-f` (follow) in particular is a very common
   ask and needs the same interactive/streaming plumbing as exec (a long-lived
   attached stream).

3. **`inspect` drops `--format`/`-f`.** `podman inspect --format '{{...}}' <c>` is
   the single most common inspect use; netcage `inspect` discards it, so you only
   get the full JSON. (Low risk — all inspect flags are read-only/metadata — so
   this is safe to pass through per the ADR-0010 vetting checklist.)

4. **`stop` drops `-t`/`--time`.** `podman stop -t <secs> <c>` (grace period)
   is dropped; netcage `stop` is always the default grace. Minor.

5. **Flag-position parsing is name-first-only.** Because `requireName` assumes
   `args[0]` is the container, ANY leading flag (`netcage logs -f web`,
   `netcage exec -it web sh`) is mis-taken as the name. A podman user writes
   flags before the subject. The verbs need a small curated flag parse (per
   verb) that separates flags from the subject, mirroring how `run` curates its
   allow-list.

## The shape of the fix (shared across the verbs)

Each gap is the same shape as the `run`/`start` fidelity work already done:
curate a per-verb allow-list of the SAFE podman flags (all of these are
read-only / lifecycle / metadata -> network-irrelevant per ADR-0010's checklist,
so passing them through cannot open a leak), refuse unknown flags (fail-closed),
and for the STREAMING verbs (`exec` interactive, `logs -f`) reuse the
`RunSpec{Interactive,Stdin}` raw-stdio path instead of capture-only `stream()`.
Scoping stays the `guardManaged` label check. The forced-egress invariant is
untouched throughout (these verbs enter an EXISTING jailed netns or read
metadata; none create a network).

## Routing

- `exec` interactivity + flags -> PROMOTED to a task (the foundational verb; it
  also sets the "management verb honours podman flags + is jail-safe" precedent
  the `commit` task then follows, so it is sequenced FIRST among the netcage
  fidelity tasks).
- `logs -f`/`--tail`/`--since`, `inspect --format`, `stop -t`, and the
  name-first parse fix -> a SECOND fidelity task (or folded into the exec task's
  "curate per-verb flags" pattern once that lands). Left here as the captured
  survey until promoted; individually low-risk, collectively they are what makes
  netcage's verbs feel like podman.
