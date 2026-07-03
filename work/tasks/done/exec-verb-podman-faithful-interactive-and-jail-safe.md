---
title: Make `netcage exec` podman-faithful - honour -i/-t/-w/-e/-u with real interactive stdio, jail-safe
slug: exec-verb-podman-faithful-interactive-and-jail-safe
blockedBy: []
covers: []
---

## What to build

Make `netcage exec` a faithful mirror of `podman exec`. Today it is a thin
capture-only pass-through: `ExecArgs(name, cmd)` builds a bare `podman exec
<name> <cmd...>` with NO flags, and it runs through `stream()` which wires only
Stdout/Stderr (no TTY, no stdin). So `netcage exec <c> sh` / `netcage exec <c> pi`
cannot be an INTERACTIVE shell (pi/bash need a real terminal), and `netcage exec
-it <c> sh` mis-parses `-it` as the CONTAINER NAME (the dispatch takes args[0] as
the subject). netcage's identity is "podman-native", so `exec` dropping the exec
flags a user reaches for is a fidelity gap.

Bring `exec` up to podman parity, curated + jail-safe:

- **Honour the exec flags** `podman exec` takes: `-i`/`--interactive`,
  `-t`/`--tty`, `-w`/`--workdir <dir>`, `-e`/`--env KEY=VAL` (repeatable),
  `-u`/`--user <user>`. Parse them BEFORE the container name (a podman user writes
  `netcage exec -it -w /root <c> bash`), separate flags from the subject +
  command, and refuse UNKNOWN flags (fail-closed on the unknown, like `run`).
  These are all network/isolation-IRRELEVANT per the ADR-0010 vetting checklist
  (they only affect the exec'd process's tty/stdin/cwd/env/uid), so they are safe
  to pass through; a flag that could breach the jail (e.g. anything network/priv)
  is NOT in the allow-list.
- **Real interactive stdio for `-it`.** Reuse the existing raw-stdio path: the
  jail `RunSpec` already carries `Interactive bool` + `Stdin io.Reader` (used by
  `run -it` / `start -ai` via `toolRunSpec`/`toolStartSpec`). When `exec` is
  interactive, build the RunSpec with `Interactive: true` + `Stdin` wired
  (os.Stdin in production), so `podman exec -it` gets a real PTY + stdin
  passthrough instead of capture-only `stream()`. Non-interactive `exec` keeps
  the current capture/tee behaviour.
- **Jail-safe (the netcage-specific bit).** `exec` enters the container's EXISTING
  jailed netns (a plain `podman exec`, never `podman run --network ...`), so it
  cannot hand out a fresh, un-jailed network - that invariant is already true and
  must stay. ADD the guarantee that the jail is actually HEALTHY before exec'ing:
  if the target's sidecar is stopped (a kept pair at rest), a plain `podman exec`
  into the tool would run before the jail is up. Reuse `start`'s revive+verify
  machinery: ensure the sidecar is running and the firewall is verified (the same
  `verifyFirewall` fail-loud probe `netcage start` uses) BEFORE the exec, and
  re-exec the DNS forwarder if it is down - OR, if that is deemed out of scope for
  a single task, at minimum REFUSE to exec into a container whose sidecar is not
  running with a clear message ("run `netcage start <c>` first"), never a silent
  un-jailed-DNS exec. Decide and record which (revive-then-exec vs refuse-if-down)
  in the done record; revive-then-exec is the more podman-faithful and is
  preferred if it reuses start cleanly.
- Keep the scoping exactly as today: the `guardManaged` label check refuses a
  non-netcage container BEFORE the exec.

This is the FIRST of the netcage management-verb fidelity tasks (see
`work/notes/ideas/podman-fidelity-of-management-verbs.md` for the full sweep -
`logs -f`/`--tail`, `inspect --format`, `stop -t`, and the name-first parse fix
are a SEPARATE follow-up). It sets the "management verb curates its podman flags +
is jail-safe" precedent the `commit` task then follows, and both edit
`internal/manage`, so this lands first.

## Acceptance criteria

- [ ] `netcage exec -it <container> <cmd...>` runs `<cmd>` INTERACTIVELY in the
      container (real TTY + stdin passthrough via the RunSpec Interactive/Stdin
      path), so `netcage exec -it <c> sh` / `... bash` is a usable interactive
      shell - not capture-only.
- [ ] `netcage exec` honours `-i`/`-t`/`-w`/`-e`/`-u` (parsed BEFORE the container
      name, separated from the subject + command), passing them through to
      `podman exec` verbatim; an UNKNOWN flag is refused (fail-closed), with a
      message listing the accepted flags.
- [ ] `-w <dir>` sets the exec cwd; `-e KEY=VAL` (repeatable) sets env; `-u <user>`
      sets the user - each reaching the `podman exec` argv.
- [ ] Non-interactive `netcage exec <c> <cmd>` keeps the capture/tee behaviour
      (output returned/streamed), unchanged.
- [ ] The forced-egress invariant holds: `exec` enters the EXISTING jailed netns
      (never `--network`/a fresh netns), and it does NOT run before the jail is
      healthy - either the sidecar is revived + firewall-verified first (reusing
      `start`), or a container whose sidecar is down is REFUSED with a clear
      "start it first" message. A deliberately-down jail must NOT yield an exec
      with a working un-jailed network / live DNS.
- [ ] A non-netcage / unknown container is still refused (`guardManaged`) before
      any exec runs.
- [ ] Tests: unit tests for the exec flag parse + argv construction (the built
      `podman exec [flags] <name> <cmd>` argv, and that `-it` sets the RunSpec
      Interactive/Stdin path, WITHOUT executing podman - mirror the existing
      manage arg-builder + jail interactive-spec tests) and the unknown-flag +
      non-netcage refusals; a podman-gated (`integration`) test that
      `netcage exec` runs a command in a kept container in a given `-w` cwd with a
      passed `-e` env, and (if revive-then-exec is chosen) that exec into a
      STOPPED-sidecar kept container revives + verifies the jail first.
- [ ] **Shared-write isolation (podman is host-global state):** any integration
      test that creates a container MUST use a unique run-id name and clean it up
      via `t.Cleanup` / `podman rm -f --depend` even on failure, so it cannot
      orphan containers or collide with a concurrent run.

## Blocked by

- None. Builds on the shipped v0.4.0 `internal/manage` + `internal/jail` (the
  `RunSpec{Interactive,Stdin}` path from `run`/`start`, and `start`'s
  revive+verify). Sequenced FIRST among the fidelity tasks; the `commit` task
  `blockedBy` this one (both edit `internal/manage`).

## Prompt

> Goal: make `netcage exec` faithful to `podman exec` - honour `-i`/`-t`/`-w`/
> `-e`/`-u` with a REAL interactive terminal for `-it`, while staying jail-safe
> (enter the existing jailed netns, and ensure the jail is healthy before
> exec'ing). netcage is podman-native; `exec` silently dropping the exec flags +
> having no TTY is a fidelity gap.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm `internal/manage`'s `exec` case still does
> `requireName` (args[0] = name, args[1:] = command) -> `ExecArgs(name, cmd)` (a
> bare `podman exec <name> <cmd>`, no flags) -> `stream()` (capture-only, no
> Interactive/Stdin); and that `internal/cli` captures a management verb's args
> verbatim as `ManageArgv = args[1:]`. Confirm the interactive raw-stdio path
> exists to reuse: `jail.RunSpec` has `Interactive bool` + `Stdin io.Reader`, and
> `run -it`/`start -ai` build it via `toolRunSpec`/`toolStartSpec`. Confirm
> `start` has the revive-sidecar + `verifyFirewall` + DNS-re-exec machinery to
> reuse for the jail-health guarantee. If any landed differently, adapt or route
> to needs-attention.
>
> Domain: netcage forces all egress through a socks5h proxy, fail-closed. A run
> makes a tun2socks sidecar (netns + firewall + DNS) and a tool container joined
> via `--network container:<sidecar>`; a non-`--rm` run leaves both kept +
> labelled `netcage.managed`. `netcage exec` runs a command INSIDE the existing
> tool container (its existing jailed netns), scoped by the label via
> `guardManaged`.
>
> Where to look / seams: `internal/manage` (add a curated exec-flag parse:
> separate `-i/-t/-w/-e/-u` from the subject + command, refuse unknown flags; build
> the podman argv; wire the interactive RunSpec when `-it`); reuse
> `jail.RunSpec{Interactive,Stdin}` (do NOT reinvent raw stdio - `run`/`start`
> already do it); reuse `start`'s revive+verify for the jail-health guarantee (or
> refuse-if-sidecar-down - decide + record). Test at the argv/spec seam without
> podman (assert the built `podman exec` argv + that `-it` sets Interactive/Stdin),
> plus the refusals; one podman-gated integration test for a real exec with `-w`/
> `-e` in a kept container (unique run-id + t.Cleanup rm -f --depend).
>
> Preserve the forced-egress invariant: `exec` enters the EXISTING jailed netns
> (never a fresh `--network`), the accepted flags are all network-irrelevant
> (ADR-0010 checklist) with unknown flags refused, and exec must not run before
> the jail is healthy (revive+verify, or refuse). A deliberately-down jail must
> never yield a working un-jailed exec.
>
> RECORD in the done record: which jail-health approach you took (revive-then-exec
> vs refuse-if-down) and why, and the exact exec flags you allow + why they pass
> the ADR-0010 checklist. An ADR is likely NOT warranted (a podman-faithful verb
> upgrade, not a hard-to-reverse decision) - a done-record note suffices unless the
> jail-health choice turns out to be a real, surprising trade-off. Done =
> `netcage exec -it -w <dir> -e K=V <c> bash` is a real interactive shell in the
> right cwd/env, unknown flags refused, the jail is healthy before exec, scoping +
> forced-egress intact, tests cover the argv/spec + refusals + a podman-gated exec.
