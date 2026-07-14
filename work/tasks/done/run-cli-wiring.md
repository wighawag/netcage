---
title: Wire `netcage run` to the jail engine (CLI integration)
slug: run-cli-wiring
spec: netcage
blockedBy: [jail-run-forced-egress, teardown-invariant]
covers: [1, 11, 12]
---

## What to build

Wire the `netcage run` subcommand to actually stand up the jail. The jail engine
(`internal/jail.Run`), the forced-egress topology, the DNS forwarder, the leak-test, and the
teardown invariant are all built and green; `run` currently only parses + preflights, then no-ops
with a non-zero exit. This task connects the parsed CLI `Command` to `jail.Run` so a real wrapped
tool runs through the jail.

End-to-end thin path:

- Map the parsed `cli.Command` (proxy, image, post-`--` tool argv) to a `jail.Config` and call
  `jail.Run` under the SIGINT-cancellable context already wired in `main.go` (so Ctrl-C tears down,
  per `teardown-invariant`).
- **Detect the host-loopback proxy case** (`127.0.0.1`/`::1`/`localhost`) and set
  `ProxyOnHostLoopback` so the sidecar gets the pasta map + reachback narrowing; a remote proxy
  needs neither (ADR-0002).
- **Pass through mounts** (`-v`/`--volume`, story 11) and the tool argv (story 12) so the tool is
  usable for real work; the tool image is wrapped UNCHANGED.
- Propagate the tool's exit code as `netcage`'s exit code (the wrapped tool's result is the run's
  result), and surface the reachback diagnostic (story 14) and other jail errors clearly.

This MUTATES THE SYSTEM (it stands up the jail). The jail engine's own tests already cover the
forced-egress/teardown behaviour against the fixture; this task's tests cover the CLI mapping
(parse -> jail.Config) at the unit boundary, plus the exit-code propagation.

## Acceptance criteria

- [ ] Tests written FIRST: parsing `run --proxy ... --image X -v a:b -- tool args` maps to a
      `jail.Config` with the right proxy, `ProxyOnHostLoopback` (true for a loopback proxy, false
      for a remote one), image, mounts, and tool argv.
- [ ] `netcage run` calls `jail.Run` and propagates the wrapped tool's exit code as its own.
- [ ] `-v`/`--volume` mounts and the post-`--` tool argv pass through to the wrapped tool unchanged
      (an arbitrary existing image is wrapped with no changes, stories 11/12).
- [ ] Host-loopback vs remote proxy is detected and drives `ProxyOnHostLoopback` (ADR-0002).
- [ ] SIGINT during a run tears the jail down (inherits the `teardown-invariant` wiring; no new
      residue path introduced).
- [ ] Tests cover the new behaviour; the CLI-mapping tests need no podman (pure mapping), and any
      system-mutating test is podman-gated and leaves no residue.

## Blocked by

- `jail-run-forced-egress`, `teardown-invariant` — both landed; `run` consumes `jail.Run` + the
  teardown wiring they built.

## Prompt

> Goal: make `netcage run` actually run the wrapped tool through the jail. Read `CONTEXT.md` (jail,
> forced egress, reachback, socks5h), ADR-0002 (host-loopback via pasta), and the done records of
> `jail-run-forced-egress` + `teardown-invariant`. The jail engine (`internal/jail.Run`), DNS
> forwarder, leak-test, and teardown are built and green; `run` just needs wiring.
>
> Write the mapping test FIRST: a parsed `run` command (proxy + image + `-v` mounts + post-`--`
> argv) yields the right `jail.Config`, with `ProxyOnHostLoopback` true for a loopback proxy and
> false for a remote one. Then wire `main.go` to call `jail.Run` under the existing
> SIGINT-cancellable context, parse `-v`/`--volume` into `Config.Mounts`, and propagate the tool's
> exit code.
>
> "Done" means `netcage run` stands up the jail, runs the wrapped tool with mounts/args passed
> through, exits with the tool's exit code, detects host-loopback vs remote proxy, and tears down on
> Ctrl-C. RECORD non-obvious decisions (e.g. the exit-code mapping for jail-setup failures vs tool
> non-zero exits) per the task-template guidance.

## Done record (2026-06-30)

Wired `netcage run` to `jail.Run` in `main.go` (`runRun`), under the existing SIGINT-cancellable
context so Ctrl-C tears the jail down. `cli.Command` gained `Mounts` (parsed from `-v`/`--volume`,
incl. `--volume=`/`-v=` forms) and a `ProxyOnHostLoopback()` helper (true for `127.0.0.1`/`::1`/
`localhost`, false for a remote proxy). Verified live: a wrapped `wget` through `netcage run`
against the fixture returned the proxy exit IP `127.0.0.2` with exit 0, no residue.

Non-obvious in-scope decisions:

- **Exit-code mapping.** A jail SETUP failure (sidecar/nft/reachback/DNS-forwarder) exits `1` with a
  clear stderr message. A wrapped tool that RAN but exited non-zero has THAT exit code propagated as
  netcage's own (the wrapped tool's result is the run's result), backed by
  `TestJail_PropagatesToolExitCode`. So `exit 42` in the tool makes `netcage run` exit 42, while a
  jail that could not stand up exits 1 (never 0, never a leak).
- **Host-loopback detection lives on `cli.Command`** (not duplicated in `main`), so the run path and
  any future caller share one definition matched to ADR-0002's pasta-reachback case.
- The tool's stdout is printed to netcage's stdout; jail errors go to stderr. Mounts flow straight
  through to `jail.Config.Mounts` -> `podman -v` (the jail already passed them through).
