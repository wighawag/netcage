---
title: Parse the `netcage ports <container> [--json]` verb surface (proxyless)
slug: ports-verb-cli-parse
prd: ports-verb-list-jail-listeners
blockedBy: []
covers: [5, 6]
---

## What to build

The CLI-parse layer for the new `ports` verb: a thin vertical slice through `internal/cli` alone (file-orthogonal to the parser and the wiring package), unit-tested without podman.

`netcage ports <container> [--json]` parses into a `Command` with its own tiny surface, mirroring how `detect-proxy` / `setup-default` / `forward` are parsed (a dedicated parse function, NOT run through the run flag allow-list):

- Exactly one positional: the netcage container NAME. Zero or two+ positionals is a loud usage error.
- The sole flag `--json` (boolean): emit the machine-readable listener contract instead of the human table. Reuse the existing `Command.JSON` field (already used by `detect-proxy --json`) so there is one spelling.
- NO `--proxy` (it does not egress; a `--proxy` is a usage error, not silently ignored), and it is NOT subject to the run allow-list or the proxy preflight. Add `ports` to the proxyless set (`IsProxyless`) so `Preflight` skips it, alongside the management verbs / detect-proxy / setup-default / forward.
- Unknown flags refused (fail-closed on the unknown), consistent with the rest of the surface.

Routing `ports` to its handler (the `internal/ports` package) is the wiring task; here it is enough that `Parse` produces the correct `Command` and that `main`'s dispatch recognises the verb name (a stub handler is acceptable if the wiring task owns the real dispatch, but the parse + validation must be complete and tested).

## Acceptance criteria

- [ ] `netcage ports <container>` parses to a `ports` command carrying the container name; `--json` sets the JSON flag.
- [ ] Zero / two+ positionals, `--proxy`, and unknown flags are all refused loudly.
- [ ] `ports` is treated as proxyless (no proxy resolution, no preflight), like the management verbs / detect-proxy / setup-default / forward.
- [ ] Tests cover the parse surface (positional required, `--json`, refusals) mirroring the existing `internal/cli` parse-test style (pure parsing/validation, no podman, no system mutation).

## Blocked by

- None — can start immediately. (File-orthogonal to `proc-net-tcp-listener-parser`; the wiring task depends on BOTH.)

## Prompt

> Self-contained. Goal: add the `netcage ports <container> [--json]` verb to the CLI PARSE layer, so an operator/agent has a discoverable, well-formed, proxyless surface for listing a jail's open TCP listeners. Parse + validation ONLY; the enumeration MECHANISM is a separate task.
>
> FIRST check against current reality (launch snapshot): read `internal/cli/cli.go` - the `Command` struct (note the existing `JSON` field used by `detect-proxy`), `Parse`/`ParseWithEnv`, `parseDetectProxy` / `parseSetupDefault` / `parseForward` (the tiny-surface proxyless verb pattern to mirror), and `IsProxyless` (how a verb opts out of the proxy preflight). Confirm these shapes still hold.
>
> Domain + the decision: the prd `work/prds/ready/ports-verb-list-jail-listeners.md`. `ports` is proxyless (it only reads `/proc`, sends no traffic), so it carries no `--proxy` and is not preflighted, exactly like `detect-proxy`. Reuse the existing `Command.JSON` field for `--json` (one spelling for the machine contract).
>
> Where to look: `parseDetectProxy` for the `--json`-only proxyless pattern; `parseForward` for a `<container>` positional verb; `IsProxyless` / the proxyless set. Seam to test at: `ParseWithEnv` (parse + validation cases), mirroring the existing cli parse tests.
>
> "Done" means: the parse surface is complete and validated, `ports` is proxyless, and the tests mirror the existing `internal/cli` style. Record any non-obvious in-scope decision (e.g. the `Command` field carrying the container name for `ports`) so the wiring task consumes it unambiguously.
