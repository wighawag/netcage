---
title: Parse the `netcage forward` verb surface and point the refused -p message at it
slug: forward-verb-cli-parse
prd: host-access-forward-verb
blockedBy: []
covers: [2, 3, 11, 12]
---

## What to build

The CLI-parse layer for the new `forward` verb, plus the `-p`/`--publish` refusal message update. This is a thin vertical slice through `internal/cli` alone (file-orthogonal to the spike and the wiring package), unit-tested without podman.

`netcage forward <container> <port>` parses into a new `Command` shape with its own tiny surface, mirroring how `detect-proxy` / `setup-default` are parsed (a dedicated parse function, NOT run through the run flag allow-list):

- Positionals: exactly `<container>` (a netcage container name) and `<port>` (a TCP port). Zero/one/three positionals, or a non-numeric / out-of-range port, is a usage error, loud.
- The sole flag `--bind <addr>` (and `--bind=<addr>`), defaulting to `127.0.0.1`. The ONLY other accepted value is `0.0.0.0`; any other bind address is refused loudly for now (a specific-interface bind is out of scope, prd Out of Scope).
- NO `--proxy` (it does not egress; a `--proxy` is a usage error, not silently ignored), and it is NOT subject to the run allow-list or the proxy preflight (add `forward` to the proxyless set alongside the management verbs / detect-proxy so `Preflight` skips it).
- Unknown flags refused (fail-closed on the unknown), consistent with the other verbs.

Separately, update the `-p` / `--publish` entries in `denyReasons` so the refusal message points the user at the safe path: "...to view an in-jail server on the host, use `netcage forward <container> <port>` (loopback by default)".

Routing `forward` to its handler (the `internal/forward` package) is the NEXT task; here it is enough that `Parse` produces the correct `Command` and that `main`'s dispatch recognises the verb name (a stub handler / not-yet-wired error is acceptable if the wiring task owns the real dispatch, but the parse + validation must be complete and tested).

## Acceptance criteria

- [ ] `netcage forward <container> <port>` parses to a `forward` command carrying the container name, the port, and the resolved bind (`127.0.0.1` default).
- [ ] `--bind 0.0.0.0` (and `--bind=0.0.0.0`) is accepted; any other `--bind` value is refused loudly; `--proxy`, unknown flags, and wrong positional counts / bad ports are refused loudly.
- [ ] `forward` is treated as proxyless (no proxy resolution, no preflight), like the management verbs / `detect-proxy`.
- [ ] The refused `-p` / `--publish` message now points at `netcage forward`.
- [ ] Tests cover the new parse surface AND the updated `-p` message, mirroring the existing `internal/cli` parse-test style (pure parsing/validation, no podman, no system mutation).

## Blocked by

- None — can start immediately. (File-orthogonal to `spike-socat-forward-into-jail-netns`; the wiring task depends on BOTH.)

## Prompt

> Self-contained. Goal: add the `netcage forward <container> <port>` verb to the CLI PARSE layer and repoint the refused `-p` message at it, so an operator has a discoverable, well-formed surface for host access to a jailed server. This task is parse + validation ONLY; the forward MECHANISM is a separate task.
>
> FIRST check against current reality (launch snapshot): read `internal/cli/cli.go` — the `Command` struct, `Parse`/`ParseWithEnv`, the `denyReasons` map (the `-p`/`--publish` refusal lives there), `IsProxyless`/`Preflight`, and the dedicated parse functions `parseDetectProxy` / `parseSetupDefault` (the pattern to mirror for a proxyless, non-preflighted, non-allow-list verb). Confirm these shapes still hold before building.
>
> Domain vocabulary + the decision: ADR-0014 (host access is a loopback-by-default `forward` verb, not a `-p` flag; `--bind 0.0.0.0` is a guardrailed opt-in) and `work/prds/tasked/host-access-forward-verb.md`. Guardrails this parse layer enforces: loopback default, `0.0.0.0` is the ONLY other accepted bind (a specific-interface bind is out of scope), no `--proxy`, unknown flags refused.
>
> Where to look: `parseDetectProxy` / `parseSetupDefault` for the tiny-surface, proxyless verb pattern; `IsProxyless` / the `managementVerbs` set for how a verb opts out of the proxy preflight; `denyReasons` for the `-p` message. Seams to test at: `ParseWithEnv` (the parse + validation cases) and the `-p`-refusal message assertion (mirror the existing deny-flag test).
>
> "Done" means: the parse surface is complete and validated, `forward` is proxyless, the `-p` message points at the verb, and the tests mirror the existing `internal/cli` style. Record any non-obvious in-scope decision (e.g. the exact `Command` field shape for the bind/port) so the wiring task consumes it unambiguously.
