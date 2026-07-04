---
title: forward host-port remap ([hostPort:]jailPort) - parse, wiring, docs
slug: forward-port-remap
prd: forward-host-port-remap
blockedBy: []
covers: [1, 2, 3, 4, 5, 6]
---

## What to build

Extend the shipped `netcage forward` verb so the port positional accepts an optional `[hostPort:]jailPort` remap, docker/kubectl-familiar, end-to-end (parse -> wiring -> start line -> docs). It is a small, single vertical slice: the change is localized to the forward verb's parse + the host bind port, with NO new package, NO ADR, and NO guardrail change.

Behaviour:

- `netcage forward <c> 3001` stays BYTE-IDENTICAL to today: host 3001 -> jail 3001. The bare single-port form is the zero-remap special case, so no existing invocation changes.
- `netcage forward <c> 8080:3001` binds host `<bind>:8080` and connects to in-jail `127.0.0.1:3001`.
- Split the second positional on a single `:`: zero colons => host == jail; exactly one colon => `hostPort:jailPort`; two or more colons (`1:2:3`) => LOUD usage error. Validate BOTH sides 1..65535 (reuse/extend the existing `parseForwardPort`); a non-numeric or out-of-range host side or jail side is a loud usage error. NOTE: use a plain `strings.Split(s, ":")` + count check, NOT `net.SplitHostPort` (both sides are bare port NUMBERS, no host address; `net.SplitHostPort` would mis-handle the count/IPv6 cases and is the wrong tool here).
- `--bind` semantics are UNCHANGED (`127.0.0.1` default, `0.0.0.0` the guardrailed warned opt-in, nothing else).
- The startup / running line names BOTH ports honestly: `forwarding http://127.0.0.1:8080 -> <container>:3001`.
- README host-access section updated to show the remap; if the `-p`/`--publish` refusal hint quotes the single-port form, update it to the `[hostPort:]jailPort` form.

Wiring notes (from the prd Implementation Decisions):

- `internal/cli`: `parseForward` splits `[hostPort:]jailPort`; add a `ForwardHostPort int` field on `Command` (default it to the jail port when no remap is given, so downstream is uniform). Keep `ForwardPort` as the JAIL/connect port.
- `internal/forward`: `Config` gains `HostPort`; `ListenArgs` binds `TCP-LISTEN:<hostPort>` while the connect side still reaches `127.0.0.1:<Port>` (the jail port). The start line in `Run` prints `http://<bind>:<hostPort> -> <container>:<Port>`.
- `main.go` `runForward` threads `cmd.ForwardHostPort` into `forward.Config.HostPort`.

The security surface is untouched: still NO OUTPUT/nft rule, TCP-only, exactly ONE in-jail port, netcage-managed-only (via the sidecar connector, unchanged), loopback-by-default, lifetime-bounded. Only the HOST bind port becomes independently choosable.

## Acceptance criteria

- [ ] `netcage forward <c> 3001` behaves exactly as before (host 3001 -> jail 3001); the bare form is unchanged.
- [ ] `netcage forward <c> 8080:3001` binds host `<bind>:8080` and connects to in-jail `127.0.0.1:3001`.
- [ ] Both port sides are validated 1..65535; a bad host side, bad jail side, or extra colons (`1:2:3`) is a loud usage error.
- [ ] `--bind` still parses alongside the remap with unchanged semantics (127.0.0.1 / 0.0.0.0 only).
- [ ] The running line names both the host port and the in-jail port (e.g. `forwarding http://127.0.0.1:8080 -> <c>:3001`).
- [ ] README host-access section (and the `-p` refusal hint if it quotes the single-port form) show the `[hostPort:]jailPort` form.
- [ ] Tests: the parse matrix (bare `3001`, `8080:3001`, `x:3001`, `70000:3001`, `0:3001`, `8080:x`, `8080:99999`, `1:2:3`, plus `--bind` alongside) AND a `ListenArgs` assertion that for `8080:3001` the host listener binds `:8080` and the connect side targets `127.0.0.1:3001` (and for the bare form both are the same port). Pure, no podman.
- [ ] `verify` (the forced-egress leak-test) is unaffected: the remap changes only the host bind port; no OUTPUT rule, TCP-only, one jail port unchanged.

## Blocked by

- None — can start immediately.

## Prompt

> Self-contained. Goal: extend `netcage forward` so its port positional accepts an optional `[hostPort:]jailPort` remap (docker/kubectl-familiar), so an in-jail server on :3001 can be exposed on a DIFFERENT host port (e.g. host :8080). The bare single-port form must stay byte-identical (backward compatible). Small, localized change: parse + the host bind port only; NO new package, NO ADR, NO guardrail change.
>
> FIRST check against current reality (launch snapshot): read `internal/cli/cli.go` `parseForward` (the current single-`<port>` positional, `parseForwardPort` validation 1..65535, `ForwardPort`/`ForwardBind`/`ForwardContainer` on `Command`, `resolveForwardBind`) and `internal/forward/forward.go` (`Config` with `Port` [the jail/connect port] + `Bind`, `ListenArgs` building `TCP-LISTEN:<port>` and the connect side `podman exec -i <sidecar> nc 127.0.0.1 <port>`, and `Run`'s start line), plus `main.go` `runForward`. Confirm these shapes still hold (the forward connector was recently changed to exec the SIDECAR, not the tool - that is orthogonal to this change; do not touch it).
>
> Domain + decision: the prd `work/prds/tasked/forward-host-port-remap.md` and ADR-0014 (the forward verb; loopback default, warned 0.0.0.0 opt-in, no OUTPUT rule, TCP-only, netcage-managed-only, lifetime-bounded - ALL unchanged here). The remap makes ONLY the host bind port independently choosable; the in-jail connect side stays `127.0.0.1:<jailPort>` in the shared netns.
>
> Where to look: `parseForward` + `parseForwardPort` (split `[hostPort:]jailPort`, add `ForwardHostPort`), `forward.Config`/`ListenArgs`/`Run` (add `HostPort`, bind hostPort, connect jailPort, name both in the start line), `main.go` `runForward` (thread the field), README host-access section + the `-p` deny hint. Seams to test at: `ParseWithEnv` (the parse matrix) and `ListenArgs` (host-bind vs connect-port split), pure, no podman.
>
> "Done" means: the remap works, the bare form is unchanged, both sides validated, the start line + README + `-p` hint name both ports, tests cover the parse matrix + the ListenArgs split, and `verify` stays green. Record any non-obvious in-scope decision (e.g. the `ForwardHostPort` default-to-jail-port choice, the exact colon-split error strings) in the done record.
