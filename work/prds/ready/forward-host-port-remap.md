---
title: `netcage forward` host-port remap ([hostPort:]jailPort)
slug: forward-host-port-remap
taskedAfter: []
---

> Launch snapshot - records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked - they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

`netcage forward <container> <port>` (ADR-0014) uses a SINGLE `<port>` value for BOTH the host bind and the in-jail target, so you cannot expose an in-jail server on a DIFFERENT host port. If the jailed tool serves on `:3001` and the operator already has something on host `:3001` (or just wants it on `:8080`), there is no way to say "in-jail 3001, host 8080". `kubectl port-forward` and `docker -p` both support this remap with a familiar `hostPort:containerPort` syntax; `forward` should too.

## Solution

Extend the port positional to an optional `[hostPort:]jailPort` remap, podman/kubectl-familiar:

```
netcage forward <c> 3001         # host 3001 -> jail 3001  (UNCHANGED, backward compatible)
netcage forward <c> 8080:3001    # host 8080 -> jail 3001  (the remap)
```

- The bare single-port form stays BYTE-IDENTICAL to today (host port == jail port), so no existing invocation changes.
- `8080:3001` binds host `<bind>:8080` and connects to in-jail `127.0.0.1:3001`.
- BOTH sides are validated 1..65535 at the parse layer (mirroring the existing single-port validation + the `DirectAllow.Port` style); a non-numeric or out-of-range host side, a bad jail side, or extra colons (`a:b:c`) is a LOUD usage error.
- `--bind` semantics are UNCHANGED: `127.0.0.1` default, `0.0.0.0` the guardrailed, warned opt-in, nothing else accepted.
- The startup / running line names BOTH ports honestly: `forwarding http://127.0.0.1:8080 -> <container>:3001`.

No jail-safety guardrail changes: the forward still adds NO OUTPUT/nft rule, is TCP-only, exposes exactly ONE in-jail port, is netcage-managed-only, loopback-by-default, and lifetime-bounded. Only the HOST bind port becomes independently choosable; the in-jail connect side is unchanged in kind.

## User Stories

1. As an operator whose jailed tool serves on `:3001` but whose host `:3001` is taken, I want `netcage forward <c> 8080:3001` to expose it on host `:8080`, so a host-port collision does not block me.
2. As an operator, I want `netcage forward <c> 3001` to behave EXACTLY as before (host 3001 -> jail 3001), so the remap is a pure superset and no existing command or script breaks.
3. As an operator, I want the familiar `hostPort:jailPort` order (matching `docker -p` / `kubectl port-forward`), so the syntax carries no surprise.
4. As an operator, I want a loud usage error if either side is non-numeric, out of range, or if I write extra colons, so a typo fails clearly rather than binding the wrong port.
5. As an operator, I want the running line to name both the host port and the in-jail port, so I can see the mapping I actually got and not assume they are equal.
6. As a security-conscious operator, I want `--bind` semantics unchanged (loopback default, warned 0.0.0.0 opt-in) and every other forward guardrail (no OUTPUT rule, TCP-only, one jail port, netcage-managed-only, lifetime-bounded) to stay exactly as they are, so the remap adds convenience without widening the security surface.

### Autonomy notes

- **`humanOnly` NOT set (prd-level):** no CI / autonomous tasker here; the flag's effect is inert.
- **`needsAnswers`:** NOT set. The change is a localized parse + wiring extension of an existing verb (ADR-0014) with a settled, familiar syntax and no guardrail change. Remaining choices (exact error strings) are tasking-time details.

## Implementation Decisions

Decided at launch:

- **Parse layer** (`internal/cli` `parseForward`): the second positional becomes `[hostPort:]jailPort`. Split on a single `:`; zero colons => host==jail (today's behaviour); one colon => `hostPort:jailPort`; two or more colons => usage error. Validate each side 1..65535 (reuse/extend `parseForwardPort`). Add a `ForwardHostPort int` field (defaulting to `ForwardPort` when no remap given, so downstream is uniform).
- **Wiring** (`internal/forward`): `Config` gains `HostPort`; `ListenArgs` binds `TCP-LISTEN:<hostPort>` and the connect side reaches `127.0.0.1:<jailPort>` (the existing `Port` stays the jail/connect port). The start line prints `http://<bind>:<hostPort> -> <container>:<jailPort>`.
- **No ADR**: this extends the existing verb shape within ADR-0014 (no new invariant, no new verb, no guardrail change). A one-line pointer in the README + the ADR-0014 consequences is enough.

> Trimmed at tasking-time.

## Testing Decisions

- **Parse matrix** (pure, no podman): bare `3001` (host==jail), `8080:3001` (remap), bad host side (`x:3001`, `70000:3001`, `0:3001`), bad jail side (`8080:x`, `8080:99999`), extra colons (`1:2:3`), and that `--bind` still parses alongside.
- **`ListenArgs` test**: for `8080:3001` the host listener binds `:8080` and the connect side targets `127.0.0.1:3001` (the remap is honoured on the right sides); for the bare form both are the same port.
- **verify stays green**: the remap changes only the host bind port; no OUTPUT rule, TCP-only, one jail port unchanged, so the forced-egress leak-test is unaffected.

> Also trimmed at tasking-time.

## Out of Scope

- **Multiple ports / port ranges in one invocation.** Still exactly one `[hostPort:]jailPort` per `forward` (a range or repeated mapping is a separate future feature).
- **UDP.** TCP-only stands (ADR-0003).
- **Binding a specific host interface.** `--bind` still accepts only `127.0.0.1` / `0.0.0.0` (a specific-interface bind remains out of scope, unchanged from ADR-0014).
- **Remapping the in-jail connect ADDRESS.** The connect side is always `127.0.0.1:<jailPort>` in the shared netns; only the host-side PORT is remappable, not the in-jail address.

## Further Notes

- Purely additive to the shipped `forward` verb (v0.8.1). The single-port form is the zero-remap special case, so backward compatibility is structural, not just promised.
- Reuses the parse + wiring seams `forward` already has; the only new surface is the host-side bind port, which is not security-relevant (the in-jail side, the label scope, the firewall, and the bind-address guardrail are all untouched).
