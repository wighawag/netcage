---
title: Prove the forced-egress leak-test stays green with a forward active
slug: verify-forward-keeps-egress-tight
spec: host-access-forward-verb
blockedBy: [forward-verb-wiring-and-bind]
covers: [10]
---

## What to build

The acceptance proof that host access does not weaken the egress guarantee: an automated check that, with a `netcage forward` active against a running jail, the forced-egress three-point leak-test still passes. This makes "the forward adds no OUTPUT rule / does not touch forced egress" a TESTED property, not just a design claim.

End-to-end: stand up a real jail (against the socks5h test fixture), stand up a forward into it, and assert while the forward is active:

1. The tool's observed exit IP is the proxy's (forced egress holds).
2. A unique hostname resolves through the proxy's resolver, not the host's (DNS is proxy-side).
3. With the proxy killed, the tool's egress FAILS CLOSED (no leak to the host network).

And assert the forward's own property in the same run: the host reaches the in-jail server on `127.0.0.1:<port>` while the three assertions above hold (host access and leak-tightness coexist). Reuse the existing verify leak-test harness / fixture rather than building a new one; extend it to run with a forward attached.

## Acceptance criteria

- [ ] With a forward active against a real jail, the three forced-egress assertions (exit-IP is the proxy's, DNS proxy-side, fail-closed on proxy-kill) all pass.
- [ ] In the same run, the host reaches the in-jail server on `127.0.0.1:<port>` (host access and leak-tightness coexist).
- [ ] The check reuses the existing leak-test harness / socks5h fixture (no parallel harness); it is wired so a regression that let the forward touch egress would FAIL it.
- [ ] **Shared-write isolation:** the check runs ephemeral (unique run-id, remove-both teardown) and leaves no containers, listeners, or host networking state behind.
- [ ] Tests / the acceptance check mirror the existing verify-leak-test style.

## Blocked by

- `forward-verb-wiring-and-bind` (the forward must exist to prove it keeps egress tight).

## Prompt

> Self-contained. Goal: prove, as an automated acceptance check, that a `netcage forward` active against a jail does NOT weaken forced egress — the three-point leak-test stays green with the forward attached — so host access is verified orthogonal to the egress guarantee, not merely designed to be.
>
> FIRST check against current reality (launch snapshot): `forward-verb-wiring-and-bind` must be in `tasks/done/`; read it and the `internal/forward` package it produced. Read the existing verify leak-test (the three assertions: exit-IP is the proxy's, DNS proxy-side, fail-closed on proxy-kill) and the socks5h test fixture (`internal/socks5hfixture`) — this task EXTENDS that harness to run with a forward attached, it does not build a new one. If the forward wiring landed differently than assumed, route to needs-attention.
>
> Domain vocabulary + decisions: verify/leak-test is the project's acceptance floor (`CONTEXT.md`); ADR-0014 requires the forward to add no OUTPUT rule and to leave the egress model untouched; this task is the empirical guard on exactly that. `work/specs/tasked/host-access-forward-verb.md` story 10.
>
> Where to look: the verify leak-test + `internal/socks5hfixture` for the harness to reuse; `internal/forward` for standing up the forward under test. Seam to test at: the leak-test's three assertions plus the host-reaches-`127.0.0.1:<port>` assertion, run with a forward active, ephemeral + isolated.
>
> "Done" means: an automated check that fails if the forward ever touches egress, reusing the existing harness, running clean (no residue). Record any non-obvious in-scope decision in the done record.

## Requeue 2026-07-04

Blocker found + fixed: the forward connector (sh -c nested in socat EXEC) is unparseable by socat; fixing internal/forward to the spike-proven plain nc connector on this branch, then the acceptance test proves it.
