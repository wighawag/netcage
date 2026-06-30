---
title: tooljail verify — the three leak assertions (exit IP, DNS-through-proxy, fail-closed)
slug: verify-leak-test
prd: tooljail
blockedBy: [jail-run-forced-egress]
covers: [4, 6, 7, 8]
---

## What to build

`tooljail verify` — the project's top acceptance seam and first-class proof. It runs a probe through the SAME jail that `run` uses and asserts the three leak properties, exiting non-zero (CI-gating, story 8) if any fails:

1. **Exit IP is the proxy's** — the observed exit IP equals the proxy's exit IP, not the host's (IP-echo through the jail).
2. **DNS goes through the proxy** — a unique hostname resolves through the proxy's resolver (socks5h, proxy-side), NOT the host resolver. Assert it appears proxy-side / not host-side.
3. **Fail-closed on proxy-kill** — with the proxy deliberately killed, the probe FAILS CLOSED (no egress), never falling back to the host network.

End-to-end thin path: drive all three assertions against the `socks5h-test-fixture` (known exit IP, known DNS view, killable), so they are deterministic without real Tor. `verify` returns non-zero on any failed assertion so CI can gate releases on it.

This MUTATES THE SYSTEM (it stands up the jail). Run with explicit confirmation, not unattended.

## Acceptance criteria

- [ ] The three assertions are written FIRST and RED before the wiring, each against the `socks5h-test-fixture`: (1) exit IP == fixture's; (2) unique hostname resolves proxy-side not host-side; (3) fixture killed ⇒ probe fails closed (no egress).
- [ ] `tooljail verify` runs the probe through the same jail `run` uses and reports pass/fail per assertion.
- [ ] Any failed assertion ⇒ non-zero exit (so CI can gate on it).
- [ ] The proxy-kill assertion proves NO egress to the host network when the proxy is down (fail-closed, not fail-open).
- [ ] Tests cover the new behaviour and run against the fixture (deterministic, no real Tor). System-mutating parts isolate to throwaway containers/netns and assert the host is untouched after.

## Blocked by

- `jail-run-forced-egress` — verify runs a probe through the same jail `run` builds.

## Prompt

> Goal: build `tooljail verify`, the three-assertion leak-test that is the project's top acceptance seam. Read `CONTEXT.md` (verify/leak-test, socks5h, fail-closed), ADR-0003 (UDP), the prd Solution section, and the ADRs (the testing detail was trimmed out of the prd into the tasks/ADRs at tasking time). The three assertions: exit IP is the proxy's; a unique hostname resolves proxy-side not host-side; proxy-killed ⇒ fails closed.
>
> FIRST, check against current reality: confirm `jail-run-forced-egress` landed and exposes the jail path verify runs a probe through; read its done-record/ADRs. If the jail seam differs from what this task assumes, route to needs-attention rather than building on a stale seam.
>
> This MUTATES THE SYSTEM (it stands up the jail). Do NOT run unattended — get explicit confirmation before creating containers/netns.
>
> Write the three assertions FIRST (testFirst is ON), each against the `socks5h-test-fixture`: (1) IP-echo through the jail returns the fixture's exit IP; (2) a unique hostname resolves proxy-side (the fixture sees the lookup; the host resolver does not); (3) kill the fixture, run the probe, assert it fails closed with no host egress. Red until verify wires them. Then implement verify to run the probe and report/exit per assertion (non-zero on any failure).
>
> "Done" means all three assertions are green against the fixture, verify exits non-zero on any failure (CI-gateable), and the proxy-kill case proves fail-closed (no host egress). Keep it deterministic against the fixture — do NOT depend on real Tor. RECORD non-obvious in-scope decisions (exit-code scheme, how "proxy-side resolution" is observed) per the task-template guidance.
