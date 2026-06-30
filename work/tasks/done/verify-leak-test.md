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

## Done record (2026-06-30)

Built as `internal/verify` (+ `tooljail verify` CLI wiring in `main.go`). All three leak
assertions are green end-to-end against `internal/socks5hfixture`, podman-gated, leaving no residue.

Non-obvious in-scope decisions:

- **Exit-code scheme:** `Report.ExitCode()` returns 0 iff EVERY assertion passed, else 1. An EMPTY
  report is NOT a pass (exits 1): "nothing asserted" must never read as green. `tooljail verify`
  returns this code so CI can gate (story 8). Unit-tested without podman.
- **How "proxy-side resolution" is observed (assertion #2):** the jail's in-netns DNS forwarder is
  pointed (via the new `jail.Config.DNSUpstream`) at a controllable DNS-over-TCP resolver addressed
  BY HOSTNAME (`dns.tooljail.test`), so the fixture resolves that name proxy-side and RECORDS it in
  `ResolvedHosts()`. The assertion is the conjunction of three facts: (a) the unique name resolved
  to the proxy-side answer, (b) the fixture saw the upstream name (proof it went through the proxy),
  and (c) the HOST resolver returns nothing for the fake `.test` TLD (proof it did not leak to the
  host resolver).
- **Fail-closed (assertion #3)** kills the fixture BEFORE the probe and asserts a distinctive
  host-echo marker NEVER appears in the tool output (no fall-back to the host network). A jail-run
  error with the proxy down counts as no-egress (fail-closed), not a leak.
- **CLI `verify` vs the fixture leak-test:** the deterministic three-assertion proof IS the
  fixture-backed test suite (the acceptance gate). `tooljail verify` against a user's REAL proxy
  cannot know the exit IP or kill the proxy, so it asserts the property it CAN observe without
  controllable infra: the jail's exit IP DIFFERS from the host's direct exit IP (forced egress
  active), via a public IP-echo. This network path is deliberately NOT in the test gate.

Found + fixed along the way (recorded as a finding): the jail's nft ruleset dropped the forwarder's
loopback DNS REPLY (it allowed only `dport 53`, but the reply's dport is the tool's ephemeral port),
so DNS silently failed closed. Fixed to allow all loopback UDP (provably non-egress) while still
hard-dropping egress UDP (ADR-0003 intact). See
`work/notes/findings/spike-jail-dns-nft-loopback-reply.md`.
