---
title: verify assertion - the jail reaches only its own loopback (DNS forwarder), never another 127.0.0.1 service
slug: verify-jail-loopback-confined
blockedBy: []
covers: []
---

## What to build

Add a `verify` assertion proving row 6 of the Tails-derived leak catalogue: a different loopback service used as an escape hatch. The jailed tool must be able to reach ONLY its own intended loopback (the in-jail DNS-over-SOCKS forwarder), never some OTHER `127.0.0.1` service (e.g. a second SOCKS on `:9150`, or a host service reachable via the pasta loopback map). Tails' local-services allowlist is precisely this defence.

Add a named assertion (mirror the existing verify shape): from inside the jail, a connection to a loopback destination that is NOT the jail's own forwarder / intended port is dropped, while the intended forwarder loopback IS reachable (so the assertion is non-vacuous). The PASS is confinement: only the intended loopback works.

## Acceptance criteria

- [ ] A named `verify` assertion (e.g. `jail-loopback-confined`) asserts the jail can reach its own DNS forwarder / intended loopback but NOT another `127.0.0.1` service (e.g. a probe to `127.0.0.1:9150` is dropped).
- [ ] The assertion is non-vacuous: it confirms the INTENDED loopback is reachable (else "everything on loopback is dropped" would pass trivially and hide a broken forwarder).
- [ ] The pure assertion/decision logic is unit-tested; the live jailed probe runs in the verify integration suite (the `integration` tag), isolated to a throwaway container, host untouched.
- [ ] The assertion name is recorded for pinning in the future `verify --json` contract.
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: prove the jail is confined to its own loopback and cannot pivot to another `127.0.0.1` service. Row 6 of `work/notes/ideas/verify-leak-catalogue-backlog.md`. One of four sibling verify-assertion tasks.
>
> FIRST, check drift: read `internal/verify/verify.go` (assertion shape) + `internal/verify/integration_test.go` (jailed-probe pattern). Read how the jail's own loopback / DNS forwarder is wired (the sidecar + the pasta host-loopback reachback, ADR-0002; `internal/jail`) so the assertion targets the RIGHT intended-loopback port and a genuinely-other one for the negative case. The most leak-prone seam is the pasta host-loopback reachback (ADR-0002 flags it), so an off-target loopback probe is a meaningful test.
>
> Domain vocabulary: the jail forces egress through the proxy; its only intended local peer is the in-jail DNS-over-SOCKS forwarder. Any other loopback destination is an escape hatch and must be dropped.
>
> Where to look: mirror `forced-egress-exit-ip-differs-from-host`; the live probe dials the intended forwarder loopback (expect reachable) and a different `127.0.0.1:<port>` (expect dropped), behind the `integration` tag, isolated. Seams to test at: the pure decision (unit) and the live confinement probe (integration). "Done" = the jail is proven to reach its own forwarder but not another loopback service, non-vacuously. Keep the assertion INTENT consistent with anonctl's `bypass-loopback-closure` (same concept: only the intended loopback, everything else dropped).
