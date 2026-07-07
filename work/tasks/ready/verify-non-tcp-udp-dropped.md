---
title: verify assertion - raw non-53 UDP (incl. UDP/443 QUIC) from the jail is dropped
slug: verify-non-tcp-udp-dropped
blockedBy: []
covers: []
---

## What to build

Add a `verify` assertion proving row 5 of the Tails-derived leak catalogue: raw non-53 UDP from the jail is dropped, specifically including UDP/443 (QUIC / HTTP-3). netcage already hard-drops ALL UDP (ADR-0003, "UDP is dropped, period"); this assertion PROVES the QUIC case specifically rather than assuming it.

Add a named assertion (mirror the existing verify shape in `internal/verify`): from inside the jail, a raw UDP datagram to an off-box address (a generic UDP port AND specifically UDP/443) is DROPPED. The PASS is that the UDP attempt does not leave the jail to the real network.

### Design decision, RESOLVED in the design pass (do not re-open)

- **Assert the DROP, not the browser fallback.** netcage cannot run a real browser in the jail integration suite to observe HTTP-3 degrading to TCP. The PROVABLE claim is "UDP/443 from the jail is DROPPED" (already true, ADR-0003). "A real client degrades to TCP" is a docs note about expected client behaviour, NOT a test assertion. The assertion proves the drop; the fallback is prose.

## Acceptance criteria

- [ ] A named `verify` assertion (e.g. `non-tcp-udp-dropped`) asserts that raw non-53 UDP from the jail, INCLUDING UDP/443 (QUIC), is dropped / does not reach the real network.
- [ ] The pure assertion/decision logic is unit-tested; the live jailed probe runs in the verify integration suite (the `integration` tag), isolated to a throwaway container, host untouched.
- [ ] A one-line docs note records that UDP/443 is dropped and a real client is expected to degrade to TCP (client behaviour, not a tested assertion).
- [ ] The assertion name is recorded for pinning in the future `verify --json` contract.
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: prove raw non-53 UDP incl. UDP/443 (QUIC) is dropped by the jail. Row 5 of `work/notes/ideas/verify-leak-catalogue-backlog.md`; assert-not-assume (ADR-0003 already hard-drops all UDP). One of four sibling verify-assertion tasks. The design pass RESOLVED: assert the drop, the client-degrades-to-TCP is a docs note not a test.
>
> FIRST, check drift: read `internal/verify/verify.go` (assertion shape) + `internal/verify/integration_test.go` (jailed-probe pattern), and ADR-0003 (`docs/adr/0003-hard-block-all-udp-in-v1.md`) to confirm UDP is still hard-dropped. Note the DNS subtlety: DNS still works DESPITE the UDP drop because it is a client-side UDP->TCP conversion via the in-jail DNS-over-SOCKS forwarder (ADR-0003 / `dns-through-socks-is-tcp-not-udp.md`); the assertion targets NON-53 UDP so it does not conflict with the DNS path.
>
> Where to look: mirror `forced-egress-exit-ip-differs-from-host` for the jailed-probe + decision shape; the live probe (a `socat`/raw UDP datagram to an off-box host and to :443) runs behind the `integration` tag, isolated. Seams to test at: the pure decision (unit) and the live UDP-drop probe (integration). "Done" = a raw UDP and a UDP/443 attempt from the jail are proven dropped, and the docs carry the QUIC/TCP-fallback note. Keep the assertion INTENT consistent with anonctl's `non-tcp-udp-drop` (same concept, same resolution).
