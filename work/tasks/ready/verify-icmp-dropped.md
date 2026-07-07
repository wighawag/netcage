---
title: verify assertion - ICMP / raw sockets from the jail emit no real-source-IP packet (+ PMTU docs caveat)
slug: verify-icmp-dropped
blockedBy: []
covers: []
---

## What to build

Add a `verify` assertion proving row 4 of the Tails-derived leak catalogue: ICMP / raw sockets leaking the real IP. `ping`, traceroute, raw ICMP from the jail must not emit an ICMP packet carrying the real source IP. Tails drops all ICMP to the Internet (accepting the PMTU cost). netcage's jail already confines this (non-TCP does not ride the TUN-to-SOCKS path); this assertion PROVES it.

Add a named assertion (mirror the existing verify shape): an ICMP echo (`ping`) from inside the jail to an off-box address does NOT emit an ICMP packet with the real source IP; a dropped ping gets no reply. The PASS is no real-source-IP ICMP reaching the network.

### Design decision, RESOLVED in the design pass (do not re-open)

- **PMTU/PLPMTUD: document as a caveat, do NOT set a sysctl (for now).** netcage's ICMP/UDP drops live INSIDE the jail netns, so a `net.ipv4.tcp_mtu_probing` here would at least be jail-scoped (unlike anonctl's per-UID case), but it is still unnecessary in v1: the jailed tool's forced TCP rides tun2socks to the SOCKS proxy, and no motivating tool needs raw ICMP. Drop ICMP (already happens), assert it, add a one-line docs caveat that netcage does not tune PMTU and why; revisit only if a real tool's PMTU breaks.

## Acceptance criteria

- [ ] A named `verify` assertion (e.g. `icmp-dropped`) asserts that an ICMP echo (`ping`) from the jail to an off-box address emits no real-source-IP packet (dropped: no reply).
- [ ] The pure assertion/decision logic is unit-tested; the live jailed probe runs in the verify integration suite (the `integration` tag), isolated to a throwaway container, host untouched.
- [ ] A one-line docs caveat records that netcage drops ICMP and deliberately does NOT tune PMTU (jail-scoped drop; forced path is tun2socks-relayed TCP; revisit only if a tool's PMTU breaks).
- [ ] The assertion name is recorded for pinning in the future `verify --json` contract.
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: prove ICMP from the jail cannot leak the real source IP, and document the PMTU trade-off. Row 4 of `work/notes/ideas/verify-leak-catalogue-backlog.md`; assert-not-assume. One of four sibling verify-assertion tasks. The design pass RESOLVED: drop + assert + a docs caveat, do NOT set `tcp_mtu_probing`.
>
> FIRST, check drift: read `internal/verify/verify.go` (assertion shape) + `internal/verify/integration_test.go` (jailed-probe pattern + isolation). Confirm the jail still confines non-TCP (ICMP does not ride the TUN-to-SOCKS path).
>
> Where to look: mirror `forced-egress-exit-ip-differs-from-host`; the live probe runs the jail's `ping` with a short deadline / single packet (a missing ping binary or any error yields no-reply = the fail-closed PASS, mirroring anonctl's `pingAsAnon`), behind the `integration` tag, isolated. Seams to test at: the pure decision (unit) and the live ping-drop probe (integration). "Done" = a ping from the jail is proven to get no reply (no real-source-IP ICMP left), and the docs carry the PMTU caveat. Keep the assertion INTENT consistent with anonctl's `icmp-drop` (same concept, same PMTU resolution).
