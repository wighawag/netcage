---
kind: idea
title: Grow netcage verify to prove the full Tails-derived leak catalogue (IPv6, QUIC/UDP, ICMP, other-loopback)
slug: verify-leak-catalogue-backlog
status: proposed
---

## The idea

`work/notes/findings/learning-from-anonctl-tails-leak-catalogue.md` maps a decade of Tails adversarial review into a `verify`-assertion backlog for netcage. Findings are meant to be acted on: netcage's `verify` today asserts the happy path (`forced-egress-exit-ip-differs-from-host`, `dns-resolves-over-tcp-glibc`) but does not PROVE several leak classes the jail already closes. Grow `verify` so the forced-egress guarantee is proven against the full leak surface, not just the happy path.

The row-2 fix (LAN-exemption-as-DNS-hole) is its own STAGED TASK (`allow-direct-must-not-be-a-dns-hole`) because it is a concrete latent hole in a shipped feature. The remaining rows are assertions netcage should add; grouped here as one idea because they share the verify integration harness and can be tasked together or in a small batch:

- **IPv6 as a total bypass** (table stakes): assert ANY v6 egress from the jail (a `curl -6` to a v6 literal, a v6 DNS) fails closed. The classic transparent-proxy leak (v4 forced, v6 untouched).
- **Non-53 UDP incl. QUIC/HTTP-3 (UDP/443)**: netcage already hard-drops UDP (ADR-0003); make `verify` assert the QUIC case specifically (dropped, and a real client degrades to TCP rather than leaking).
- **ICMP / raw sockets**: assert `ping`/raw ICMP from the jail does not emit a packet with a real source IP (dropped). Note the PMTU cost Tails accepts (and its PLPMTUD workaround) as a caveat.
- **Other loopback as an escape hatch**: assert the jail can reach ONLY its own DNS forwarder / intended loopback, never another `127.0.0.1` service (e.g. a second SOCKS on `:9150`).

## Why an idea (and how to task it)

These are additive `verify` assertions with a shared shape (a jailed probe + an expected drop/confinement), so the design is low-risk, but there are a few judgement calls worth a human pass before tasking: whether to mirror Tails' PLPMTUD sysctl or just document the ICMP/PMTU caveat; how the QUIC-degrades-to-TCP expectation is asserted without a real browser; and whether these land as one task or a small batch (one assertion per task keeps them file-orthogonal in `internal/verify`). Once those are settled, task it/them off this idea. Coordinate the assertion INTENT with anonctl's equivalent verify growth (anonctl task `verify-icmp-and-non53-udp-drop-assertions` covers the ICMP/UDP rows for the per-UID side) so the two `verify`s prove the same catalogue with consistent assertion semantics.

## What does NOT apply to netcage

The anonctl finding's row 7 (the UID-transition escape) is anonctl-SPECIFIC: it exists because anonctl matches by socket-owning `skuid` on a shared machine. netcage confines by network NAMESPACE, not by uid, so there is no per-uid escape inside the jail. This is a genuine structural advantage of the netns model over the per-account model; it is worth stating in netcage's docs (alongside ADR-0013's honest scope) that on this one axis netcage's guarantee is tighter than a per-UID forcer's. It is NOT a netcage task, only a documentation point.
