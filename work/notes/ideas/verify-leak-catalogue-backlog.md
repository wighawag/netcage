---
kind: idea
title: Grow netcage verify to prove the full Tails-derived leak catalogue (IPv6, QUIC/UDP, ICMP, other-loopback)
slug: verify-leak-catalogue-backlog
status: proposed
---

> TASKED 2026-07-07: the four spawn tasks below now exist in `work/tasks/ready/` (`verify-ipv6-egress-fails-closed`, `verify-non-tcp-udp-dropped`, `verify-icmp-dropped`, `verify-jail-loopback-confined`). This idea remains as the design record; do not re-task it.

## The idea

`work/notes/findings/learning-from-anonctl-tails-leak-catalogue.md` maps a decade of Tails adversarial review into a `verify`-assertion backlog for netcage. Findings are meant to be acted on: netcage's `verify` today asserts the happy path (`forced-egress-exit-ip-differs-from-host`, `dns-resolves-over-tcp-glibc`) but does not PROVE several leak classes the jail already closes. Grow `verify` so the forced-egress guarantee is proven against the full leak surface, not just the happy path.

The row-2 fix (LAN-exemption-as-DNS-hole) is its own STAGED TASK (`allow-direct-must-not-be-a-dns-hole`) because it is a concrete latent hole in a shipped feature. The remaining rows are assertions netcage should add; grouped here as one idea because they share the verify integration harness and can be tasked together or in a small batch:

- **IPv6 as a total bypass** (table stakes): assert ANY v6 egress from the jail (a `curl -6` to a v6 literal, a v6 DNS) fails closed. The classic transparent-proxy leak (v4 forced, v6 untouched).
- **Non-53 UDP incl. QUIC/HTTP-3 (UDP/443)**: netcage already hard-drops UDP (ADR-0003); make `verify` assert the QUIC case specifically (dropped, and a real client degrades to TCP rather than leaking).
- **ICMP / raw sockets**: assert `ping`/raw ICMP from the jail does not emit a packet with a real source IP (dropped). Note the PMTU cost Tails accepts (and its PLPMTUD workaround) as a caveat.
- **Other loopback as an escape hatch**: assert the jail can reach ONLY its own DNS forwarder / intended loopback, never another `127.0.0.1` service (e.g. a second SOCKS on `:9150`).

All four ALREADY hold in the shipped jail (v6 not carried; ADR-0003 hard-drops ALL UDP incl. QUIC/HTTP3/ping-style; other-loopback is outside the tun2socks path), so this is assert-not-assume: grow `verify` to PROVE them, add no new drop behaviour.

## Design pass: the three judgement calls, RESOLVED

Resolved 2026-07-07 (design pass), consistent with anonctl's sibling resolution:

- **PMTU/PLPMTUD: document as a caveat, do NOT set a sysctl (for now).** netcage's ICMP/UDP drops live INSIDE the jail netns, so unlike anonctl a `net.ipv4.tcp_mtu_probing` here would at least be jail-scoped, not host-global. But it is still unnecessary in v1: the jailed tool's forced TCP rides tun2socks to the SOCKS proxy, and no motivating tool needs raw ICMP. RESOLUTION: drop ICMP (already happens), assert it, add a one-line docs caveat that netcage does not tune PMTU and why; revisit only if a real tool's PMTU breaks. Do NOT set the sysctl now.
- **QUIC: assert the DROP, not the browser fallback.** netcage cannot run a real browser in the jail integration suite to observe TCP fallback. The PROVABLE claim is "UDP/443 from the jail is DROPPED" (already true, ADR-0003). "A real client degrades to TCP" is a docs note about expected client behaviour, not a test assertion. RESOLUTION: the assertion proves the drop; the fallback is prose.
- **Granularity: ONE assertion per task (a small batch), NOT one big task.** The four assertions (v6-bypass, non-tcp-udp/QUIC, icmp, other-loopback) are independent, each a distinct jailed probe, and keeping them one-per-task keeps `internal/verify` edits file-orthogonal and each PR trivially reviewable. They share the jail integration harness but do not depend on each other. RESOLUTION: task as FOUR small sibling tasks (or a 4-item batch), not one monolith. Order: v6-bypass and non-tcp-udp first (table stakes), then icmp and other-loopback.

Coordinate the assertion INTENT with anonctl's equivalent verify growth (anonctl task `verify-icmp-and-non53-udp-drop-assertions` covers the ICMP/UDP rows for the per-UID side, with the SAME PMTU and QUIC resolutions) so the two `verify`s prove the same catalogue with consistent assertion semantics and names where the concept is identical.

## What this idea spawns (ready to task once promoted)

Four small sibling verify-assertion tasks, each mirroring the existing `forced-egress-exit-ip-differs-from-host` / `dns-resolves-over-tcp-glibc` shape (a jailed probe behind the jail integration suite, plus unit-tested render/exit logic):

- `verify-ipv6-egress-fails-closed` (table stakes): any v6 egress from the jail (v6 literal TCP, v6 DNS) is dropped.
- `verify-non-tcp-udp-dropped` (table stakes): raw non-53 UDP incl. UDP/443 (QUIC) is dropped.
- `verify-icmp-dropped`: `ping`/raw ICMP emits no real-source-IP packet; + the PMTU docs caveat.
- `verify-jail-loopback-confined`: the jail reaches ONLY its own DNS forwarder / intended loopback, never another `127.0.0.1` service.

All four also want the assertion names pinned in netcage's verify JSON output contract (see the sibling idea `verify-json-output-contract`).

## What does NOT apply to netcage

The anonctl finding's row 7 (the UID-transition escape) is anonctl-SPECIFIC: it exists because anonctl matches by socket-owning `skuid` on a shared machine. netcage confines by network NAMESPACE, not by uid, so there is no per-uid escape inside the jail. This is a genuine structural advantage of the netns model over the per-account model; it is worth stating in netcage's docs (alongside ADR-0013's honest scope) that on this one axis netcage's guarantee is tighter than a per-UID forcer's. It is NOT a netcage task, only a documentation point.
