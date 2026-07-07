---
title: Learning from anonctl - the Tails-derived leak catalogue and verify-assertion backlog (canonical copy lives in anonctl)
slug: learning-from-anonctl-tails-leak-catalogue
source: 'Reference pointer to the sibling repo anonctl, finding work/notes/findings/tails-network-filter-lessons.md (authored 2026-07-07 from Tails design docs retrieved that day). This netcage-side file is a REFERENCE, not a second copy of the ground truth; keep the analysis single-sourced in anonctl and update it there.'
---

# Learning from anonctl (and, through it, from Tails)

netcage and its sibling **anonctl** solve the same primitive at different scopes: netcage forces egress for one **container netns** through a socks5h proxy (fail-closed); anonctl forces egress for one **Unix account** (`meta skuid`) through a socks5h endpoint (fail-closed). anonctl is the newer of the two and is the one closest to the Tails model (per-user forced egress on a real machine), so the durable "what does a decade of Tails adversarial review teach forced-egress jails" analysis was written THERE, once, to avoid two drifting copies.

**Canonical finding (the real content):** in the anonctl repo, `work/notes/findings/tails-network-filter-lessons.md`. Read it there. This file exists so a netcage reader lands on the pointer and knows where the shared analysis lives.

## Why it applies to netcage even though it was written for anonctl

The forcing MECHANISM differs (netcage: per-netns firewall + tun2socks sidecar; anonctl: per-UID nftables + shim), but **the leak surface is nearly identical**, and it is exactly the surface Tails' committed ferm/iptables ruleset closes: default-block, per-identity special-casing, DNS forced remote, LAN DNS forbidden, IPv6 not carried, UDP/ICMP/non-TCP dropped, other-loopback denied, `RELATED` dropped. Each is a candidate netcage `verify` assertion.

## The netcage `verify`-assertion backlog (mapped from the anonctl finding)

The anonctl finding lists the full catalogue with quotes and priorities; the netcage-relevant rows, in priority order:

- **IPv6 as a total bypass** (table stakes): assert ANY v6 egress from the jail (a `curl -6` to a v6 literal, a v6 DNS) fails closed. The classic transparent-proxy leak.
- **Plaintext DNS via UDP/53** (table stakes): already load-bearing for netcage (ADR-0003, and the sibling finding `dns-through-socks-is-tcp-not-udp.md`). Assert with the black-hole-resolver probe (a query to an unreachable resolver STILL returns an answer, proving interception) plus a zero-off-box-udp/53 check - NOT the naive "direct dig must time out", which is wrong for a transparently-redirected setup.
- **LAN exemption must NOT become a DNS hole** (our OWN feature can reintroduce this): Tails forbids LAN DNS because a `@192.168.x.x` resolver can reveal the local network's public IP. netcage's `--allow-direct` (ADR-0005) opens an RFC1918 `host:port` hole; `verify` should prove that hole does NOT permit clear DNS (tcp/udp 53) to the LAN resolver. The exemption is host+port scoped; assert 53 is not reachable through it.
- **Non-53 UDP incl. QUIC/HTTP-3 (UDP/443)** (real modern clients): SOCKS is TCP-only, so UDP/443 is unrelayable; assert it is DROPPED and a real client degrades to TCP rather than leaking. netcage already hard-drops UDP (ADR-0003); make `verify` assert the QUIC case specifically.
- **Other loopback as an escape hatch**: assert the jail can reach ONLY its own DNS forwarder / intended loopback, never another `127.0.0.1` service (e.g. a second SOCKS on `:9150`).
- **ICMP / raw sockets**: assert `ping`/raw ICMP from the jail does not emit a packet with a real source IP. (Tails accepts the PMTU cost of dropping ICMP and works around it with PLPMTUD; note as a caveat.)

## What is anonctl-SPECIFIC and does NOT apply to netcage (a genuine netns advantage)

The anonctl finding's sharpest item is the **UID-transition escape**: because anonctl matches by socket-owning `skuid` on a machine full of other UIDs, a setuid helper / `sudo` / triggerable daemon can produce a socket owned by a non-anon UID that escapes forcing. **This class does NOT exist for netcage**: a container netns confines by NAMESPACE, not by UID, so there is no per-UID escape inside the jail. Worth recording as a real advantage of the netns model over the per-account model, and a reason netcage's guarantee is structurally tighter on that one axis.

## Scope boundary (shared with anonctl, restated so netcage does not scope-creep)

netcage takes ONLY Tails' network-filter discipline and leak catalogue. It does NOT adopt Tails' amnesia, anti-forensics, MAC spoofing, or whole-OS control, and it explicitly does not hide the shared-kernel/hardware fingerprint (ADR-0013). "Learn from Tails/anonctl" means "grow `verify` to prove the full leak surface is closed", not "become an OS". Cross-cutting posture the anonctl finding spells out and netcage already follows: any un-anonymized hole stays off by default, private-range only, host+port scoped, never a DNS hole, and announced (netcage's `--allow-direct` guardrails + the `forward --bind 0.0.0.0` warning are exactly this).
