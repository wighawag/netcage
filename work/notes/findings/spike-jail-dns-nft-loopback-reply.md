---
title: The jail nft UDP rule must allow the forwarder's loopback REPLY, not just the dport-53 query, or DNS fails closed
slug: spike-jail-dns-nft-loopback-reply
source: 'captured live on this host 2026-06-30 (podman 5.4.2 rootless, netavark, pasta; nftables v1.1.3) while building verify-leak-test. Reproduced end-to-end: with the dport-53-only rule the tool nslookup timed out; with an all-loopback-UDP allow it resolved the unique name to the proxy-side answer and the fixture recorded the lookup.'
---

# DNS through the jail needs the nft rule to allow the loopback REPLY too

While wiring `verify`'s DNS-through-proxy assertion, the in-jail DNS resolution timed out
(`;; connection timed out; no servers could be reached`) even though every component worked in
isolation (the forwarder resolves proxy-side; the fixture answers; the mounted resolv.conf points
at `127.0.0.1:53`). The cause was the jail's own nft ruleset.

## The bug

The old rule allowed only the QUERY direction:

```
udp dport 53 ip daddr 127.0.0.0/8 accept   # tool -> forwarder (dport 53)
meta l4proto udp drop                       # everything else
```

But the tool<->forwarder DNS exchange is TWO loopback UDP packets:

- tool `127.0.0.1:<ephemeral>` -> forwarder `127.0.0.1:53`  (dport 53, matches, accepted)
- forwarder `127.0.0.1:53` -> tool `127.0.0.1:<ephemeral>`  (dport = the EPHEMERAL port, does NOT
  match `dport 53`, falls through to `meta l4proto udp drop`, **dropped**)

nft counters confirmed it: `udp dport 53 ... accept` counted 4 packets, and `meta l4proto udp drop`
counted exactly 4 (the replies). The tool never got an answer, so DNS failed closed for the wrong
reason (the jail dropped its own reply, not a leak).

## The fix

Allow ALL loopback UDP (the tool<->forwarder hop is entirely 127.x<->127.x and never egresses the
netns), and keep dropping every other (egress) UDP:

```
meta l4proto udp ip daddr 127.0.0.0/8 accept   # tool<->forwarder loopback DNS (query AND reply)
meta l4proto udp drop                           # every other (egress) UDP dropped (ADR-0003)
```

This preserves ADR-0003's invariant exactly: the ONLY UDP allowed is loopback-internal (provably
non-egress), and all egress UDP is still hard-dropped. The host resolver never sees the name (it
went proxy-side over TCP); UDP never leaves the jail.

nft syntax note: the protocol-plus-address match is `meta l4proto udp ip daddr 127.0.0.0/8 accept`;
the shorthand `ip daddr 127.0.0.0/8 udp accept` is a syntax error in nftables v1.1.3.

## Evidence (2026-06-30)

End-to-end through the real jail, after the fix:

```
tool: nslookup unique.tooljail.test   ->  Address: 203.0.113.55   (the proxy-side answer)
fixture ResolvedHosts(): [dns.tooljail.test ...]   (the lookup went THROUGH the proxy)
```

The forced-egress task's integration test missed this because it tests by IP (no DNS); the DNS path
is first exercised end-to-end by `verify`'s second assertion, which is why the bug surfaced now.

## Carry-over

- `internal/jail.nftRuleset` updated accordingly (and its unit test).
- `internal/jail.Config` gained `DNSUpstream` so `verify` can point the forwarder at a controllable
  DNS-over-TCP resolver (addressed by hostname so the proxy resolves it proxy-side, the
  observability hook the assertion binds to via `socks5hfixture.ResolvedHosts()`).
