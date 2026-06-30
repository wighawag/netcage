---
title: DNS-to-SOCKS-TCP forwarder resolves through the proxy, fail-closed, no host leak (spike result)
slug: spike-dns-to-socks-bridge
source: 'captured live on this host 2026-06-30; the spike forwarder + harness (a socks5 proxy + a dns-over-tcp resolver). Probe sources in work/tasks/ready/spike-dns-to-socks-bridge/probe/. Mechanism rationale in work/notes/findings/dns-through-socks-is-tcp-not-udp.md (Tor/Mullvad sourced).'
---

# A DNS-to-SOCKS-TCP forwarder is the leak-proof DNS seam (spike POSITIVE)

**Verdict: POSITIVE.** The DNS-through-the-proxy mechanism ADR-0003 assumes is realisable as a small forwarder, and it is leak-proof: a tool's UDP DNS query is resolved VIA THE SOCKS PROXY OVER TCP, the answer comes back, UDP never leaves the jail, and the host resolver never sees the name. This de-risks the DNS seam the jail-run-forced-egress task needs (the live smoke showed tun2socks alone leaks DNS — see `dns-through-socks-is-tcp-not-udp.md`).

## What was proven

The forwarder (`probe/forwarder`) listens on UDP, and for each DNS query:

1. dials the SOCKS5 proxy and CONNECTs (socks5h) to an upstream DNS resolver addressed BY HOSTNAME (so the proxy resolves the resolver's name too),
2. sends the query as DNS-over-TCP (RFC 1035 2-byte length prefix) through the tunnel,
3. reads the TCP answer and replies to the tool over UDP.

Run against a harness (`probe/harness`) that is a minimal socks5 proxy + a dns-over-tcp resolver answering ONLY `unique.tooljail.test` -> `203.0.113.55`:

- **Resolves through the proxy:** `ASSERT OK: unique.tooljail.test resolved to 203.0.113.55 THROUGH the proxy (DNS-over-SOCKS-TCP)`. The proxy-side resolver answered; the tool got the record over UDP.
- **No host-resolver leak:** the host resolver returns NXDOMAIN for `unique.tooljail.test` (a fake TLD), so the name resolved ONLY proxy-side. The tool->forwarder hop is UDP; the forwarder->proxy hop is TCP; nothing UDP and nothing name-bearing reaches the host.
- **Fail-closed:** with the proxy DOWN (forwarder pointed at a dead address), the query gets NO answer (the forwarder drops on upstream failure, no fallback to a host resolver) -> the assert times out and exits non-zero. Proxy-down means resolution fails, never leaks. Consistent with the jail's fail-closed invariant.

## Recipe for the jail task to reuse

- Run a DNS-to-SOCKS-TCP forwarder in the jail netns (in the shared netns under Option A). Point the tool's `resolv.conf` at the forwarder's address (e.g. `127.0.0.1` on a chosen port, or a netns-local address).
- The forwarder dials the SAME socks5 proxy the tun2socks sidecar uses (translate the user's `socks5h://` to a `socks5://` SOCKS5 dial; the proxy resolves remotely). For a host-loopback proxy it reaches it via the pasta map (169.254.1.1:<port>), through the same nft narrowing.
- Use DNS-over-TCP framing to a stable upstream resolver addressed by hostname (so socks5h resolves it). For Tor, the upstream can be any public DNS name; Tor resolves it at the exit. (Alternatively, for proxies that support it, a SOCKS5 RESOLVE extension; DNS-over-TCP via CONNECT is the portable path proven here.)
- Keep UDP hard-blocked at nft (ADR-0003): the tool->forwarder UDP hop is INSIDE the netns to a local address, not egress; all egress UDP is still dropped. (Confirm the nft rule allows the local tool->forwarder UDP to the loopback/forwarder address while dropping egress UDP — a daddr-scoped allow for the forwarder address, drop the rest.)

## Caveats / not-yet-proven

- This spike proved the forwarder mechanism in USERSPACE (no container). The jail task must run it inside the shared netns and confirm the nft UDP rule permits the local tool->forwarder hop while still dropping egress UDP (a daddr-scoped exception for the forwarder's address).
- The upstream resolver choice (a public DNS name resolved at the Tor exit vs a SOCKS5 RESOLVE) is a jail-build detail; DNS-over-TCP-via-CONNECT is the portable, proven path.
- The spike's harness proxy is a stand-in; the jail tests use internal/socks5hfixture (extended for the DNS-over-TCP path if needed) as the controllable proxy.
