---
title: DNS-through-a-SOCKS-proxy is a CLIENT-SIDE UDP→TCP conversion, not a UDP path (Tor/Mullvad)
slug: dns-through-socks-is-tcp-not-udp
source: 'Tor SOCKS-extensions spec (spec.torproject.org/socks-extensions.html, retrieved 2026-06-30) + Mullvad SOCKS5 proxy docs (mullvad.net/en/help/socks5-proxy, retrieved 2026-06-30) + live smoke on this host 2026-06-30 (tun2socks has no DNS handling; the jailed tool leaked DNS to the host gateway 192.168.1.1).'
---

# DNS through a SOCKS proxy is TCP, resolved proxy-side — never a UDP datagram to the proxy

This finding settles the DNS seam for tooljail and CONFIRMS (strengthens) ADR-0003 (hard-block all UDP). It was prompted by a real question — "Tor/Mullvad don't do SOCKS UDP-associate, but don't they accept UDP for DNS? could we allow UDP only for DNS?" — and the answer, from the protocols themselves, is NO.

## The ground truth

- **Tor supports NO UDP at all.** The Tor SOCKS-extensions spec states plainly: *"The SOCKS5 'UDP ASSOCIATE' command is not supported."* There is no UDP path into the Tor network, DNS-shaped or otherwise.
- **DNS-over-SOCKS is a CLIENT-SIDE UDP→TCP conversion.** Per the Tor docs: *"The SOCKS client on your local Tor daemon converts your DNS UDP request to TCP and then forwards it into the Tor tunnel. UDP packets never traverse the Tor network."* The conversion happens BEFORE the proxy; the proxy only ever sees TCP.
- **Mullvad is the same model.** Its SOCKS5 is TCP-only; "Proxy DNS" means the CLIENT sends the lookup through the SOCKS5 (TCP) so the resolution happens at the exit, not that a UDP datagram is sent to the proxy.
- **socks5h is exactly this:** the `h` = the proxy resolves the hostname (proxy-side), reached via a TCP SOCKS CONNECT/RESOLVE. No client UDP is involved.

## Why "allow UDP only for DNS" is the WRONG fix

- It would NOT work for Tor (the prime use case): Tor accepts zero UDP, so DNS-shaped UDP to the proxy is dropped by Tor itself — the tool would simply fail to resolve.
- It would reintroduce a UDP leak surface for marginal benefit (only proxies that DO support UDP-associate, which excludes Tor and is exactly where leaks hide).
- It would break the single clean invariant ADR-0003 buys ("UDP is dropped, period"). The conditional "UDP, but only if it looks like DNS" is harder to make leak-proof than "no UDP".

So the question productively CONFIRMS ADR-0003 rather than reopening it: keep UDP hard-blocked, AND convert the tool's DNS to a SOCKS-TCP resolution locally.

## The correct mechanism (what tooljail must build)

A **DNS-to-SOCKS-TCP forwarder** inside the jail's netns:

1. The wrapped tool emits ordinary UDP (or TCP) DNS to its `resolv.conf` nameserver.
2. tooljail points the tool's `resolv.conf` at the forwarder's address.
3. The forwarder takes each query and RESOLVES IT VIA THE SOCKS PROXY OVER TCP (a socks5h CONNECT to the proxy, or a SOCKS-tunnelled DNS-over-TCP to a resolver), then answers the tool.
4. UDP never leaves the jail (ADR-0003 holds); the host resolver NEVER sees the name (no leak).

This is exactly what `tor-resolve`, Tor's `DNSPort`, and `dns2socks` do. tun2socks itself does NOT do this (confirmed live: it has no DNS handling and only tunnels packets), which is why the jail needs the forwarder as a distinct component.

## Live confirmation of the gap (2026-06-30 smoke)

With the Option-A topology (tun2socks sidecar + tool sharing the netns), the tool's `resolv.conf` (from pasta) pointed at `169.254.1.1` and `192.168.1.1` (the host gateway). DNS queries went to `192.168.1.1:53` — the REAL host resolver — and returned NXDOMAIN for the test name: a DNS LEAK and a resolution failure. tun2socks tunnels packets but does not convert DNS to a SOCKS-TCP resolution, so without the forwarder the jail leaks DNS. This is the seam the `spike-dns-to-socks-bridge` spike proves and the jail task wires.

## Corollary recorded for the build

tun2socks's `--proxy` flag rejects the `socks5h://` scheme (`unsupported protocol: socks5h`) and uses `socks5://`; its tunneling is remote-resolving by construction, so tun2socks `socks5://` IS socks5h semantics for TCP. tooljail must translate the user-facing `socks5h://` to `socks5://` for the tun2socks sidecar env. (DNS is still handled by the forwarder above, not by tun2socks.)
