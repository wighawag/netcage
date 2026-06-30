---
title: tun2socks receives NO packets in the Option-A shared-netns + pasta topology (jail forced-egress wall)
slug: jail-tun2socks-shared-netns-no-packets
---

# tun2socks gets no packets from the TUN in shared-netns + pasta (jail end-to-end wall)

Observed 2026-06-30 while building `jail-run-forced-egress`. The unit-level wiring is correct and green; the END-TO-END forced-egress step is not yet working because the real `xjasonlyu/tun2socks` image, in the chosen Option-A topology, never receives packets from the TUN.

## What was tried (Option A, shared netns)

Per ADR-0001/0002 + the requeue handoff:

1. tun2socks sidecar started: `podman run -d --network pasta:--map-host-loopback,169.254.1.1 --cap-add NET_ADMIN --device /dev/net/tun -e PROXY=socks5://169.254.1.1:<port> <pinned tun2socks>`. It comes up healthy: logs `[STACK] tun://tun0 <-> socks5://169.254.1.1:<port>`.
2. Tool container joins the SAME netns: `podman run --rm --network container:<sidecar> alpine wget http://<target>:<echoport>`.
3. nft narrowing + UDP drop applied in the shared netns via `nsenter ... nft` (works, rc=0).

## The symptom

The tool's connection **times out**, and tun2socks logs show **ZERO connection attempts** (no dial, no error) beyond startup — even when the tool targets an IP INSIDE the TUN subnet (`198.18.0.0/15`, e.g. `198.18.5.5`). So the packet is not reaching tun2socks's TUN reader at all.

Routing inside the shared netns LOOKS correct:

- `ip rule`: `32765: not from all fwmark 0x22b lookup 555` (unmarked traffic -> table 555 = the TUN). tun2socks marks its own dialer 0x22b so its proxy egress escapes the TUN.
- `ip route get 198.51.100.10` -> `dev tun0 table 555 src 198.18.0.1`. So the kernel SAYS the packet goes to tun0.
- The netns CAN reach the proxy at the pasta map (`169.254.1.1:<port>` TCP REACHABLE).

Yet tun2socks never reads the packet. The routing decision points at tun0 but the userspace tun2socks reader sees nothing.

## Notable detail (possible cause)

Table 555 (cloned from main via the entrypoint's `CLONE_MAIN=1`) contains TWO default routes: `default dev tun0 scope link` AND `default via 192.168.1.1 dev enx... metric 100` (the cloned real-NIC default). The presence of the real-NIC default in the TUN table is suspicious: a target not matched by a more-specific route could follow the real-NIC default and be dropped, rather than going to the TUN. (For an in-subnet target like 198.18.5.5 the `198.18.0.0/15 dev tun0` route should win, yet it still failed — so this may not be the whole story.)

## Leading hypothesis (for the next session): SEPARATE-netns, not shared-netns

The rootless-TUN spike (`spike-rootless-tun-routing`) PROVED a TUN routes packets in rootless podman — but with the spike's OWN reader, in a `--network none` container that created its own TUN. The Option-A shared-netns arrangement (tool joins the sidecar's pasta netns, tun2socks reads tun0) may be where it breaks. The **separate-netns topology** is the leading alternative to try:

- Tool container in its OWN `--network none` netns with the TUN (as the spike did), and tun2socks reading THAT tun — i.e. run tun2socks against the tool's netns, OR have the tool's netns TUN be what tun2socks bridges. The spike's success was exactly this shape (own netns + own TUN), so aligning the real image with it is the obvious next experiment.
- Alternatively: investigate why tun2socks-in-shared-netns gets no packets — rp_filter / the double-default-route in table 555 / whether `--network container:` actually shares the routing tables the way assumed / whether tun2socks needs the TUN created a specific way vs the entrypoint's `ip tuntap`.

## What IS proven and green (so the next session starts from a real base)

- `internal/dnsforwarder` — DNS-to-SOCKS-TCP bridge, unit-tested (resolves through proxy, fails closed). The DNS seam is solved.
- `internal/jail` unit tests — sidecar args, tool args, nft ruleset, socks5h->socks5 translation, teardown (the teardown integration test PASSES: containers are cleaned up).
- `internal/socks5hfixture` — extended with AllowIPConnect + RedirectTarget for the by-IP forced-egress harness.
- `cmd/tooljail-dns` — the in-netns DNS forwarder helper.
- The end-to-end forced-egress integration test exists as a READY harness (`TestJail_ForcedEgress_ExitIPIsProxys`), currently `t.Skip`-ped with this reason. Un-skip it once the topology is fixed; it asserts the tool's observed exit IP equals the fixture's exit IP (forced egress) by IP, with the DNS-through-proxy assertion deferred to `verify-leak-test`.

## Corollaries already captured elsewhere

- DNS-over-proxy is TCP not UDP (Tor/Mullvad): `work/notes/findings/dns-through-socks-is-tcp-not-udp.md`.
- The DNS forwarder mechanism: `work/notes/findings/spike-dns-to-socks-bridge.md`.
- tun2socks rejects `socks5h://` and uses `socks5://` (its tunneling is remote-resolving by construction): same DNS finding.

---

## RESOLVED 2026-06-30 (this diagnosis was WRONG)

Live re-investigation overturned the "tun2socks gets no packets" diagnosis. tun2socks DID read the
tool's packets and DID dial the proxy. The end-to-end wall was two fixable sidecar-env issues, NOT
the shared-netns topology:

1. `CLONE_MAIN=1` (the image default) cloned the real main table (incl. the pasta-copied real NIC
   default) into the TUN routing table, causing a routing loop / packet storm (tun0 RX ~200 KB/s
   idle, thousands of sockets). Fix: `CLONE_MAIN=0`.
2. The proxy reachback address (`169.254.1.1`) routed INTO the TUN, so tun2socks's own dialer looped
   back through tun0 (source `198.18.0.1`) and pasta reset it. Fix:
   `TUN_EXCLUDED_ROUTES=169.254.1.1/32` forces the proxy address onto the real NIC (the pasta map).

With both set, a wrapped wget through the Option-A shared-netns jail returned the fixture exit IP
`127.0.0.2` rc=0 (reproduced twice). **Keep Option A; do NOT pivot to separate-netns.** Full recipe,
evidence, and a test-harness caveat (a mis-framed SOCKS5 listener that faked a "pasta corrupts
streams" red herring) are in `work/notes/findings/spike-jail-forced-egress-clone-main-and-excluded-route.md`.
