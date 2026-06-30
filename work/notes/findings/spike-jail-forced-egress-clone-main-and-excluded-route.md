---
title: The shared-netns + pasta jail DOES force egress; the wall was CLONE_MAIN=1 + the proxy address routing into the TUN (not "tun2socks gets no packets")
slug: spike-jail-forced-egress-clone-main-and-excluded-route
source: 'captured live on this host 2026-06-30 (podman 5.4.2 rootless, netavark, pasta/passt 0.0~git20250503; xjasonlyu/tun2socks v2.6.0 @sha256:aa931665f4a3ad9be7bc1ea5117c41471c20a770a62490e38090c839c1fef107). Reproduced end-to-end: a wrapped wget through the jail returned the proxy fixture exit IP 127.0.0.2 rc=0, twice, against two in-subnet targets. Overturns the diagnosis in work/notes/observations/jail-tun2socks-shared-netns-no-packets.md.'
---

# The Option-A shared-netns + pasta jail works; the real fix is CLONE_MAIN=0 + excluding the proxy address from the TUN

**Verdict: POSITIVE. The shared-netns topology was never the problem.** The prior observation
(`jail-tun2socks-shared-netns-no-packets.md`) concluded "tun2socks receives NO packets from the
TUN" and proposed pivoting to a separate-netns topology. That diagnosis was **wrong**. Live
re-investigation shows tun2socks DOES read the tool's packets and DOES dial the proxy; the
end-to-end path failed for two unrelated, fixable reasons. With both fixed, a wrapped tool run
through the Option-A jail exits from the proxy's IP. **Do not pivot to separate-netns; keep
Option A (ADR-0001/0002).**

## The two real causes (both in the tun2socks sidecar's entrypoint env)

The `xjasonlyu/tun2socks` image entrypoint creates `tun0`, builds a policy-routing table
(`TABLE=0x22b`, default `CLONE_MAIN=1`), and adds `ip rule not fwmark 0x22b lookup <table>` so
unmarked (tool) traffic goes to the TUN while tun2socks's own dialer (marked `0x22b`) escapes it.

1. **`CLONE_MAIN=1` poisons the TUN table and causes a packet storm.** With the default
   `CLONE_MAIN=1`, the entrypoint clones the WHOLE main table into table `0x22b` BEFORE replacing
   the default with `dev tun0`. Under pasta the netns contains a copy of the real host NIC
   (`enxc8a362ba9779`, `192.168.1.164/24`) and its routes, so table `0x22b` ends up with TWO
   defaults (`dev tun0` AND `via 192.168.1.1 dev enx...`) plus `198.18.0.0/15 dev tun0`. This
   created a routing feedback loop: tun0 RX climbed ~200 KB/s **with no tool running at all**, and
   tun2socks opened thousands of sockets. **Fix: `CLONE_MAIN=0`** so table `0x22b` is exactly
   `default dev tun0`. The idle flood drops to zero.

2. **The proxy's reachback address routed INTO the TUN, so tun2socks's dialer reset.** The
   host-loopback proxy is reached via the pasta map `169.254.1.1`. Unmarked, `169.254.1.1` matched
   the TUN default (`dev tun0 table 0x22b`), so tun2socks's dial to its own proxy was sent back
   into the TUN (a loop) with source `198.18.0.1` (the TUN address). pasta reset that connection
   (`[TCP] dial 169.254.1.1:18070: read tcp 198.18.0.1:...->169.254.1.1:18070: read: connection
   reset by peer`). A bare marked dial that egressed via the real NIC (source `192.168.1.164`)
   completed the full SOCKS handshake and returned the exit IP fine, proving pasta reachback itself
   is healthy. **Fix: `TUN_EXCLUDED_ROUTES=169.254.1.1/32`**, which the entrypoint turns into
   `ip rule add to 169.254.1.1 table main`, forcing the proxy address onto the real NIC (and the
   pasta map) instead of the TUN. The dialer then uses source `192.168.1.164` and pasta forwards it
   cleanly.

## The working recipe (sidecar env), proven end-to-end

```
podman run -d --name tooljail-run-<id>-sidecar \
  --network pasta:--map-host-loopback,169.254.1.1 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -e CLONE_MAIN=0 \
  -e TUN_EXCLUDED_ROUTES=169.254.1.1/32 \
  -e PROXY=socks5://169.254.1.1:<proxyport> \
  docker.io/xjasonlyu/tun2socks@sha256:aa93...  # the pinned redirector

# tool joins the shared netns:
podman run --rm --network container:tooljail-run-<id>-sidecar <image> <cmd...>
```

Resulting `ip rule` in the shared netns (the shape that works):

```
32763: from all to 169.254.1.1 lookup main          # proxy addr -> real NIC (the EXCLUDED route)
32764: from all to 198.18.0.1/15 fwmark 0x22b prohibit
32765: not from all fwmark 0x22b lookup 0x22b       # unmarked (tool) traffic -> table 0x22b -> tun0
32766: from all lookup main
32767: from all lookup default
```

For a **REMOTE** proxy (`socks5h://user:pass@bastion:1080`): no `--map-host-loopback`, and the
excluded route is the remote `host/32` (so tun2socks reaches the bastion over the real NIC, not the
TUN). Same `CLONE_MAIN=0`.

## Run evidence (2026-06-30)

A controllable test proxy on host `127.0.0.1:<port>` that dials a local HTTP echo FROM exit IP
`127.0.0.2` (the same shape `internal/socks5hfixture` provides with `ExitIP` + `RedirectTarget`):

```
tool: wget -qO- http://198.18.5.5:18090/   (an in-subnet target, captured by the TUN)
-> "127.0.0.2"  rc=0            # the proxy's exit IP, twice, two different targets
proxy log: CONNECT 198.18.5.5:18090 -> redirect to echo from 127.0.0.2
```

`podman ps -a` showed no leftover after `podman rm -f` the sidecar (the `--rm` tool and the
netns/nft die with it); only the unrelated pre-existing `my-alpine` remained.

## What this means for the tasks

- `internal/jail` must add `CLONE_MAIN=0` and `TUN_EXCLUDED_ROUTES=<proxy-host-or-map>/32` to
  `SidecarRunArgs` env. For a host-loopback proxy the excluded route is `169.254.1.1/32`; for a
  remote proxy it is the remote `host/32`.
- The forced-egress integration test `TestJail_ForcedEgress_ExitIPIsProxys` can be un-skipped once
  the env is wired; it already targets an in-subnet IP and uses the fixture's `AllowIPConnect` +
  `RedirectTarget`.
- **Keep Option A (shared netns).** The separate-netns pivot the observation proposed is
  unnecessary.

## Caveat (a test-harness wrinkle that cost time, recorded so it is not re-hit)

A throwaway python SOCKS listener used during diagnosis mis-framed the SOCKS5 greeting (read 2
bytes instead of the 3-byte VER/NMETHODS/METHODS), which corrupted the request and produced a
spurious "pasta mangles multi-write streams" red herring (it reproduced even host-direct with NO
container). pasta/slirp4netns stream forwarding is FINE. The lesson: frame SOCKS5 correctly in any
test proxy, and reproduce a suspected transport bug WITHOUT the container in the path before
blaming the network mode. `internal/socks5hfixture` already frames correctly.
