---
title: Spike - split-tunnel LAN allowlist works via TUN_EXCLUDED_ROUTES + nft (TCP-only, leak-tight)
slug: spike-split-tunnel-lan-allowlist
source: live spike on 2026-07-01, rootless podman + Tor SOCKS 127.0.0.1:9050 + a real llama.cpp on 192.168.1.150:8080; scripts under /tmp/tj-spike (throwaway, no residue).
---

# Spike: split-tunnel LAN allowlist

POSITIVE. A rootless jailed container CAN reach a specific RFC1918 LAN host DIRECTLY (TCP) while ALL other egress still goes through the SOCKS proxy, using ONLY mechanisms netcage already has: `TUN_EXCLUDED_ROUTES` (the sidecar env the forced-egress build already uses for the proxy reachback) + an nft accept rule. The `anonymity-shell-and-lan-split-tunnel` idea note's Thread 2 is buildable and leak-tight; it does NOT need a new networking model.

## What was tested

Replicated netcage's jail wiring (`SidecarRunArgs` + `nftRuleset`, host-loopback / Tor case) and added the LAN host `192.168.1.150:8080` (a real llama.cpp) as a split-tunnel target. Signal convention: `HTTP/1.1 415` from the probe = reached llama.cpp DIRECTLY; `reset`/`timed out` = blocked (packet went to the TUN -> Tor, which resets an RFC1918 target).

## The decisive matrix

Probing the allowlisted host `192.168.1.150:8080` and the non-allowlisted gateway `192.168.1.1:80`:

| Host in `TUN_EXCLUDED_ROUTES`? | nft LAN rule | allowlisted host `.150:8080` | gateway `.1:80` |
|---|---|---|---|
| yes (`.150/32`) | narrow `accept .150 tcp dport 8080` + rfc1918 `drop` | **HTTP 415 (direct)** | timed out (dropped) |
| yes (`.150/32`) | default (no LAN rule) | **HTTP 415 (direct)** | reset (blocked) |
| no | narrow accept | reset (blocked) | timed out |
| no (today's DEFAULT jail) | default | reset (blocked) | reset (blocked) |

## What the matrix proves (the mechanism)

1. **`TUN_EXCLUDED_ROUTES` is the ENABLER.** The LAN host is reachable directly IFF its `/32` is in the excluded routes (rows 1-2). Without it (rows 3-4) the packet goes to the TUN -> tun2socks -> the SOCKS proxy, and Tor resets the RFC1918 target. So excluding the host `/32` is what opens the direct path; pasta already copies the host's real-NIC LAN route into the netns (`192.168.1.0/24 dev <nic>` + `default via <gw>` are present), so once a destination is excluded from the TUN it egresses the real NIC to the LAN.
2. **Excluding a `/32` exposes ONLY that `/32`, not the whole `/24`.** Row 1 vs the gateway column: with only `.150/32` excluded, the gateway `.1` is NOT directly reachable. (An earlier ambiguous run suggested the whole /24 was exposed; that was an artifact of an nft ruleset that failed to apply. The corrected matrix is clear: per-host `/32` exclusion is per-host.)
3. **nft is the NARROWING / defense-in-depth.** The narrow ruleset (`accept ip daddr .150 tcp dport 8080` then `192.168.0.0/16 drop`, `10.0.0.0/8 drop`, `172.16.0.0/12 drop`) makes non-allowlisted LAN a clean DROP (timeout) and narrows even the allowed host to exactly its port. Proven: `.150:9999` (wrong port) and `.1` (wrong host) both blocked while `.150:8080` works.
4. **Leak-proof elsewhere still holds.** With the split-tunnel active, a public fetch by IP (`http://1.1.1.1/`) still returned `HTTP/1.1 301, Server: cloudflare` THROUGH Tor. Excluding the LAN host did not break the proxy path for everything else.
5. **TCP-only; ADR-0003 (hard-block UDP) stays intact.** UDP to the allowlisted host is still dropped (`nc -u` -> `Operation not permitted`) while TCP to the same host works. So directs are TCP-only; UDP stays hard-dropped for everything including the allowlisted host.
6. **No pre-existing leak / no regression.** Today's DEFAULT jail (row 4: host neither excluded nor nft-allowed, exactly current `netcage`) BLOCKS the LAN host. The split-tunnel genuinely ADDS a narrow hole; it does not paper over an existing one.

## The buildable design this implies

To allowlist `HOST:PORT` (RFC1918 / link-local, TCP):

- add `HOST/32` to the sidecar's `TUN_EXCLUDED_ROUTES` (alongside the proxy reachback addr), so it egresses the real NIC via pasta instead of the TUN; AND
- add `ip daddr HOST tcp dport PORT accept` to the in-netns nft ruleset BEFORE the RFC1918/`drop` rules, with the RFC1918 ranges dropped after as defense-in-depth.

Both are required together (the excluded route without the nft accept still works for the host but loses the narrowing/defense-in-depth; the nft accept without the excluded route does nothing because there is no direct route). Empty allowlist == today's strict jail (row 4), so the feature is off-by-default and additive.

## Confirmed constraints for the PRD

- **IP/CIDR only (no hostnames) for v1** - a LAN hostname cannot resolve through Tor (DNS is proxy-side, socks5h), and a local-resolver exception is another hole. Bare IP/CIDR sidesteps this. (The tested target was a bare IP.)
- **RFC1918 / link-local only** - restricting allowed directs to private ranges means a user cannot accidentally allow a PUBLIC IP that becomes a real anonymity leak. A public-IP direct, if ever wanted, needs a separate loud opt-in.
- **TCP-only** - UDP stays hard-dropped (ADR-0003) even to allowlisted hosts.
- **`verify` must be extended** - the leak-test must assert "everything EXCEPT the named directs still goes through the proxy (three core assertions hold for non-allowlisted traffic), AND the named directs are reachable", so the split-tunnel is proven tight, not merely present.

## Residue

None. All spike containers named `tj-spike-*`, torn down on exit; `podman ps -a` clean (only the unrelated `my-alpine`), no stray `nsenter`/`tun2socks` procs, host LAN route intact. The spike did NOT modify host networking (all nft/route changes were inside the throwaway sidecar netns via nsenter).
