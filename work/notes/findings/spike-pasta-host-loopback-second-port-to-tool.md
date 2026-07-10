---
title: pasta host-loopback reachback extends to a SECOND port reachable from the TOOL netns (via the shared sidecar netns) with per-port nft narrowing; Mechanism A confirmed, Mechanism B unnecessary
slug: spike-pasta-host-loopback-second-port-to-tool
source: 'captured live on this host 2026-07-10 (podman 5.4.2 rootless, netavark, pasta/passt; iptables in-netns) reusing the probe sources from work/tasks/done/spike-pasta-loopback-reachback/probe/ (built CGO_ENABLED=0 static for the alpine test containers). Three throwaway host-loopback listeners + a pasta sidecar + a `--network container:` tool + the A/B/C probe below. All torn down.'
relates: [ADR-0002, ADR-0005, idea loopback-reachback-for-a-host-local-service]
---

# Extending the pasta host-loopback reachback to a SECOND port, reachable from the TOOL (spike result)

**Verdict: POSITIVE. Mechanism A (per-port host-loopback forward reachable from the TOOL netns) works via the EXACT SAME mechanism split-tunnel already uses, so Mechanism B (a sidecar forwarder) is unnecessary.** This re-runs the ADR-0002 spike "for a second port" (the open question the idea note named) and adds the piece the original spike did not test: reachability from the TOOL container, not just the sidecar.

## Why this spike existed (what the original ADR-0002 spike did NOT prove)

The original `spike-pasta-loopback-reachback` proved: (1) the sidecar reaches the host-loopback proxy port via the pasta map `169.254.1.1`; (2) an nft/iptables drop narrows the sidecar to exactly that one port; (3) a **`--network none`** "tool" container has NO host reachback at all. Point (3) is what made the idea note treat "reach a host model from the TOOL" as an open, delicate question, and it is what made Mechanism B (forward through the sidecar) look like the conservative default.

But netcage's REAL tool container is NOT `--network none`: it joins the sidecar's netns with `--network container:<sidecar>` (ADR-0001, jail.go). Tool and sidecar therefore SHARE one netns: one `127.0.0.1`, one pasta map `169.254.1.1`, one routing table, one iptables ruleset (`firewallScript`, ADR-0008). So the real question was never "can the isolated tool netns reach host loopback" (it has no separate netns); it was "does adding a SECOND accept port on the shared pasta map expose exactly that port to the tool, while the drop still closes the rest?"

## The three assertions, proven (from BOTH the sidecar AND the tool)

Setup: three throwaway host-loopback listeners, `127.0.0.1:29050` (banner PROXY, the reachback port), `127.0.0.1:29080` (banner MODEL, the new second port to expose), `127.0.0.1:29051` (banner CONTROL, must stay closed), all confirmed free first. A pasta sidecar `--network pasta:-I,ncspike0,--map-host-loopback,169.254.1.1 --cap-add NET_ADMIN` and a `--network container:<sidecar>` tool, each running the static dialer.

1. **Blunt map, address-scoped (Phase 0).** BEFORE any narrowing, BOTH the sidecar AND the tool reached all three ports via `169.254.1.1:<port>`. The map is address-scoped, not port-scoped (consistent with the original spike), and the TOOL inherits it because it shares the netns. So per-port narrowing is mandatory and is an iptables concern, not a pasta one.

2. **A SECOND accept coexists with the drop (Phase 1, the decisive one).** Applying the netcage `firewallScript`-shaped ruleset into the shared netns:
   ```
   -A OUTPUT -d 169.254.1.1/32 -p tcp -m tcp --dport 29050 -j ACCEPT   # proxy reachback
   -A OUTPUT -d 169.254.1.1/32 -p tcp -m tcp --dport 29080 -j ACCEPT   # the MODEL port (new)
   -A OUTPUT -d 169.254.1.1/32 -j DROP                                 # everything else on the map
   ```
   made the MODEL port reachable AND kept CONTROL dropped, **from BOTH the sidecar and the tool**. The second accept did not weaken the drop; the control port stayed closed. This is byte-identical in shape to the split-tunnel accepts (`writeSplitTunnelAccepts`) and to the proxy-reachback accept, both already shipped and tested.

3. **Off-by-default: no accept == dropped (Phase 2).** With ONLY the proxy accept (no model accept), the MODEL port was DROPPED exactly like CONTROL, from the tool. So exposure is OPT-IN PER PORT, never a side effect of the shared netns. An empty host-loopback allowlist leaves the model port closed, preserving the "empty allow == byte-identical strict jail" invariant (ADR-0005).

## What this means for the implementation task

- **Mechanism A is the mechanism, and it IS split-tunnel's mechanism, generalised from a LAN `/32` to the host-loopback map address `169.254.1.1`.** No new plumbing kind: a host-loopback `--allow 127.0.0.1:<port>` emits an `iptables -A OUTPUT -p tcp -d 169.254.1.1 --dport <port> -j ACCEPT` in the ENABLING block BEFORE the `-d 169.254.1.1 -j DROP`, exactly where the proxy-reachback accept goes. The tool reaches host `127.0.0.1:<port>` by dialling the in-jail map address `169.254.1.1:<port>` (the docs/branch must translate the user's typed `127.0.0.1:<port>` to the map address at rule-emit time; the user types the HOST's loopback, netcage rewrites it to the reachback map).
- **Mechanism B (sidecar forwarder) is unnecessary and should NOT be built.** It only made sense under the false premise that the tool netns is isolated from the sidecar's pasta map. It is not; they share the netns. B would add a process, a lifecycle, and a hop for zero benefit. Reject it in the ADR.
- **`--map-host-loopback` must be present for the host-model case even with a REMOTE proxy (the idea's open question, resolved).** Today `--map-host-loopback,169.254.1.1` is added ONLY when `ProxyOnHostLoopback` is true (jail.go `SidecarRunArgs`). A host model on `127.0.0.1:<port>` needs the pasta map REGARDLESS of proxy locality: the reachback for the model is ORTHOGONAL to the reachback for the proxy. So the implementation must add the map (and the `169.254.1.1/32` excluded route, and the map's `-j DROP` closer) whenever there is at least one host-loopback `--allow` entry, even if the proxy is remote. When the proxy is ALSO host-loopback, the map is shared (one map address, two accepts, one drop). This is the one wiring subtlety beyond "add a second accept".
- **TUN_EXCLUDED_ROUTES:** `169.254.1.1/32` is ALREADY in `excludedRoutes()` for the host-loopback proxy case; for the remote-proxy-plus-host-model case it must be ADDED (the model's dial to `169.254.1.1` must egress the real NIC via pasta, not the TUN, same enabler half as the proxy reachback and the split-tunnel directs).
- **The map's `-j DROP` closer is load-bearing and must be present whenever the map exists.** It is what keeps closure tight: with the map present but only the named ports accepted, every OTHER host-loopback port (including the proxy/control ports if not named, and they must be REFUSED by the guardrail anyway) is dropped. This mirrors the sidecar-only invariant of ADR-0002: the map exists, but the ruleset makes it "exactly the named ports and nothing else".

## Guardrail note (not a mechanism finding, but confirmed compatible)

The spike used arbitrary ports, but the real feature must REFUSE the proxy port and the conventional Tor/SOCKS/control ports (9050/9150/9051/1080) and 53 on the host-loopback branch (stricter than the LAN branch), because host loopback is where the anonymizer's control surface lives. Refusing those at parse time means they can never reach the accept-emitter, so the map's DROP closer stays authoritative for them. The mechanism proven here is indifferent to which ports are named; the guardrail is a separate (parse-time) concern that the task + ADR-0019 own.

## Teardown evidence

Both containers force-removed (`podman rm -f --depend`, confirmed GONE); all three host listeners killed and ports 29050/29080/29051 released; the temp dir `/tmp/netcage-spike2` removed; no `ncspike-*` containers left; no listener/dialer processes left. All iptables rules were applied INSIDE the container netns (via `nsenter -t <pid> -n -U --preserve-credentials`, the rootless-netns form) and died with the netns; NO host iptables rules were ever touched. (2026-07-10)
