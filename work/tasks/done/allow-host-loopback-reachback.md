---
title: Host-loopback reachback via the unified --allow (exact 127.0.0.1:port to a same-host service, through the shared-netns pasta map, with a stricter port-blocklist)
slug: allow-host-loopback-reachback
blockedBy: [allow-require-explicit-port-and-rename]
covers: []
---

## What to build

Let the unified `--allow` flag accept a same-host HOST-loopback destination `127.0.0.1:<port>` (e.g. a local AI/model server bound to loopback only), so the jailed tool can reach that ONE trusted host-loopback port DIRECTLY while every OTHER host-loopback destination stays closed and all external egress stays forced through the socks5h proxy, fail-closed. This is the netcage counterpart of anonctl's landed `loopback-exemption` (anonctl ADR-0008); the two share the `--allow` vocabulary and the loopback guardrail's INTENT, but NOT the mechanism (anonctl: per-UID nftables port-allow; netcage: pasta host-loopback reachback in the shared sidecar netns). See `work/notes/idea-loopback-reachback-for-a-host-local-service.md`, the resolved mechanism finding `work/notes/findings/spike-pasta-host-loopback-second-port-to-tool.md`, and the design ADR `docs/adr/0019-host-loopback-reachback-is-a-unified-allow-with-a-stricter-port-blocklist.md`.

Motivating case: run a same-host model bound to loopback only, without forcing it onto `0.0.0.0` (which exposes it to the whole LAN and hairpins host-local traffic out the NIC and back). Binding loopback-only keeps the model private to the host.

The MECHANISM IS ALREADY RESOLVED (do not re-open the spike; do build on it). The `spike-pasta-host-loopback-second-port-to-tool` finding proved, live, that Mechanism A works: the tool shares the sidecar's netns (`--network container:<sidecar>`), so it inherits the sidecar's pasta host-loopback map `169.254.1.1`; a SECOND accept port on that map is reachable from the TOOL while the map's `-j DROP` closer keeps every other host-loopback port closed, and an un-accepted port is dropped (off-by-default holds). Mechanism B (a sidecar forwarder) is REJECTED (unnecessary: tool and sidecar share the netns, there is no crossing to bridge). ADR-0019 records this; do not build a forwarder.

This LAYERS on the landed `allow-require-explicit-port-and-rename`, which already made `--allow` port-mandatory and exact-host:port-only. So a host-loopback exemption is the SAME exact-host:port shape as a LAN one; ONE flag (`--allow`), ONE config key (`allow`), and netcage DISPATCHES on the address the user typed (`127.0.0.1` vs `192.168.x.x`). No new flag, no new config field.

### The class-dispatch (loopback vs LAN), at parse and rule-emit time

- **`--allow 127.0.0.1:<port>` routes to the host-loopback branch; `--allow 192.168.1.150:<port>` routes to the LAN branch.** The parse inspects the address: a host-loopback address (`127.0.0.0/8`) goes to the loopback guardrail branch (below); an RFC1918/link-local address goes to the existing LAN guardrail (`networkWithinPrivateRanges`).
- **The user types the HOST's loopback; netcage rewrites it to the reserved in-jail pasta map address `169.254.1.1` at rule-emit time.** The docs AND the branch MUST be explicit that `--allow 127.0.0.1:<port>` reaches a HOST service via the reachback, NOT the container's own loopback (which is already freely reachable inside the netns and useless for a host service). The user never types `169.254.1.1`.

### The loopback guardrail branch (STRICTER than the LAN branch)

Host loopback is where the anonymizer's control surface lives, so the loopback branch REJECTS a port-blocklist LOUDLY at config time (naming the port + reason). This blocklist is the loopback analogue of the LAN branch's `networkWithinPrivateRanges` and its completeness is LOAD-BEARING (ADR-0019):

- **53** (clear DNS): DNS stays on the jail's proxy-side socks5h forwarder (ADR-0018).
- **the configured proxy port**: allowing it lets the tool dial the SOCKS surface directly and bypass the forced path.
- **9050** (Tor SocksPort), **9150** (Tor Browser SocksPort), **9051** (Tor CONTROL port — a self-deanonymization vector), **1080** (generic SOCKS): conventional anonymizer/control ports.

The well-known ports (53/9050/9150/9051/1080) are host-independent and are refused in the context-free CLI/config parse. The configured PROXY port is known only where the proxy config is (the run wiring), so it is refused THERE. Both fire at config time, before any container/firewall mutation, so a refusal leaves the host untouched. A LAN `--allow` is NEVER subject to this blocklist.

### The mechanism wiring (Mechanism A; all halves required)

- **`iptables -A OUTPUT -p tcp -d 169.254.1.1 --dport <port> -j ACCEPT`** in the ENABLING block of `firewallScript`, BEFORE the `-A OUTPUT -d 169.254.1.1 -j DROP` closer (exactly where the proxy-reachback accept goes). One accept per host-loopback `--allow` entry.
- **The pasta `--map-host-loopback,169.254.1.1` sidecar option MUST be present whenever there is at least one host-loopback `--allow` entry, INDEPENDENT of proxy locality.** Today it is added only for a host-loopback proxy (`ProxyOnHostLoopback`). A host model on loopback needs the map even with a REMOTE proxy (the model reachback is orthogonal to the proxy reachback — the idea's open question, resolved in ADR-0019). When the proxy is ALSO host-loopback, the map is SHARED (one map address, one DROP closer, the proxy-port accept + each host-model-port accept).
- **`169.254.1.1/32` in `TUN_EXCLUDED_ROUTES`** so the model dial egresses the real NIC via pasta, not the TUN (the enabler half). It is already present for the host-loopback-proxy case; ADD it for the remote-proxy-plus-host-model case.
- **The `-A OUTPUT -d 169.254.1.1 -j DROP` closer MUST be present whenever the map exists** (it keeps every non-named host-loopback port closed). Update `firewallVerifyRules` to assert the map accept(s) + the DROP closer for the host-loopback case.

### Persistence + start-reconcile + defaults: NO new field

Host-loopback exemptions ride the SAME `allow` config key / `AllowDirect` slice / CLI plumbing / `main.go` overlay / `start`-reconcile path as LAN ones, stored raw as `127.0.0.1:<port>`. Nothing new to thread; the class-dispatch happens at parse/generate time from the raw address. The `start`-reconcile (ADR-0011) must treat a changed host-loopback allow like any other jail-config change (refuse a differing config).

## Acceptance criteria

- [ ] `--allow 127.0.0.1:<port>` (a non-blocklisted TCP port) makes that same-host HOST-loopback service reachable DIRECTLY from the jailed tool, WITHOUT binding it to `0.0.0.0`; it rides the same `--allow` flag and `allow` config key as a LAN exemption (no new flag, no new field).
- [ ] The host-loopback branch REJECTS loudly, at config time, naming the port + reason: 53; the configured proxy port; 9050/9150/9051/1080. (Port-omitted is already rejected globally by the prerequisite task.) A LAN `--allow` is unaffected by this blocklist.
- [ ] The pasta `--map-host-loopback,169.254.1.1` option, the `169.254.1.1/32` excluded route, the per-port map accept(s), AND the `169.254.1.1 -j DROP` closer are ALL emitted when there is a host-loopback `--allow` entry, INCLUDING with a REMOTE proxy; and NONE of them are emitted (for the model case) when there is no host-loopback allow (off-by-default: an empty allow == byte-identical strict jail, ADR-0005; a remote-proxy jail with no host-loopback allow does NOT get `--map-host-loopback`).
- [ ] Every OTHER host-loopback port stays UNREACHABLE from the tool (the map's DROP closer holds): the tool reaching any non-named `127.0.0.1:<other>` (via the map) is DROPPED, so the exemption does not widen host loopback. The proxy/control ports specifically stay unreachable (they are refused by the guardrail, so they can never be accepted).
- [ ] TCP only: UDP stays hard-dropped even to the allowed host-loopback port (ADR-0003); the accept is TCP-only by construction.
- [ ] The class-dispatch is unit-tested: a `127.0.0.1:<port>` entry routes to the loopback branch (blocklist rejects fire, and the emitted accept targets the map address `169.254.1.1`), and a private address routes to the LAN branch (targets the LAN `/32`), from the SAME `--allow` entry point.
- [ ] `verify` gains host-loopback coverage mirroring `split-tunnel-tight`: it PROVES the exempted host-loopback port IS reachable from the tool AND that the rest of host loopback (and the proxy/control ports) STAY unreachable. A probe that cannot run FAILS LOUD (ADR-0003 discipline), never a silent pass.
- [ ] The guardrail (port-blocklist) and the map-address rewrite are unit-tested (pure logic); the direct-reachable-but-still-tight behaviour is integration-tested behind the repo's integration tag, isolated to a throwaway jail, asserting host iptables/other jails are untouched.

## Blocked by

- `allow-require-explicit-port-and-rename`: this task assumes `--allow` is already port-mandatory, exact-host:port-only, and renamed. It extends the SAME `parseAllowDirect` / `firewallScript` / config plumbing that task touches, so it is serialized behind it (and to avoid a merge conflict on the same modules).

## Prompt

> Goal: let the unified `--allow` flag accept a same-host HOST-loopback destination `127.0.0.1:<port>` (e.g. a loopback-bound local model) so the jailed tool can reach it directly without binding it to `0.0.0.0`. This LAYERS on the landed `allow-require-explicit-port-and-rename` (which already made `--allow` port-mandatory, exact-host:port-only, and renamed). ONE flag, ONE config key; netcage DISPATCHES on the typed address (host-loopback vs RFC1918/link-local). netcage counterpart of anonctl's landed `loopback-exemption` (anonctl ADR-0008) — shared vocabulary, DIFFERENT mechanism (do not copy anonctl's per-UID nftables shapes).
>
> The MECHANISM IS ALREADY RESOLVED — build on it, do not re-spike. Read `work/notes/findings/spike-pasta-host-loopback-second-port-to-tool.md` and `docs/adr/0019-host-loopback-reachback-is-a-unified-allow-with-a-stricter-port-blocklist.md`. Mechanism A (a second per-port accept on the shared pasta map `169.254.1.1`, before the map's DROP closer, reachable from the tool because it shares the sidecar netns) is proven and chosen. Mechanism B (a sidecar forwarder) is REJECTED — do NOT build a forwarder.
>
> FIRST, check drift (WORK-CONTRACT.md "Drift is a needs-attention signal"): read the LANDED `allow-require-explicit-port-and-rename` (flag/key names after the rename), `internal/cli/allowdirect.go` (`parseAllowDirect`, the private-range guardrail), `internal/jail/jail.go` (`firewallScript`, `writeSplitTunnelAccepts`, `excludedRoutes`, `SidecarRunArgs`, `proxyReachbackAddr`, `mappedHostLoopback`, `ProxyOnHostLoopback`, `firewallVerifyRules`), `internal/verify` (the split-tunnel-tight probe), the `start`-reconcile path (ADR-0011), and ADR-0002/0019. Adapt to what actually landed. If a dependency landed differently than assumed, route to needs-attention rather than build on a stale premise.
>
> The one new thing is a SECOND guardrail branch for the host-loopback address class, STRICTER than the LAN branch: reject (naming the port + reason) 53, the configured proxy port, and 9050/9150/9051/1080. The well-known ports go in the context-free parse; the proxy port is refused where the proxy config is known. Its completeness is load-bearing (ADR-0019).
>
> Mechanism wiring (all halves required): a `-p tcp -d 169.254.1.1 --dport <port> -j ACCEPT` per host-loopback entry (before the `-d 169.254.1.1 -j DROP` closer); the pasta `--map-host-loopback,169.254.1.1` option present whenever there is a host-loopback allow (EVEN with a remote proxy — the model reachback is orthogonal to the proxy reachback); `169.254.1.1/32` in `TUN_EXCLUDED_ROUTES` (already there for the host-loopback-proxy case; ADD it for remote-proxy-plus-host-model); and the DROP closer present whenever the map exists. Rewrite the user's typed `127.0.0.1:<port>` to the map address `169.254.1.1:<port>` at rule-emit time (the user never types the map address). Update `firewallVerifyRules`.
>
> NO new config field, NO new flag: host-loopback exemptions ride the same `allow` key / `AllowDirect` slice / CLI plumbing / start-reconcile, stored raw as `127.0.0.1:<port>`; the class-dispatch is at parse/generate time from the raw address. Keep the empty-allow == byte-identical strict jail invariant (ADR-0005): with no host-loopback allow, emit no map/accept/route/drop for the model case (and no `--map-host-loopback` for a remote-proxy jail).
>
> `verify`: add host-loopback coverage mirroring `split-tunnel-tight` — the exempted host-loopback port IS reachable from the tool while the rest of host loopback (and the proxy/control ports) STAY unreachable. Fail-loud if a probe cannot run (ADR-0003), never a silent pass.
>
> Seams to test at: the class-dispatch + the port-blocklist + the map-address rewrite (unit, everywhere) and the direct-reachable-but-still-tight behaviour (integration, behind the tag), isolated to a throwaway jail, asserting host iptables / other jails are untouched. RECORD non-obvious in-scope decisions per the task-template guidance; ADR-0019 already records the mechanism + blocklist, so amend it (not a new ADR) if you make a further durable decision. Run the repo's gate green before done.
