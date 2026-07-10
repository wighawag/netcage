# Host-loopback reachback (`--allow 127.0.0.1:<port>`) is a second class of the unified `--allow`, via the shared-netns pasta map, guarded by a stricter port-blocklist

**Status:** proposed (design decision; builds on ADR-0002 pasta reachback, ADR-0005 guardrailed-hole precedent, ADR-0018 never-a-clear-DNS-hole, ADR-0003 UDP hard-drop. Confirmed by `work/notes/findings/spike-pasta-host-loopback-second-port-to-tool.md`. Ships with task `allow-host-loopback-reachback`, which is blockedBy `allow-require-explicit-port-and-rename`.)

## Context

netcage's `run` gains the ability to let a jailed tool reach ONE service on the HOST's `127.0.0.1:<port>` (e.g. a same-host model server bound to loopback only) DIRECTLY, while all other egress stays forced through the socks5h proxy, fail-closed. Today the only sanctioned way to reach a same-host model is to bind it to `0.0.0.0` and `--allow-direct <host-lan-ip>:<port>`, which exposes the model to the whole LAN and hairpins host-local traffic out the NIC and back. Binding loopback-only and reaching it directly keeps the model private to the host. This is the netcage counterpart of anonctl's `loopback-exemption` (ADR-0008 there); the two tools share the `--allow` vocabulary and the loopback guardrail's INTENT, but NOT the mechanism (anonctl uses a per-UID nftables port-allow; netcage uses its netns/pasta reachback).

Two structural facts make this NOT "just add `127.0.0.1` to the LAN allowlist":

1. **`127.0.0.1` typed by the user means the HOST's loopback, not the jail's own.** Inside the shared netns the jail's own `127.0.0.1` is already freely reachable and useless for reaching a host service. The user types the HOST's loopback address; netcage translates it to the in-jail pasta map address at rule-emit time. The docs and the branch MUST be explicit about this (a `--allow 127.0.0.1:<port>` reaches a HOST service via the reachback, not a container-local port).

2. **Host reachback is the single most leak-prone seam (ADR-0002), and loopback is where the anonymizer's control surface lives** (the socks5h proxy port, and the conventional Tor/SOCKS/control ports). A loopback hole to the wrong port would let the jailed tool dial the proxy's SOCKS surface directly and bypass the forced path, or hit a Tor control port (a self-deanonymization vector). So the loopback branch needs a STRICTER guardrail than the LAN branch's "must be an RFC1918/link-local range".

The prerequisite `allow-require-explicit-port-and-rename` (ADR-0020) already made the exemption port-mandatory and renamed `--allow-direct` -> `--allow`, so LAN and host-loopback holes are now the SAME shape (exact `host:port`), differing only in the per-class guardrail. This ADR records the second class.

## Decision

**A host-loopback destination `127.0.0.1:<port>` is a SECOND class of the unified `--allow` flag, dispatched on the typed address, wired through the SAME pasta host-loopback reachback the sidecar already uses, and guarded by a STRICTER port-blocklist. There is NO new flag and NO new config field.**

### Mechanism: Mechanism A (the split-tunnel mechanism, generalised to the pasta map address)

The spike (`spike-pasta-host-loopback-second-port-to-tool`) proved, live, that:

- The tool container shares the sidecar's netns (`--network container:<sidecar>`, ADR-0001), so it inherits the sidecar's pasta host-loopback map (`169.254.1.1`). A SECOND accept port on that map is reachable from the TOOL while an nft/iptables `drop` on the map still closes every other host-loopback port. Adding the second accept does not weaken the drop.
- With NO accept for a port, that port is DROPPED (off-by-default holds: exposure is opt-in per port, never a side effect of the shared netns).

So a host-loopback `--allow 127.0.0.1:<port>` emits, in `firewallScript`:

- an `iptables -A OUTPUT -p tcp -d 169.254.1.1 --dport <port> -j ACCEPT` in the ENABLING block, BEFORE the `-A OUTPUT -d 169.254.1.1 -j DROP` closer (exactly where the proxy-reachback accept goes); and
- it requires the pasta `--map-host-loopback,169.254.1.1` sidecar option, the `169.254.1.1/32` `TUN_EXCLUDED_ROUTES` entry (so the dial egresses the real NIC via pasta, not the TUN), and the `-d 169.254.1.1 -j DROP` closer, ALL present.

The user's typed `127.0.0.1:<port>` is REWRITTEN to the map address `169.254.1.1:<port>` at rule-emit time; the user never types `169.254.1.1` (an internal reserved address).

**The map exists whenever there is at least one host-loopback `--allow` entry, INDEPENDENT of proxy locality.** Today `--map-host-loopback` is added only for a host-loopback proxy. A host model on loopback needs the map even with a REMOTE proxy, because the model reachback is orthogonal to the proxy reachback (the idea note's open question, resolved). When the proxy is ALSO host-loopback, the map is shared: one map address, one drop closer, and two (or more) accepts (the proxy port + each host-model port).

### The stricter loopback port-blocklist (load-bearing; refused at parse time)

A host-loopback `--allow` whose port is on this blocklist is REFUSED LOUDLY at config time, naming the port + the reason. The blocklist is the loopback analogue of the LAN branch's `networkWithinPrivateRanges`:

- **53** (clear DNS): DNS stays on the jail's proxy-side socks5h forwarder, never a direct loopback query (consistent with ADR-0018).
- **the configured proxy port**: allowing it would let the tool dial the SOCKS surface directly and bypass the forced path.
- **9050** (conventional Tor SocksPort) and **9150** (conventional Tor Browser SocksPort): same skip-the-forced-path risk.
- **9051** (conventional Tor CONTROL port): a self-deanonymization vector (`GETINFO`, `SIGNAL NEWNYM`, circuit inspection).
- **1080** (conventional generic SOCKS port): same skip-the-forced-path risk.

The well-known ports (53/9050/9150/9051/1080) are host-independent and belong in the context-free CLI/config parse. The configured PROXY port is known only where the proxy config is (the run wiring), so it is refused there. Both fire at config time, before any container/firewall mutation, so a refusal leaves the host untouched. A LAN `--allow` is NEVER subject to this blocklist (a LAN host's `:9050` is a different socket than host loopback).

**Completeness of this blocklist is now a load-bearing invariant.** Before this feature, the tool netns had NO host reachback at all (ADR-0002: sidecar-only). This feature opens host loopback to the tool for exactly the named non-anonymizer ports. Safety that "the tool cannot dial the anonymizer's control surface" now rests on this blocklist being complete; a missing port would be an exemptable hole into that surface. Extend it only with a recorded reason.

## Considered options

- **Mechanism A: per-port host-loopback accept on the shared pasta map (chosen).** Reuses the vetted split-tunnel/reachback mechanism (a second accept before the map's drop closer). Proven leak-tight by the spike (second port reachable from the tool, control port dropped, off-by-default holds). Simplest: no new process, no new hop.
- **Mechanism B: a forwarder process in the sidecar (rejected).** The idea note's conservative default, under the premise that the tool netns is isolated from the sidecar's pasta map. It is NOT: tool and sidecar share one netns, so there is no netns crossing to bridge. B would add a process, a lifecycle, and a hop for zero security benefit. Rejected.
- **Mechanism C: reuse the `forward` verb's plumbing inverted (rejected as the mechanism, kept as a naming precedent).** The `forward` verb (ADR-0014) is a HOST->jail inbound relay; this is the INVERSE (jail->host-loopback egress) and rides the firewall/reachback path, not a userspace host relay. Its guardrail SHAPE (exactly-one-port, TCP-only, off-by-default) is a good precedent, but the data direction differs, so it is not a reuse.
- **A separate `--allow-host-loopback` flag / config field (rejected).** The user already makes the class obvious by typing `127.0.0.1:<port>` vs a LAN `<ip>:<port>`; a unified `--allow` with internal class-dispatch is simpler and needs no cross-misuse errors. Mirrors anonctl's ADR-0008 decision so the two tools' vocabulary stays identical.
- **Widening the ADR-0002 sidecar-only invariant silently (rejected).** ADR-0002 scoped host reachback to the sidecar-only and to the proxy port only. This feature DOES extend host-loopback reachability to the tool, but ONLY for operator-named non-anonymizer ports, with the map's DROP closer still authoritative for everything else, and with the stricter port-blocklist refusing the control surface. The extension is explicit and guarded, not a silent widening; this ADR is the record of that deliberate scope change.

## Consequences

- A jailed tool can reach a same-host loopback service directly by naming its exact `127.0.0.1:<port>`, without binding it to `0.0.0.0`. Any attempt to name the proxy port, a Tor/SOCKS/control port (9050/9150/9051/1080), or 53 is refused loudly at config time (naming the port), so the failure is self-explaining and cannot silently open a deanonymization vector.
- **Off by default, byte-identical strict jail.** With no host-loopback `--allow` entry, NO extra map/accept/excluded-route/drop is emitted for the model case, and the jail is byte-identical to today (the ADR-0005 stance, extended to this class). For a remote-proxy jail with no host-loopback allow, `--map-host-loopback` is NOT added.
- **TCP only.** UDP stays hard-dropped (ADR-0003) even to the allowed host-loopback port; the accept is TCP-only by construction.
- **verify-covered.** `verify` must prove the exempted host-loopback port IS reachable from the tool AND that the rest of host loopback (and the proxy/control ports) STAY unreachable, mirroring the split-tunnel-tight assertion on the loopback map. A probe that cannot run FAILS LOUD (never a silent pass).
- The ADR-0002 sidecar-only invariant is deliberately extended (tool now reaches the named host-loopback ports too), with the map's DROP closer and the port-blocklist as the guardrails that keep the extension exactly as narrow as the operator named. Blocklist completeness is a maintenance obligation (a new conventional anonymizer loopback port must be added here or it becomes an exemptable hole).

## Implementation notes (amended when the task `allow-host-loopback-reachback` landed)

Two load-bearing refinements were settled at implementation time and are recorded here (this ADR owns the mechanism + blocklist), rather than in a new ADR:

- **The RFC1918/link-local defense-in-depth DROPs are gated on a LAN allow, not on any non-empty allowlist.** The split-tunnel LAN feature (ADR-0005) emits the RFC1918/link-local range DROPs to make a non-allowlisted neighbour of an allowed LAN host a clean DROP. A host-loopback-only allowlist has NO LAN direct to defend, so it does NOT emit those LAN DROPs; it adds only the map accept(s) + the map DROP closer. This keeps a remote-proxy-plus-host-model jail byte-identical to the strict jail on its LAN shape (it gains only the host-loopback map rules), and it is what makes the off-by-default invariant hold for the model case without pulling in LAN drops the operator never asked for. A mixed allowlist (a LAN entry AND a host-loopback entry) emits both: the LAN DROPs for its LAN half and the map closer for its loopback half.

- **The configured-proxy-port reject fires only when the proxy is itself on host loopback.** The rationale for refusing the proxy port on the host-loopback class is "the tool could dial the proxy's SOCKS surface directly ON host loopback and bypass the forced path". That risk exists only when the proxy actually listens on the host's loopback (the local Tor / `ssh -D` case, the same host set as `ProxyOnHostLoopback`: `127.0.0.1` / `::1` / `localhost`). A REMOTE proxy on the same port NUMBER is a different socket on a different host, so a host-loopback `--allow` on that number does not reach it; the reject is therefore scoped to a loopback proxy. The host-INDEPENDENT well-known ports (53/9050/9150/9051/1080) are still refused unconditionally in the context-free parse regardless of proxy locality.

- **The whole `127.0.0.0/8` class dispatches to the host-loopback branch, and every host-loopback entry is rewritten to the single map address `169.254.1.1` at rule-emit time.** The user typically types `127.0.0.1`, but any `127.0.0.x` is treated as the HOST's loopback and rewritten to the one reserved in-jail map address (there is one map, so the destination collapses to `169.254.1.1:<port>`). When the proxy is ALSO on host loopback, the map route is SHARED and the `169.254.1.1/32` excluded route is emitted exactly once (deduped), not twice.
