# Split-tunnel LAN allowlist: a guardrailed hole in forced egress

**Status:** accepted

netcage's `run` gains an opt-in `--allow-direct <IP|CIDR>[:port]` (repeatable) that lets a jailed tool reach specific **RFC1918 / link-local** destinations DIRECTLY over the real LAN, while ALL other egress stays forced through the socks5h proxy, fail-closed, exactly as today. An EMPTY allowlist (the default) is byte-for-byte today's strict jail. This is a deliberate, narrow hole in the forced-egress invariant, introduced so tightly it cannot become the fail-open leak the project exists to prevent.

The motivating case: run a jailed agent harness whose web/search/tool egress is anonymized through the proxy, while it still reaches ONE trusted local service (e.g. a `llama.cpp` on `192.168.1.150:8080`) that must NOT go through the proxy (a Tor/anonymizing proxy cannot and must not route to an RFC1918 address).

## The mechanism (two required halves)

Both halves are required together; the spike (`work/notes/findings/spike-split-tunnel-lan-allowlist.md`) proved each ALONE is insufficient:

- **Enabler: `TUN_EXCLUDED_ROUTES`.** Each allowed net (`HOST/32` for a bare IP, or the CIDR) is added to the sidecar's `TUN_EXCLUDED_ROUTES` env ALONGSIDE the existing proxy-reachback `/32`. pasta already copies the host's real-NIC LAN route into the netns, so excluding a destination from the TUN is what lets it egress the real NIC to the LAN instead of being pushed into the TUN and forced through the proxy. The env is a COMMA-separated list the tun2socks entrypoint turns into `ip rule add to <route> table main` per route. Without the exclusion the packet goes to the TUN, and the proxy (Tor) resets the RFC1918 target.
- **Narrowing: nft.** For each entry the in-netns ruleset emits `ip daddr <net> tcp dport <port> accept` (port omitted => `ip daddr <net> meta l4proto tcp accept`, all TCP ports) BEFORE the fail-closed drops, then explicit **RFC1918-range `drop`** rules (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) AFTER as defense-in-depth. The excluded route alone would leave a non-allowlisted host on the same LAN merely unrouted-to-the-proxy; the range drops make it a clean DROP, so allowing `192.168.1.150` does not silently expose the rest of `192.168.1.0/24`.

## Guardrails (all load-bearing)

- **Off by default.** No `--allow-direct` means today's EXACT strict jail. The accept + RFC1918-drop nft block and the extra excluded routes are emitted ONLY for a non-empty allowlist. Today's default jail has NO RFC1918 drops at all (its fail-closed comes from the TUN-only route), so adding them unconditionally would break the empty==today invariant and the existing forced-egress / teardown / leak tests. An empty allowlist is therefore byte-identical `SidecarRunArgs` + `nftRuleset` to before this feature.
- **RFC1918 / link-local only.** Allowed directs are restricted to private ranges so a user cannot accidentally allow a PUBLIC IP that would be a real anonymity leak (validated at the CLI boundary, `--allow-direct`). A public-IP direct, if ever wanted, is a separate louder opt-in, NOT this feature.
- **IP / CIDR only, no hostnames.** A LAN hostname cannot resolve through the proxy (DNS is proxy-side, socks5h) and a local-resolver exception would be another hole; bare IP/CIDR sidesteps it.
- **TCP only.** UDP stays hard-dropped (ADR-0003) even to an allowlisted host: the existing `meta l4proto udp drop` is untouched, and the accept rules are TCP-only by construction. Directs are TCP-only.
- **Never a clear-DNS hole (ADR-0018).** An explicit `:53`/`:853`/`:5353` allow is rejected at the CLI, and a port-omitted (all-ports) allow EXCLUDES those clear-DNS ports from its accept (they stay on the loopback DNS-over-SOCKS forwarder), so `--allow-direct` can never carry direct clear DNS to a LAN resolver (a @LAN-resolver query can reveal the local network's public IP). See ADR-0018; the all-ports accept described below is the non-DNS-port shape.
- **Still fail-closed for everything else.** The accept is for exactly the named `daddr` (+ port) placed BEFORE the drops; it is not a policy flip. Everything not named still goes to the proxy or is dropped.

## Considered options

- **`TUN_EXCLUDED_ROUTES` + nft accept (chosen).** Reuses the SAME mechanism the proxy reachback already uses, generalised to a user-named allowlist. Proven leak-tight by the spike's decisive matrix (allowed host reachable, non-allowlisted sibling dropped, public still tunnelled, UDP dropped, empty == today).
- **A policy flip / broader private-range accept (rejected).** Accepting a whole range or flipping the default would widen the hole beyond the named destinations and risk exposing a LAN the user did not intend. The accept is scoped to exactly the named `daddr`(+port); the range drops are DROPS, never accepts.
- **Unconditional RFC1918 drops in the base ruleset (rejected).** Would change the default jail's ruleset and break the empty==today invariant; the drops are emitted only alongside a non-empty allowlist.

## Consequences

- An allowlisted RFC1918/link-local `HOST[:PORT]` is reachable directly over the LAN (TCP); everything else stays proxy-forced / fail-closed; UDP stays dropped even to the allowed host; an empty allowlist is byte-identical to today's jail.
- Rule ordering for a host-loopback proxy: the reachback narrowing block (`ip daddr <map> tcp dport <proxyport> accept` then `ip daddr <map> drop`) stays authoritative for the reserved pasta map address; the split-tunnel accepts follow it and target user-named LAN destinations, so the two do not interact for any realistic allowlist (the reserved map address is not a user allowlist target).
- **Story 10 diagnostic.** When an allowlisted direct that carries a specific port does not answer on the LAN, netcage prints a WARNING (not a hard failure) naming the direct and marking it as ON the allowlist but silent, so an operator tells a LAN problem apart from a jail-policy block. It is a warning, not a gate: unlike the proxy (whose absence means fail-closed), a down direct is not a leak and must not stop the jailed tool's proxy egress.
- The `verify` leak-test being extended to prove split-tunnel tightness (named directs reachable AND the three core leak assertions still hold for non-allowlisted traffic) is a separate task (`verify-proves-split-tunnel-tight`); this ADR + task deliver the jail mechanism and its off-by-default guarantee.
