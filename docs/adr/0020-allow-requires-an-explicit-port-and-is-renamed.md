# The split-tunnel direct exemption is PORT-MANDATORY, and `--allow-direct` is renamed `--allow`

**Status:** accepted (amends ADR-0005 split-tunnel guardrailed-hole and ADR-0018 never-a-clear-DNS-hole; prerequisite for `allow-host-loopback-reachback` / ADR-0019. The exact netcage analogue of anonctl's `allow-require-explicit-port-and-rename` / anonctl ADR-0007: the two tools share the `--allow` vocabulary and the port-mandatory intent, though the mechanisms differ (netcage: iptables in the sidecar netns + `TUN_EXCLUDED_ROUTES`; anonctl: per-UID nftables).)

## Context

netcage's split-tunnel exemption (ADR-0005) let a jailed tool reach a private LAN destination DIRECTLY over the real NIC while everything else stayed forced through the socks5h proxy. As shipped, the port was OPTIONAL: `--allow-direct 192.168.1.150` (or a bare `10.0.0.0/24`) emitted an all-TCP-ports accept (`iptables -A OUTPUT -p tcp -d <host> -j ACCEPT`, minus the clear-DNS ports per ADR-0018), reaching EVERY TCP port on that host directly and un-anonymized.

That all-ports form is a real DEANONYMIZATION vector, not merely a wide hole. If the exempted host runs ANY forwarding proxy on some other port, a jailed tool can dial that proxy directly and egress to the WHOLE internet from the operator's real IP, entirely around the forced anonymizing path. Concrete examples on a typical LAN host:

- an `ssh -D` SOCKS proxy on 1080,
- a squid / HTTP proxy on 3128,
- a Tor SOCKS on 9050,
- a socat / reverse tunnel on an arbitrary port.

ADR-0018 patched ONE symptom of the all-ports form (a direct clear-DNS query on tcp/53 to a LAN resolver) by excluding the clear-DNS ports from the all-ports accept. But 53 was never the disease. A forwarding-proxy port deanonymizes MORE than a DNS port: it carries arbitrary egress traffic, not just name lookups. The disease is "all ports". For an anonymity jail, the only defensible granularity is "reach exactly THIS service", so a direct hole must ALWAYS be an exact `IP:port` (or `CIDR:port`).

Separately, once the port is always explicit (and, in the sibling ADR-0019, host-loopback added), a single flag covers every direct-destination class dispatched on the address the user already typed. `--allow-direct`'s "-direct" suffix no longer earns its keep; `--allow` reads as "allow this exact destination directly, whatever its class" and matches anonctl's flag exactly.

## Decision

**A split-tunnel direct exemption MUST name an exact TCP port. The all-ports / bare-IP / port-omitted form is REMOVED. And the flag `--allow-direct` is renamed `--allow`, the config key `allowDirect` is renamed `allow`. This is a deliberate BACKWARD-INCOMPATIBLE clean break: no compat aliases, no migration shims.** netcage does not care about backward compatibility at this point.

Concretely:

- **Port-mandatory reject (the CLI/config boundary, `internal/cli/allowdirect.go`).** `parseAllowDirect` REFUSES a port-omitted value (`Port == 0` after the split) LOUDLY at parse time, naming the value and instructing the user to `add :port`, and explaining WHY (a forwarding proxy on an unspecified port would let the jailed tool egress the whole internet from the real IP around the forced path). Because config `allow` entries round-trip the SAME `parseAllowDirect` (ADR-0012), a port-omitted entry in a config file is rejected identically. The existing guardrails are UNCHANGED: the explicit clear-DNS-port reject (53/853/5353, ADR-0018) and the RFC1918/link-local private-range restriction still hold.
- **The all-ports branch is DEAD and REMOVED (the in-jail firewall, `internal/jail/jail.go`).** With `Port == 0` unable to reach the generator, the `a.Port == 0` all-ports accept in `writeSplitTunnelAccepts` (and its `clearDNSExcludePorts` per-net DROP exclusion) and the matching shape in `firewallVerifyRules` are removed. Every exemption now emits exactly `-p tcp -d <net> --dport <port> -j ACCEPT`, so NO code path can ever open more than one exact TCP port. This also makes ADR-0018's second closure layer (the per-net clear-DNS-exclusion DROP) unnecessary: only the one named non-DNS port is ever accepted, so a direct clear-DNS query on :53 to an allowed host is never accepted and falls to the RFC1918/link-local range DROP. Clear DNS is now un-allowable by the exact-port shape ALONE.
- **Rename across the whole user-facing surface.** The CLI flag (`--allow` space and `=` forms, the dangling-value error, the unknown-flag help list), the config JSON key (`allow`, plus the parse-error hint and docs), the usage/`start` operating-notes, and the README. Internal Go identifiers (`Command.AllowDirect`, `DirectAllow`, `parseAllowDirect`) are left as-is: the OPERATOR-facing surface is what MUST change, and renaming the internal symbols is optional tidiness deferred to keep this change reviewable.

An EMPTY allowlist is still byte-for-byte today's strict jail (ADR-0005's off-by-default invariant is untouched): removing the all-ports branch changes only the non-empty, port-omitted case, which no longer exists.

## Considered options

- **Port-mandatory, all-ports form removed (chosen).** The only granularity that cannot be turned into an around-the-jail egress path by a forwarding proxy on the exempted host. Simple to reason about ("exactly this service"), and it makes the ADR-0018 clear-DNS guarantee structural (no per-net exclusion rule needed).
- **Keep all-ports but blocklist known proxy ports (rejected).** A blocklist of conventional proxy ports (1080/3128/9050/...) is unbounded and fragile: any non-conventional forwarding-proxy port defeats it, and the operator cannot know what the exempted host runs. A denylist of "dangerous" ports is the wrong shape for an anonymity guarantee; an allowlist of exactly one port is the right shape.
- **Keep all-ports as a louder opt-in (rejected).** There is no defensible use for "every TCP port on a LAN host, un-anonymized" in an anonymity jail; a second, louder flag would only invite the leak back. If a genuine multi-port need arises, name each port (repeat `--allow`).
- **Keep the `--allow-direct` name (rejected).** With the port now always explicit and host-loopback added (ADR-0019), one `--allow` dispatched on the typed address covers all classes; `--allow` also matches anonctl exactly, keeping the two tools' vocabulary identical.

## Consequences

- `--allow 192.168.1.150` (or any bare IP / CIDR) is a STARTUP error naming the value and saying `add :port`; a direct hole is always an exact `IP:port` / `CIDR:port`. The same rejection fires for a port-omitted entry in the config `allow` list.
- No code path emits an all-TCP accept any more: `firewallScript` / `writeSplitTunnelAccepts` only ever emits `-p tcp -d <net> --dport <port> -j ACCEPT`, and `firewallVerifyRules` asserts exactly that shape.
- Clear DNS to a LAN resolver is un-allowable by construction from the exact-port shape alone (ADR-0018's per-net clear-DNS-exclusion DROP is removed as dead); an explicit `:53`/`:853`/`:5353` is still rejected at the CLI.
- The private-range guardrail (RFC1918 / link-local only) and the TCP-only / UDP-hard-drop invariant (ADR-0003) are unchanged.
- This is a BACKWARD-INCOMPATIBLE break: an old `--allow-direct` invocation or an `allowDirect` config key fails loudly (unknown flag / unknown config field). That is intended; there is no alias and no migration.
- Prerequisite for `allow-host-loopback-reachback` (ADR-0019): with "exact host:port only" now the invariant, the LAN and host-loopback holes are the same shape, differing only in the per-class guardrail, so that feature is a clean addition rather than a tangle.
