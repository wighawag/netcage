# `--allow-direct` is structurally incapable of carrying clear DNS to a LAN resolver

**Status:** accepted

netcage's split-tunnel `--allow-direct` (ADR-0005) opens a narrow, private-only, host+port-scoped direct hole in the forced-egress jail. That hole must NEVER carry clear DNS to a LAN resolver: a `@192.168.x.x` (or any RFC1918/link-local) DNS query can reveal the local network's public IP, a deanonymization vector Tails explicitly forbids (row 2 of the Tails-derived leak catalogue). This ADR records how netcage makes clear DNS un-allowable by construction and proves it in `verify`.

`--allow-direct` was already TCP-only (ADR-0003 hard-drops all egress UDP, so UDP/53 was never carried), but two TCP paths still opened a clear TCP-DNS hole: an EXPLICIT `:53` allow (`--allow-direct 192.168.1.1:53`), and a PORT-OMITTED "all ports" allow (`--allow-direct 192.168.1.1`) whose all-TCP-ports accept silently included 53. Both are now closed, at two layers:

- **Guardrail reject (the CLI boundary, `internal/cli/allowdirect.go`).** An explicit clear-DNS destination port is REFUSED loudly at parse time, naming the value and why. The refused set is `clearDNSPorts` = {53 (clear DNS), 853 (DoT), 5353 (mDNS)}: 53 is the load-bearing one; 853/5353 are refused too so no clear-DNS-ish port can be opened directly to the LAN. Because config `allowDirect` entries round-trip the SAME `parseAllowDirect` (ADR-0012), a `:53` in a config file is rejected identically. This is a fail-loud reject, NOT a silent rewrite: a user who asks for `:53` gets an error explaining DNS stays on the proxy-side socks5h forwarder, not a quietly-different rule.

- **Rule-emission exclusion (the in-jail firewall, `internal/jail/jail.go`).** For the PORT-OMITTED (all-ports) case, the emitted iptables OUTPUT block DROPS each clear-DNS port (`clearDNSExcludePorts` = {53, 853, 5353}) to the allowed net BEFORE the all-ports `accept`. iptables is first-match, so the DROP shadows the accept for those ports: every other TCP port to the allowed host is reachable, but a direct clear query on 53 is dropped and falls back to the jail's loopback DNS-over-SOCKS forwarder (127.0.0.1:53 -> SOCKS), never direct to the LAN. The port-scoped case needs no such drop (the guardrail already rejects an explicit `:53`, and a non-DNS port allows only that port). The post-start `firewallVerifyRules` verification (ADR-0008) asserts these DROP rules are present in the live ruleset, so a half-applied firewall still fails loud.

- **verify proves it (`internal/verify`).** A new `NoClearLANDNSAssertion` + `NoClearLANDNSProbe` assert, with `--allow-direct` active, that a clear DNS query (tcp AND udp 53) aimed DIRECTLY at the allowed LAN resolver gets NO clear answer from the LAN (dropped), while the loopback forwarder STILL resolves. The live check (behind the `integration` build tag) uses the black-hole/counter probe mandated by ADR-0003 and `dns-through-socks-is-tcp-not-udp.md`, NOT the naive "a direct dig must time out": a CONTROL leg first proves the allowed host/route is genuinely UP (a non-53 TCP connect succeeds over the split-tunnel), so the silence on port 53 is provably the firewall DROP, not an unreachable host.

## Considered options

- **Reject explicit :53 AND exclude 53 from the all-ports accept (chosen).** Closes both holes at the layer each belongs to (an explicit port is a CLI-boundary concern; the all-ports case is a rule-shape concern). Fails loud, never silently rewrites.
- **Silently drop 53 from an explicit `:53` allow (rejected).** A user who typed `:53` almost certainly has a wrong mental model (they think a LAN resolver is safe); silently accepting-but-dropping it would hide the mistake. A loud reject teaches the right model.
- **Only reject/exclude 53, not 853/5353 (rejected).** 53 is the concrete hole, but a security guardrail should not leave adjacent clear-DNS-ish ports open for the next person to rediscover; the extra two ports are cheap and un-surprising for a leak-proof jail.

## Consequences

- `--allow-direct <host>:53` (and `:853`, `:5353`) is a startup error; DNS to a LAN resolver is un-allowable by construction. An all-ports `--allow-direct <host>` reaches every TCP port on that host EXCEPT the clear-DNS ports, which stay on the DNS-over-SOCKS forwarder.
- Kept consistent by design with anonctl's sibling LAN-exemption fix (`lan-exemption-must-not-be-a-dns-hole`): same refused-port set, same "reject explicit, exclude from all-ports, prove in verify" shape, so the two projects' guardrails read the same.
- An empty allowlist is still byte-identical to today's strict jail (the DNS-exclusion drops are emitted ONLY for a non-empty allowlist's port-omitted entries), so ADR-0005's off-by-default invariant is untouched.
