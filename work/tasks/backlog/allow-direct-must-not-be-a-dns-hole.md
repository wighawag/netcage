---
title: --allow-direct must never carry clear DNS (reject :53, and exclude 53 from the all-ports case) + verify it
slug: allow-direct-must-not-be-a-dns-hole
blockedBy: []
covers: []
---

## What to build

Close row 2 of the Tails-derived leak catalogue (`work/notes/findings/learning-from-anonctl-tails-leak-catalogue.md`, canonical analysis in the sibling anonctl repo's `tails-network-filter-lessons.md`): netcage's `--allow-direct` LAN split-tunnel can currently be used to open a CLEAR-DNS hole to a LAN resolver, which Tails explicitly forbids because a `@192.168.x.x` DNS query can reveal the local network's public IP (a deanonymization vector).

`--allow-direct` (`internal/cli/allowdirect.go`, ADR-0005) is TCP-only, so UDP/53 is not carried. BUT two paths still open clear TCP-DNS to the LAN:

1. An explicit port-53 allow, e.g. `--allow-direct 192.168.1.1:53`, emits an `ip daddr <net> tcp dport 53 accept`: a direct clear TCP-DNS hole.
2. A port-omitted allow (`Port == 0`, "all ports"), e.g. `--allow-direct 192.168.1.1`, emits an all-TCP-ports accept that INCLUDES 53.

Fix both, fail loud, do not silently rewrite:

- `DirectAllow` parsing (`internal/cli/allowdirect.go`, `splitAllowDirectPort`/`Parse`) REJECTS an explicit `:53` value loudly, naming the value and why (a LAN DNS hole can reveal the local network's public IP; DNS must stay on the proxy-side socks5h path). At minimum 53; consider 853/5353 too.
- For the port-omitted ("all ports") case, the emitted sidecar nft accept must EXCLUDE 53 so an all-ports allow never carries DNS (53 stays going through the jail's DNS-over-SOCKS forwarder, never direct to the LAN). Decide and record the exact rule shape.
- Add a `verify` assertion (`internal/verify`) that, with `--allow-direct` active, clear DNS (tcp+udp 53) to the allowed host does NOT egress directly: it is served by the jail's DNS-over-SOCKS forwarder or dropped, never a direct clear query to the LAN resolver.

This mirrors the SAME fix landing in anonctl's LAN exemption (anonctl task `lan-exemption-must-not-be-a-dns-hole`); keep the two guardrail shapes consistent where practical, since they are siblings.

## Acceptance criteria

- [ ] `--allow-direct <host>:53` is rejected loudly at the CLI boundary (naming the value + why); a unit test covers it (mirror `allowdirect_test.go`).
- [ ] A port-omitted `--allow-direct <host>` does NOT open clear TCP/53 to the allowed host: the generated sidecar ruleset excludes 53 from the accept (53 stays on the DNS-over-SOCKS path). A unit test on the generated rules proves 53 is not directly accepted for an all-ports allow.
- [ ] A new `verify` assertion proves, with `--allow-direct` active, that clear DNS (tcp+udp 53) to the allowed host does not egress directly (forwarder-served or dropped). The assertion/render logic is unit-tested; the live check runs in the jail integration suite (the `integration` build tag).
- [ ] Tests cover the new behaviour (mirror the repo's existing test style; jail/verify integration tests isolate to throwaway containers and leave the host untouched).

## Blocked by

- None, can start immediately (it hardens shipped code in `internal/cli/allowdirect.go`, the sidecar rule emission, and `internal/verify`).

## Prompt

> Goal: make netcage's `--allow-direct` structurally incapable of being a clear-DNS hole to a LAN resolver, and prove it in `verify`. Row 2 of `work/notes/findings/learning-from-anonctl-tails-leak-catalogue.md` (canonical analysis: the anonctl repo's `tails-network-filter-lessons.md`, retrieved from Tails design docs). The DNS-leak assertion must use the black-hole/counter probe, NOT the naive "direct dig must time out" (wrong for a transparently-redirected setup; see netcage ADR-0003 and `dns-through-socks-is-tcp-not-udp.md`).
>
> FIRST, check drift: read `internal/cli/allowdirect.go` (the guardrail, `Parse`/`splitAllowDirectPort`), ADR-0005 (the split-tunnel mechanism: TUN_EXCLUDED_ROUTES + the nft accept + the RFC1918 defense-in-depth drops), and where the sidecar turns a `DirectAllow` into the in-jail nft `accept`. Confirm `--allow-direct` is still TCP-only and still emits the accept before the fail-closed drops.
>
> Domain vocabulary: `--allow-direct` is netcage's narrow, private-only, host+port-scoped LAN hole (ADR-0005). The Tails rule this enforces: LAN DNS is forbidden because a `@192.168.x.x` resolver can reveal the local network's public IP. netcage already scopes to an exact host:port and drops the rest of the RFC1918 space; this task makes 53 un-allowable and proves it.
>
> Two holes to close: an explicit `:53` allow, and a port-omitted ("all ports") allow that includes 53. Fix at the guardrail (reject explicit 53) AND at the rule emission (all-ports accept excludes 53, which stays on the DNS-over-SOCKS forwarder). Record any non-obvious in-scope decision (an ADR if it meets the bar). Then add the verify assertion.
>
> Where to look: `internal/cli/allowdirect.go` + `allowdirect_test.go` (guardrail + unit tests), the sidecar rule generation (ADR-0005 names the seam), `internal/verify` (the assertion + the jail integration probe). Seams to test at: the guardrail reject (unit), the generated rules for the all-ports case (unit), the live no-clear-LAN-DNS probe (jail integration). "Done" = 53 is un-allowable by construction and verify proves it. Keep consistent with the sibling anonctl fix.
