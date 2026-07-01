---
title: Split-tunnel jail wiring - TUN_EXCLUDED_ROUTES + nft accept for the allowlist (+ ADR)
slug: split-tunnel-jail-wiring
prd: split-tunnel-lan-allowlist
blockedBy: [allow-direct-cli-parse-and-validate]
covers: [1, 2, 5, 6, 7, 10]
---

## What to build

Wire the validated split-tunnel allowlist into the jail so each allowed RFC1918/link-local `HOST[:PORT]` is reachable DIRECTLY over the LAN while ALL other egress stays forced through the proxy, fail-closed. This is the core mechanism the spike proved (`work/notes/findings/spike-split-tunnel-lan-allowlist.md`); it owns the ADR recording the decision.

End-to-end thin path (the two required halves, per the spike):

- **Enabler - `TUN_EXCLUDED_ROUTES`:** extend `Config` with the allowlist (consumed from the CLI task), and have `SidecarRunArgs` compose each allowed `HOST/32` (or CIDR) into the sidecar's `TUN_EXCLUDED_ROUTES` env ALONGSIDE the existing proxy-reachback addr, so the destination egresses the real NIC via pasta instead of the TUN. (pasta already copies the host's LAN route into the netns; excluding the destination from the TUN is what lets it reach the LAN.)
- **Narrowing - nft:** have `nftRuleset` emit `ip daddr HOST tcp dport PORT accept` (port optional; omitted => all TCP ports to that host) for each allowed entry, placed BEFORE the fail-closed drops, and add explicit RFC1918-range `drop` rules after as defense-in-depth (so a non-allowlisted host on the same LAN as an allowed one is dropped, not merely unrouted). UDP stays dropped by the existing `meta l4proto udp drop` (ADR-0003 unchanged): directs are TCP-only.
- **Off by default == today's jail:** an EMPTY allowlist must produce byte-identical `SidecarRunArgs` + `nftRuleset` to the current strict jail, so the existing forced-egress / teardown / leak tests do not regress.
- **Story 10 diagnostic:** when an allowed direct is unreachable on the LAN, surface a clear message distinguishing a LAN problem from a jail-policy block, mirroring the existing reachback diagnostic pattern (`ErrReachback` / `checkReachback`). Keep it light: name the direct and that it is on the allowlist but did not answer, so the user can tell it apart from a blocked (non-allowlisted) destination.
- **ADR:** record the split-tunnel decision (a deliberate, guardrailed hole in forced egress; RFC1918/link-local + TCP-only + off-by-default; that `TUN_EXCLUDED_ROUTES` is the enabler and nft the narrowing) as a new ADR (next number after 0004).

## Acceptance criteria

- [ ] Tests written FIRST: with an allowlist, `SidecarRunArgs` includes each allowed net in `TUN_EXCLUDED_ROUTES` (alongside the proxy reachback), and `nftRuleset` emits the `ip daddr <host> tcp dport <port> accept` rule(s) BEFORE the drops, with RFC1918 drops after. With an EMPTY allowlist, both outputs are BYTE-IDENTICAL to today (the existing jail unit tests still pass unchanged).
- [ ] A podman-gated integration test (t.Skip without podman, mirroring the existing gated tests) against the `socks5hfixture`: an allowlisted direct endpoint is reachable directly; a non-allowlisted address on the same range is BLOCKED; a public destination still exits via the proxy; UDP to the allowed host is dropped. Leaves no residue (run-attributable, torn down).
- [ ] UDP stays hard-dropped even to an allowlisted host (ADR-0003 intact); directs are TCP-only.
- [ ] A clear diagnostic distinguishes an unreachable-on-LAN allowed direct from a jail-policy block (story 10).
- [ ] The split-tunnel decision + guardrails are recorded as a new ADR (`docs/adr/000N-...`).
- [ ] Tests cover the new behaviour; unit cases (excluded-route + nft composition, empty==today) need no podman; the reachability/leak cases are podman-gated and leave no residue.

## Blocked by

- `allow-direct-cli-parse-and-validate` - consumes the validated allowlist that task produces, and touches the same `Config` surface, so it is serialised after it (must reach `tasks/done/` first).

## Prompt

> Goal: make each validated RFC1918/link-local `HOST[:PORT]` on the split-tunnel allowlist reachable DIRECTLY over the LAN while all other egress stays forced through the proxy, fail-closed. Read the finding `work/notes/findings/spike-split-tunnel-lan-allowlist.md` (the proven mechanism + the decisive matrix - build against it VERBATIM), the prd `split-tunnel-lan-allowlist`, ADRs 0001/0002/0003 (tun2socks sidecar, pasta reachback, hard-block UDP - do NOT relitigate; UDP stays dropped), CONTEXT.md, and `internal/jail/jail.go` (the `Config` struct, `SidecarRunArgs` composing `TUN_EXCLUDED_ROUTES` from `proxyReachbackAddr`, `nftRuleset`, and the reachback diagnostic pattern `ErrReachback`/`checkReachback` in `run.go`), plus the done record of `allow-direct-cli-parse-and-validate`.
>
> FIRST, check against current reality: confirm `SidecarRunArgs` still builds `TUN_EXCLUDED_ROUTES=<reachback>/32` and `nftRuleset` still emits the reachback narrowing + `meta l4proto udp drop`, and that the CLI task landed the validated allowlist on `Command`/`Config` as assumed. If any moved, reconcile (route to needs-attention) rather than building on a stale premise.
>
> Write the unit tests FIRST (testFirst is ON): allowlist -> excluded routes + nft accept-before-drop + rfc1918 drops; EMPTY allowlist -> byte-identical to today. Then wire `Config` + `SidecarRunArgs` + `nftRuleset`, both halves together (excluded route AND nft accept; the spike shows each alone is insufficient). Add the podman-gated integration test against the fixture (direct reachable, non-allowlisted blocked, public via proxy, UDP dropped, no residue) and the story-10 diagnostic. Write the ADR.
>
> "Done" means an allowlisted RFC1918 host:port is reachable directly, everything else stays proxy-forced/fail-closed, UDP stays dropped, an empty allowlist is byte-identical to today's jail, and the decision is recorded as an ADR. Keep the verify gate green; the podman-gated tests must genuinely pass (not skip) where podman is present and leave no residue. RECORD non-obvious in-scope decisions (excluded-route CIDR handling, nft rule ordering, the diagnostic wording) per the task-template guidance.
