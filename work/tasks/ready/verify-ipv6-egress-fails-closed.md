---
title: verify assertion - any IPv6 egress from the jail fails closed (the classic transparent-proxy leak)
slug: verify-ipv6-egress-fails-closed
blockedBy: []
covers: []
---

## What to build

Add a `verify` assertion proving row 3 of the Tails-derived leak catalogue (`work/notes/ideas/verify-leak-catalogue-backlog.md`, canonical analysis in the sibling anonctl repo's `tails-network-filter-lessons.md`): IPv6 as a total bypass. The classic transparent-proxy leak is that v4 is forced through the proxy while v6 is untouched and goes out in the clear. netcage already does not carry v6 (the jail's forced egress is v4-through-the-TUN); this assertion PROVES it rather than assuming it.

Add a named assertion (mirror the existing `forced-egress-exit-ip-differs-from-host` / `dns-resolves-over-tcp-glibc` shape in `internal/verify`): from inside the jail, ANY IPv6 egress fails closed (dropped), covering both v6 TCP (a `wget`/`curl` to a v6 literal) and v6 DNS (an AAAA / a v6 resolver). The PASS is that the v6 attempt does NOT reach the real network.

## Acceptance criteria

- [ ] A named `verify` assertion (e.g. `ipv6-egress-fails-closed`) asserts that a v6 egress attempt from the jail (v6 literal TCP, and a v6 DNS/AAAA path) is dropped / does not reach the real network.
- [ ] The pure assertion/decision logic is unit-tested (mirror the existing verify unit tests); the live jailed probe runs in the verify integration suite (the `integration` build tag), isolated to a throwaway container that leaves the host untouched.
- [ ] The assertion name is recorded so it can be pinned in netcage's `verify --json` output contract once that lands (see the idea `verify-json-output-contract`); until then it appears in the `Report` prose like the existing assertions.
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: prove IPv6 does not bypass the jail's forced egress. Row 3 of the Tails leak catalogue (`work/notes/ideas/verify-leak-catalogue-backlog.md`; the design pass already resolved this is assert-not-assume, netcage does not carry v6). One of four sibling verify-assertion tasks.
>
> FIRST, check drift: read `internal/verify/verify.go` (the `Assertion` / `Check` / `ExitIPProbe` shapes and how the existing two assertions are built + listed) and `internal/verify/integration_test.go` (the `TestVerify_*` jailed-probe pattern + the shared-write isolation in TestMain). Confirm the jail still forces v4 through the TUN and does not route v6. If the jail gained explicit v6 handling, assert against that.
>
> Domain vocabulary: netcage forces one container netns's egress through a socks5h proxy, fail-closed. The v6 leak is the transparent-proxy classic (v4 forced, v6 clear). netcage's guarantee is that v6 is not carried at all.
>
> Where to look: mirror `forced-egress-exit-ip-differs-from-host` (a jailed probe + a pass/fail decision). The live probe needs the jail integration harness (root + podman + the sidecar), behind the `integration` tag, isolated to a throwaway run-attributable container. Seams to test at: the pure assertion decision (unit) and the live v6-drop probe (integration). "Done" = a v6 TCP and a v6 DNS attempt from the jail are proven dropped. Keep the assertion INTENT consistent with anonctl's equivalent (anonctl already ships `leak-drop-v6`); do not rename shared concepts gratuitously.
