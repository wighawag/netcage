---
title: Extend verify to prove the split-tunnel stays leak-tight outside the allowlist
slug: verify-proves-split-tunnel-tight
prd: split-tunnel-lan-allowlist
blockedBy: [split-tunnel-jail-wiring]
covers: [2, 8]
---

## What to build

Extend the `verify` leak-test so that, with a split-tunnel allowlist active, it PROVES the jail is still leak-tight for everything outside the allowlist AND that the named directs are reachable. `approve` must mean "proven leak-tight outside the allowlist," not merely "the direct host works."

End-to-end thin path:

- **Allowlist-aware verify:** `verify` gains a mode where, given an allowlist, it asserts BOTH:
  1. a probe to a named DIRECT endpoint reaches it (the `socks5hfixture` stands in for the LAN host, since a real LAN host is not deterministic in CI); AND
  2. the THREE existing core assertions still hold for NON-allowlisted traffic: the observed exit IP is the proxy's (not the host's), a unique hostname resolves proxy-side (not on the host resolver), and with the proxy killed the probe FAILS CLOSED (no egress).
- **No-allowlist report unchanged:** running `verify` with NO allowlist produces the existing three-assertion report exactly as today (same assertions, same pass/fail, same exit code). This is a strict superset; the current behaviour must not regress.
- The point is that opening a direct hole does not silently loosen the jail for everything else: the split-tunnel report is only green when the directs work AND the non-allowlisted path is still provably leak-proof.

## Acceptance criteria

- [ ] Tests written FIRST: an allowlist-active verify report is green ONLY when (a) the named direct is reachable AND (b) all three core assertions hold for non-allowlisted traffic; if any core assertion would fail (a leak on the non-allowlisted path), the report FAILS even though the direct works.
- [ ] The no-allowlist verify report is BYTE-EQUIVALENT in behaviour to today (three assertions, same exit code); the existing verify tests pass unchanged.
- [ ] The direct-reachability assertion uses the `socks5hfixture` as the stand-in endpoint (deterministic, no real LAN host); podman-dependent cases are podman-gated (t.Skip without podman) and leave no residue.
- [ ] Tests cover the new behaviour; pure-orchestration cases (report composition with/without an allowlist) are podman-free where possible, mirroring the existing `verify_test.go` fake-runner style.

## Blocked by

- `split-tunnel-jail-wiring` - verify proves the mechanism that task builds, and consumes the allowlist `Config` surface, so it is serialised after it (must reach `tasks/done/` first).

## Prompt

> Goal: extend `verify` so a split-tunnel-active run proves the jail is still leak-tight for all NON-allowlisted traffic AND the named directs are reachable, while the no-allowlist report stays exactly as today. Read the prd `split-tunnel-lan-allowlist` (story 8 + the verify Testing Decisions), the finding `work/notes/findings/spike-split-tunnel-lan-allowlist.md` (leak-proof-elsewhere held with the split-tunnel active - that is what verify must lock in), CONTEXT.md (the three-assertion leak-test is the project's top acceptance seam), `internal/verify/verify.go` (the `Check`/`Run` orchestration, `ExitIPProbe`/`DNSProbe`/`FailClosedProbe`, `RunCommandVerify`, and the `JailRunner` seam the tests fake), and the done record of `split-tunnel-jail-wiring`.
>
> FIRST, check against current reality: confirm `verify` still composes the three assertions via `Check`/`Run` and that the jail-wiring task landed the allowlist on `Config` as assumed. If either moved, reconcile rather than building on a stale premise. Do NOT weaken the three core assertions for the non-allowlisted path - they are the whole point.
>
> Write the tests FIRST (testFirst is ON): an allowlist-active report is green only when the direct is reachable AND the three assertions pass for non-allowlisted traffic; a simulated leak on the non-allowlisted path fails the report even though the direct works; the no-allowlist report is unchanged. Use the `socks5hfixture` as the stand-in direct endpoint and the existing fake-runner style for pure-orchestration cases. Then wire the allowlist-aware verify mode.
>
> "Done" means `verify` proves a split-tunnel run is leak-tight outside the allowlist (three assertions still hold) AND the directs are reachable, the no-allowlist report is unchanged, and the podman-gated cases genuinely pass (not skip) with no residue. Keep the verify gate green. RECORD non-obvious in-scope decisions (how the allowlist is passed into verify, how the direct-reachability assertion is framed against the fixture) per the task-template guidance.
