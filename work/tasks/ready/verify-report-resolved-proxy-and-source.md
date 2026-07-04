---
title: `netcage verify` reports the resolved proxy + its source (flag|env|config) - the on-demand "which proxy am I on?" answer
slug: verify-report-resolved-proxy-and-source
prd: netcage-config-and-proxy-setup
blockedBy: [config-file-and-proxy-precedence]
covers: [4]
---

## What to build

Make `netcage verify` print, in its report, the RESOLVED proxy AND where it came
from: `proxy: socks5h://host:port (source: flag|env|config)`. This turns `verify`
into the single on-demand "which proxy am I on, and am I anonymized?" command,
absorbing the config-inspector role so there is NO separate `config show` verb.

**Scope is DELIBERATELY SMALL - read this carefully to avoid re-doing shipped work:**

- The exit-IP-vs-host PROOF ALREADY EXISTS and must NOT be re-added. `internal/verify`
  already runs the `forced-egress-exit-ip-differs-from-host` leak check: it compares
  the jail's `ExitIPProbe` result to `hostExitIP` and fails as a LEAK if they are
  equal. That is the "is my exit non-host?" proof; it ships today. Do NOT duplicate
  or re-implement it.
- Once `config-file-and-proxy-precedence` (task 1) landed, `verify` ALREADY resolves
  the proxy as flag > env > config (it runs against the CLI-resolved proxy), so
  `netcage verify` with no `--proxy` already proves the config default. You do NOT
  need to re-wire resolution.
- **The ONLY new behaviour:** the verify report additionally states the resolved
  proxy address and its SOURCE (which of flag / env / config supplied it). This
  needs the resolution step to EXPOSE which source won (a small addition to the
  CLI proxy resolution from task 1 - e.g. return/record the winning source - then
  print it in the verify report header).

## Acceptance criteria

- [ ] `netcage verify` prints the resolved proxy address AND its source
      (`flag` | `env` | `config`) in its report output.
- [ ] With a config proxy and no flag/env, `netcage verify` reports
      `source: config`; with `NETCAGE_PROXY` set, `source: env`; with `--proxy`,
      `source: flag`. (Precedence unchanged: flag > env > config.)
- [ ] The existing leak assertions (incl. the shipped exit-IP-differs-from-host
      check) are UNCHANGED - no assertion is added, removed, or re-implemented.
- [ ] Tests cover the source-labelling for each of flag / env / config (mirroring
      the existing `internal/cli` + `internal/verify` test style; assert the report
      carries the right source without needing podman - the source is a pure
      resolution fact, testable at the CLI/report seam).

## Blocked by

- `config-file-and-proxy-precedence` - the config source (and the "which source
  won" signal) come from that task's proxy resolution; this task surfaces it.

## Prompt

> Goal: `netcage verify` reports the RESOLVED proxy + its SOURCE
> (`flag|env|config`), so a user can ask on demand "which proxy am I on / am I
> anonymized?". Part of the `netcage-config-and-proxy-setup` prd.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm `internal/verify`'s command verify ALREADY has the
> `forced-egress-exit-ip-differs-from-host` assertion (compares `ExitIPProbe` to
> `hostExitIP`) - it ships today, so you must NOT re-add an exit-IP-vs-host check.
> Confirm task 1 (`config-file-and-proxy-precedence`) landed so `verify` already
> resolves flag > env > config. If the exit-IP assertion is somehow absent, or the
> config resolution did not land, STOP and route to needs-attention (do not
> silently re-scope).
>
> Domain: `netcage verify` is netcage's leak-test - it runs probes through the jail
> and asserts the exit IP is the proxy's (not the host's), DNS is proxy-side, and
> fail-closed holds. It is the acceptance/on-demand proof, NOT on the run hot path.
>
> Where to look / seams: the proxy resolution in `internal/cli` (from task 1) must
> EXPOSE which source (flag/env/config) supplied the proxy - add a small
> "winning source" signal to that resolution. Then `runVerify` / the verify Report
> prints `proxy: ... (source: ...)`. Keep it a pure resolution fact so it is
> testable without podman.
>
> This is a SMALL task by design: one new report line + the source signal. Do NOT
> touch the leak assertions.
>
> Done = `netcage verify` states the resolved proxy + its source; the source is
> correct for each of flag/env/config; the leak assertions are untouched; tests
> cover the source labelling at the CLI/report seam.
