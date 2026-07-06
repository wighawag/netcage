---
title: `netcage verify --json` - a machine-readable output contract (so consumers stop scraping prose)
slug: verify-json-output-contract
---

# `netcage verify --json` machine-readable output

Proposed idea. Give `netcage verify` a `--json` mode emitting its structured `Report` (including the jail exit IP + host exit IP as explicit fields), consistent with netcage's EXISTING `--json` convention on `detect-proxy` and `ports`. Today `verify` has NO machine-readable output - only `Report.String()` prose (`internal/verify/verify.go`) - which FORCES consumers to string-scrape it.

## Why (a real field bug this would have prevented)

anon-pi's `init` calls `netcage verify --proxy <url>` to show the user their anonymized exit IP as proof of forced egress. With no `--json`, anon-pi scraped the FIRST IPv4 out of `verify`'s prose. But `Report.String()` prints the proxy URL on its FIRST line (`verify.go` ~line 84: `fmt.Fprintf(&b, "proxy: socks5h://%s", ...)`), so for a normal loopback proxy (`socks5h://127.0.0.1:9050`, e.g. Tor) the first IPv4 is `127.0.0.1` - the PROXY address, not the exit IP. anon-pi shipped `Exit IP: 127.0.0.1` (anon-pi@0.21.0), a scary false alarm during onboarding suggesting anonymization had failed, when in fact egress was fine (the real exit IP was in the `forced-egress-exit-ip-differs-from-host` assertion Detail, `verify.go` ~line 311).

anon-pi has since patched its scraper (skip the proxy line + stream verify's real output) as a stopgap. See, in github.com/wighawag/anon-pi: the observation `work/notes/observations/verify-exit-ip-parses-proxy-loopback.md` and the consumer idea `work/notes/ideas/consume-netcage-verify-json.md`. But the DURABLE fix is netcage offering a stable contract so no consumer has to parse prose at all.

## Shape

Mirror the existing `detect-proxy --json` convention:

- `netcage verify --json` emits the `Report` as JSON with a `SchemaVersion` (like detect-proxy's `--json` reuse contract), the per-assertion results (`Name`, `Ok`, `Detail`, `Err`), and - the key part for consumers - the exit-IP evidence as EXPLICIT fields: `jailExitIp` and `hostExitIp` (currently only reachable by parsing the `forced-egress-exit-ip-differs-from-host` Detail string). The `Assertion`/`Report` structs already exist (`internal/verify/verify.go`); this is adding a JSON encoder + the flag, plus surfacing the two IPs as fields rather than only prose.
- Keep the human `Report.String()` output unchanged as the default (no `--json`); `--json` is opt-in, exactly as detect-proxy/ports.
- Exit code semantics unchanged (non-zero iff `!Report.Ok`).

## Scope / cross-repo

- This is netcage's own output CONTRACT + forced-egress evidence surface, so it belongs here and wants netcage's own review (it touches how the anonymization proof is presented).
- The consumer half is anon-pi: idea `consume-netcage-verify-json` in github.com/wighawag/anon-pi (`work/notes/ideas/consume-netcage-verify-json.md`), which would switch `init` from scraping to consuming `verify --json`. That idea is BLOCKED-ON this one shipping.
- General principle (also anon-pi's grain): a tool whose output another tool consumes should offer a stable machine contract, not force prose-scraping. netcage already does this for `detect-proxy`/`ports`; `verify` is the gap.

## Open threads

- Exact `--json` schema for verify (reuse the detect-proxy `SchemaVersion` style; decide field names, `jailExitIp`/`hostExitIp` vs nested).
- Whether IPv6 exits need distinct handling in the fields.
- Whether `verify --json` should also carry the resolved proxy (address, source) it already prints, for completeness.
