---
title: Parse and validate --allow-direct (RFC1918/link-local IP/CIDR + optional port)
slug: allow-direct-cli-parse-and-validate
spec: split-tunnel-lan-allowlist
blockedBy: []
covers: [3, 4, 9]
---

## What to build

Add the `--allow-direct` CLI surface: parse one or more `IP`/`CIDR` (with an optional `:port`) values into a validated split-tunnel allowlist on the parsed `Command`, and REJECT anything unsafe or unparseable loudly at startup. This is the parse+validate boundary the jail-wiring task consumes; it does NOT touch the jail here.

End-to-end thin path (parse -> validate -> a typed allowlist on the command):

- **Flag surface:** `--allow-direct <value>` (repeatable; also accept `--allow-direct=<value>`), each value an `IP`, a `CIDR`, or either with a trailing `:port` (e.g. `192.168.1.150:8080`, `192.168.1.150`, `10.0.0.0/24`, `10.0.0.0/24:443`). Accumulate into a typed field on `Command` (a slice of parsed entries carrying the network + optional port), mirroring how `-v`/`-e` accumulate.
- **Validation is the security gate (fail-loud at startup, story 9):** accept ONLY private / link-local ranges - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`. REJECT with a clear message: a PUBLIC (non-private, non-link-local) address or CIDR; a hostname (anything that is not a valid IP/CIDR literal); a malformed value; an out-of-range port. The error must name the offending value and why (public IP would leak / hostnames unsupported / malformed), so the unsafe case fails loud rather than silently doing the wrong thing.
- **Off by default:** no `--allow-direct` yields an EMPTY allowlist (the jail-wiring task turns an empty allowlist into today's byte-identical strict jail).
- This is pure parsing + validation at the CLI boundary; it stands up no jail, so it is unit-testable with NO podman. It does NOT itself add nft rules or excluded routes (that is `split-tunnel-jail-wiring`); it only produces the validated allowlist that task consumes.

## Acceptance criteria

- [ ] Tests written FIRST: `--allow-direct 192.168.1.150:8080` and repeated `--allow-direct` values parse into the typed allowlist on `Command` (network + optional port), in both `--flag value` and `--flag=value` forms.
- [ ] A PUBLIC IP/CIDR (e.g. `8.8.8.8`, `1.2.3.0/24`), a HOSTNAME (e.g. `llama.local`), a MALFORMED value, and an out-of-range port are each REJECTED with a clear startup error naming the value and the reason; only RFC1918 + link-local ranges are accepted.
- [ ] No `--allow-direct` yields an empty allowlist (and does not change any existing parse behaviour).
- [ ] Tests cover the new behaviour in the existing `internal/cli` unit-test style; all cases are pure-logic and need NO podman.

## Blocked by

- None. Can start immediately.

## Prompt

> Goal: add `--allow-direct <IP|CIDR>[:port]` (repeatable) to `netcage run`, parsed into a validated split-tunnel allowlist on the parsed `Command`, accepting ONLY RFC1918 + link-local ranges and rejecting public IPs / hostnames / malformed values loudly at startup. Read `CONTEXT.md` (jail, forced egress, fail-closed), the prd `split-tunnel-lan-allowlist` (Solution + Implementation Decisions + the guardrails), the finding `work/notes/findings/spike-split-tunnel-lan-allowlist.md` (why IP/CIDR-only + RFC1918-only), and the `internal/cli` package (the existing `ParseWithEnv` flag loop, how `-v`/`-e`/`--env` accumulate repeatable values in both `--flag value` and `--flag=value` forms, and the `Command` type).
>
> FIRST, check against current reality: confirm `internal/cli.ParseWithEnv` is where run flags are parsed and that `Command` is where parsed run inputs live (Mounts/Env/etc.); this task adds a sibling repeatable field. If the CLI shape moved, reconcile rather than building on a stale assumption.
>
> Write the tests FIRST (testFirst is ON): private-range values (with/without port, IP and CIDR, both flag forms) parse into the typed allowlist; a public IP/CIDR, a hostname, a malformed value, and a bad port are each rejected with a message naming the value + reason; no flag => empty allowlist. Then wire the parser + a validator that accepts only `10/8`, `172.16/12`, `192.168/16`, `169.254/16`. Do NOT touch the jail wiring (that is the `split-tunnel-jail-wiring` task); only produce the validated allowlist it will consume.
>
> "Done" means `--allow-direct` parses private IP/CIDR[:port] entries and refuses public/hostname/malformed values loudly, off by default, all podman-free. Keep the verify gate green. RECORD non-obvious in-scope decisions (the exact flag spelling, the typed entry shape, whether a bare IP means all-ports, the accepted-range set) per the task-template guidance (a `## Decisions` note; the security-range decision may be worth an ADR if the wiring task does not already own it).
