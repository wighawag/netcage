---
title: Machine-readable pass-through query verbs (ps/inspect honour podman output flags)
slug: machine-readable-pass-through-query-verbs
issue:
---

> Launch snapshot: records intent at creation, NOT maintained. Current truth is
> `docs/adr/0016-pass-through-query-verbs-forward-podman-output-flags.md` +
> the code in `internal/manage/` (landed with the task
> `machine-readable-ps-and-inspect-forward-podman-output-flags` in
> `work/tasks/done/`). Settles to Problem / Solution / User Stories / Out of Scope.

## Problem Statement

netcage ships pass-through management verbs (`ps`/`logs`/`inspect`/`exec`/`stop`/
`rm`/`images`) scoped to netcage-managed containers via the `netcage.managed`
label (ADR-0009), sold as a drop-in that lets you manage netcage's containers
with podman vocabulary. But `ps` and `inspect` were built as FIXED-OUTPUT
wrappers that IGNORE the podman flags a caller needs to read managed containers
machine-readably:

- `netcage ps --format '{{.ID}}'`, `--filter label=netcage.managed`, `-q`, and
  `--format json` all printed the SAME fixed human table (identical line count,
  full default columns). None of `--format`, `--filter`, or `-q` had any effect.
- `netcage inspect <id> --format '{{index .Config.Labels "anon-pi.key"}}'`
  ignored the template and printed the full inspect JSON.

Impact: a consumer (e.g. anon-pi) cannot list netcage-managed containers WITH
their labels. anon-pi stamps an `anon-pi.key` label on each container and needs
to read it back to find "the running container for this project/machine" (for
its forward/ports wrappers, and for its `--keep` run-vs-start decision). Because
`ps` would not emit labels and would not honour `--format`, and `inspect` would
not honour `--format`, there was no non-brittle way to do this: parsing the fixed
table only yields the `ID`/`NAMES` columns (no `Labels`), and screen-scraping a
space-padded human table is fragile. The README/verb-help also over-promised
podman fidelity while silently dropping these flags.

## Solution

Make `ps` and `inspect` podman-FAITHFUL for machine-readable output by FORWARDING
podman's own read-only output/query flags to the underlying podman verb, WITHOUT
weakening any egress / fail-closed / label-scope invariant (these are read-only
query verbs: they must remain proxyless and touch no firewall):

- **`netcage ps` forwards podman's output/query flags on the managed set it
  already scopes to:** `--format <go-template>` (incl. `{{.ID}}`/`{{.Names}}`/
  `{{.Labels}}`/`{{.State}}`/`{{.Status}}`/`{{.Image}}`), `--format json`,
  `-q`/`--quiet`, and additional `--filter label=<k>[=<v>]`. The `netcage.managed`
  filter is ALWAYS PREPENDED, so a user `--filter` composes ON TOP of the implicit
  netcage scope (never replacing it). So `netcage ps --format '{{.ID}}\t{{.Labels}}'`
  works exactly as `podman ps`. A bare `netcage ps` is byte-identical to before.
- **`netcage inspect <container> --format <go-template>` forwards the template to
  `podman inspect`**, so `inspect <id> --format '{{index .Config.Labels
  "anon-pi.key"}}'` returns just that label. The no-`--format` default stays full
  JSON. The flag may appear on either side of the container name (podman-tolerant).
- **No guardrail changes.** `ps` keeps the `netcage.managed` filter enforced (a
  user `--filter` is additive); `inspect` keeps the `netcage.managed` label guard
  (a non-netcage container is refused before any podman inspect acts). Both stay
  proxyless (`cli.IsProxyless`), send no traffic, and add no firewall rule.
- **Distinguishing the tool from the sidecar** needs no new field: the consumer
  filters on the `netcage.role=tool|sidecar` label it already reads, e.g.
  `netcage ps --filter label=netcage.role=tool --format '{{.ID}}\t{{.Labels}}'`.

The podman-faithful path was chosen over a purpose-built `netcage ps --json`
reuse contract because `ps`/`inspect` output flags are read-only and cannot
breach the jail, so forwarding them holds the drop-in promise strictly better
(full podman templating over netcage's managed set, not a fixed schema). The
reuse-contract pattern stays reserved for netcage-ONLY verbs with no podman
analogue (`ports`, `detect-proxy`). See ADR-0016.

## User Stories

1. As a consumer (anon-pi), I want `netcage ps --format '{{.ID}}\t{{.Labels}}'`
   to emit IDs + labels exactly as `podman ps`, so I can read back my
   `anon-pi.key` label without screen-scraping the human table.
2. As a consumer, I want `netcage ps --format json` / `-q` / `--filter
   label=<k>=<v>` to behave as podman over netcage's containers, the `--filter`
   AND-ed on top of the implicit `netcage.managed` scope.
3. As a consumer, I want `netcage inspect <id> --format '{{index .Config.Labels
   "anon-pi.key"}}'` to return just that label (the no-`--format` default stays
   full JSON).
4. As a consumer, I want to tell the tool container from the sidecar via the
   existing `netcage.role` label (`--filter label=netcage.role=tool`), so I only
   act on the `-tool` container.
5. As a security-conscious user, I want the `netcage.managed` scope (ps) and label
   guard (inspect) still enforced no matter what flags I pass, and neither verb to
   egress or touch the firewall (read-only queries only).
6. As a reader, I want the README/verb-help to state the fidelity honestly, so the
   drop-in promise is not over-sold.

## Out of Scope

- Adding a purpose-built `netcage ps --json` fixed-schema reuse contract
  (explicitly rejected: forwarding podman's own flags is strictly more faithful
  for a verb with a podman analogue; the reuse-contract pattern stays for the
  netcage-only verbs `ports`/`detect-proxy`).
- Forwarding jail-AFFECTING flags on `exec`/`commit` (those keep their curated,
  fail-closed allow-lists because they run/snapshot a jailed container). Only the
  READ-ONLY query verbs (`ps`/`inspect`) forward their output flags.
- Any change to the egress / fail-closed / label-scope model.

---

_Tasked into `work/tasks/done/machine-readable-ps-and-inspect-forward-podman-output-flags.md`
(landed with the code); the durable decision is ADR-0016._
