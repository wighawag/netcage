---
title: ps/inspect forward podman's read-only output/query flags (machine-readable, podman-faithful)
slug: machine-readable-ps-and-inspect-forward-podman-output-flags
prd: machine-readable-pass-through-query-verbs
covers: [1, 2, 3, 4, 5, 6]
---

## What was built

The pass-through query verbs `netcage ps` and `netcage inspect` now FORWARD
podman's own read-only output/query flags to the underlying podman verb, so a
consumer can read netcage-managed containers (and their labels) machine-readably,
without weakening any egress / fail-closed / label-scope invariant.

- **`internal/manage/manage.go`:**
  - `PsArgs(userArgs)` builds `podman ps -a --filter label=netcage.managed=true
    <userArgs...>`: the caller's `--format`/`--format json`/`-q`/`--filter` are
    forwarded VERBATIM AFTER the managed-scope filter, which is always prepended,
    so a user `--filter` composes ON TOP of the netcage scope (podman ANDs
    repeated `--filter`), never replacing it. A bare `netcage ps` is byte-identical
    to before (the fixed managed listing / default human table).
  - `ParseInspectArgs(args)` separates the caller's read-only inspect flags
    (chiefly `--format`/`-f`, also `--type`/`-t`) from the single container NAME,
    accepting the flag on EITHER side of the name (podman-tolerant) and consuming a
    separate-form flag's value so a go-template is never mistaken for the name.
    `InspectArgs(flags, name)` emits `podman inspect <flags...> <name>` (flags
    before the name, podman's order). The no-`--format` default stays full JSON.
  - `Run` routes `inspect` through `ParseInspectArgs` + the `guardManaged` label
    check + `InspectArgs`, and `ps` through `PsArgs(args)`. The `netcage.managed`
    filter (ps) and label guard (inspect) stay enforced; both remain proxyless and
    add no firewall rule.
- **`internal/cli/cli.go`:** the `Command.ManageArgv` doc updated (ps/inspect now
  carry read-only output flags, forwarded verbatim by the manage package).
- **`main.go`:** the `usage`/verb-help now documents the machine-readable
  fidelity honestly (it previously over-promised podman vocabulary while ignoring
  these flags).
- **`README.md`:** a new "Manage netcage containers" section documents the verbs
  and the podman-faithful machine-readable `ps`/`inspect` output, with examples
  (`--format '{{.ID}}\t{{.Labels}}'`, `--format json`, `-q`, `--filter`, and the
  single-label inspect), and how to distinguish the tool from the sidecar via the
  `netcage.role` label.
- **`docs/adr/0016-pass-through-query-verbs-forward-podman-output-flags.md`:**
  records the decision (forward read-only output flags for the query verbs, over
  the managed scope) and why it does not weaken any guardrail, and why the
  podman-faithful path was chosen over a purpose-built `ps --json`.

## Acceptance criteria

- [x] `netcage ps --format <go-template>` (incl. `{{.ID}}`/`{{.Names}}`/`{{.Labels}}`/`{{.State}}`/`{{.Status}}`/`{{.Image}}`), `--format json`, `-q`/`--quiet`, and `--filter label=<k>[=<v>]` are forwarded to `podman ps`, with the `netcage.managed` scope always enforced on top (a user `--filter` is additive).
- [x] A bare `netcage ps` (no user flags) is byte-identical to before (the fixed managed listing).
- [x] `netcage inspect <container> --format <go-template>` forwards the template to `podman inspect` (default stays full JSON), so `inspect <id> --format '{{index .Config.Labels "anon-pi.key"}}'` returns just that label; the flag works on either side of the name.
- [x] The label scope stays enforced: `ps` always prepends the managed filter; `inspect` still runs the `guardManaged` label check (a non-netcage container is refused before any podman inspect action runs).
- [x] Both verbs stay proxyless (`cli.IsProxyless`), do no egress, and add no firewall rule; `verify` stays green.
- [x] Unit tests behind the injectable `jail.Runner` assert `--format`/`--filter`/`-q` CHANGE the forwarded podman argv (the fixed-table bug is gone), the inspect flag/name separation on both sides, and the guard still refuses a non-netcage container even with `--format`.
- [x] README + verb-help updated to state the fidelity honestly (no over-promise).
- [x] An ADR records the query-output pass-through contract (ADR-0016).

## How it was verified

`.dorfl.json` `verify` green: `gofmt -l .` clean, `go vet ./...`, `go build ./...`,
`go test ./...` all pass. New tests in `internal/manage/manage_test.go`:
`TestPsArgs_ForwardsUserFlagsAfterTheManagedFilter`,
`TestRun_PsForwardsOutputFlagsAndKeepsManagedScope`,
`TestParseInspectArgs_SeparatesFlagsFromNameEitherSide`,
`TestParseInspectArgs_RequiresExactlyOneContainer`,
`TestInspectArgs_EmitsFlagsBeforeTheName`,
`TestRun_InspectForwardsFormatAndStillGuardsTheLabel`. All wiring is tested via
the record-runner seam; no real container is needed.

## Prompt

> Self-contained. Goal: make `netcage ps` and `netcage inspect` podman-faithful
> for machine-readable output by forwarding podman's read-only output/query flags
> (`ps`: `--format`/`--format json`/`-q`/`--filter`; `inspect`: `--format`) to the
> underlying podman verb, over netcage's managed scope, without weakening any
> egress / fail-closed / label-scope invariant (read-only queries: proxyless, no
> firewall). Read `internal/manage/manage.go` (`PsArgs`/`InspectArgs`/`Run`), the
> `jail.Runner` record-runner test seam, and `internal/ports/ports.go` /
> ADR-0015 for the reuse-contract pattern (which stays for netcage-only verbs).
> Keep `.dorfl.json` verify green; add unit tests asserting the flags change the
> forwarded argv and the label guard still holds; update README + verb-help; add
> an ADR for the query-output pass-through contract.
