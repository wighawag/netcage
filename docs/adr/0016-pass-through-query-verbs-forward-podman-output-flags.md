# The pass-through query verbs (`ps`/`inspect`) FORWARD podman's read-only output/query flags, over the managed scope

**Status:** accepted (builds on ADR-0009 label scope, and the pass-through-verbs task `pass-through-verbs-and-labels`)

## Context

netcage ships pass-through management verbs (`ps`/`logs`/`inspect`/`exec`/`stop`/`rm`/`images`) scoped to netcage-managed containers via the `netcage.managed` label (ADR-0009). The verbs were introduced as THIN wrappers, but `ps` and `inspect` were built as FIXED-OUTPUT wrappers: `netcage ps` always ran `podman ps -a --filter label=netcage.managed=true` and DROPPED any caller flags, so `--format`, `--filter`, and `-q/--quiet` had no effect (every invocation printed the same full human table); and `netcage inspect <c>` always ran `podman inspect <c>` and DROPPED any `--format`, so it always printed full JSON.

This broke the drop-in promise for machine-readable output and blocked a real consumer. A downstream tool (anon-pi) stamps an `anon-pi.key` label on each container and needs to read it back to find "the running container for this project/machine" (for its forward/ports wrappers and its `--keep` run-vs-start decision). Because `ps` would not emit labels and would not honour `--format`, and `inspect` would not honour `--format`, the only handle was the fixed table's `ID`/`NAMES` columns (no `Labels`), and screen-scraping a space-padded human table is fragile. The help text and README also over-promised "podman vocabulary" fidelity while silently ignoring these flags.

## Decision

`ps` and `inspect` FORWARD podman's own read-only output/query flags to the underlying podman verb, so machine-readable output is podman-faithful, WITHOUT weakening any scope or egress invariant.

- **`ps` forwards `--format <go-template>` / `--format json` / `-q` / `--filter` VERBATIM, AFTER the managed-scope filter.** `netcage ps` builds `podman ps -a --filter label=netcage.managed=true <userArgs...>`. The `netcage.managed` filter is ALWAYS PREPENDED, so a user `--filter label=<k>=<v>` composes ON TOP of the implicit netcage scope (podman ANDs repeated `--filter`), never replacing it. So `netcage ps --format '{{.ID}}\t{{.Labels}}'` / `-q` / `--format json` / `--filter label=<k>=<v>` behave exactly as `podman ps` does over netcage's containers. A bare `netcage ps` (no user flags) is byte-identical to before (the fixed managed listing / default human table).
- **`inspect` forwards `--format <go-template>` (the caller's read-only inspect flags), after the label guard.** `netcage inspect <c> --format '...'` builds `podman inspect <flags...> <c>` (flags before the name, podman's order). The flags are separated from the single container name (accepting the flag on EITHER side of the name, matching podman's tolerant placement), the name is guarded netcage-managed (a non-netcage container is REFUSED before any podman inspect action runs), then podman inspect runs. The no-`--format` default stays full JSON.

## Why this does not weaken any guardrail

These are **read-only QUERY verbs**: their flags only shape the OUTPUT. Unlike `run`/`exec`'s curated allow-list (which governs flags that could alter a jailed container's netns/caps/ports/DNS/lifecycle), a `ps`/`inspect` output flag cannot egress, alter a netns or firewall, publish a port, or touch a container's lifecycle. Therefore:

- **Label scope stays enforced.** `ps` always prepends the `netcage.managed` filter (a user `--filter` is additive), and `inspect` still runs the pre-verb `guardManaged` label check that REFUSES a non-netcage container before podman inspect ever acts. No caller flag can widen the set beyond netcage's own containers.
- **Proxyless / no egress / no firewall.** Both verbs remain `cli.IsProxyless` (no `--proxy`, not preflighted), send no traffic, and add NO firewall rule. `verify` (the forced-egress leak-test) is unaffected.

Because there is no jail to breach, `ps`/`inspect` do NOT adopt a curated allow-list for these flags (they forward what the caller passes); the fail-closed allow-list stays where it belongs, on the jail-affecting verbs (`run`/`exec`/`commit`).

## Considered options / notes

- **A purpose-built `netcage ps --json` reuse contract (the alternative the task offered, rejected here).** The task allowed a dedicated, documented `--json` listing (mirroring `ports --json` / `detect-proxy --json`) IF jail-safety argued against forwarding arbitrary podman flags. It does not: `ps`/`inspect` output flags are read-only and cannot breach the jail, so the podman-FAITHFUL path (forward the flags) is strictly better for the drop-in promise. A consumer gets full `podman ps`/`inspect` templating (`{{.Labels}}`, `--format json`, `-q`) over netcage's managed set, not a fixed schema. The reuse-contract pattern stays reserved for netcage-ONLY verbs that have no podman analogue to be faithful to (`ports`, `detect-proxy`).
- **Distinguishing the tool from the sidecar.** The consumer that only cares about the `-tool` container filters on the role label it already reads, e.g. `netcage ps --filter label=netcage.role=tool --format '{{.ID}}\t{{.Labels}}'` (ADR-0009 stamps `netcage.role=tool|sidecar`), so no netcage-specific field is needed: podman's own `--filter`/`--format` over the stamped labels covers it.
- **`logs`/`stop`/`exec` are unchanged.** `logs`/`stop` stay plain named pass-throughs (they take no output/query flags worth forwarding here); `exec`/`commit` keep their curated, fail-closed flag sets because they DO affect a jailed container (they run/snapshot it), unlike the pure query verbs.

## Consequences

- `netcage ps`/`inspect` are now podman-faithful for machine-readable output: a consumer lists netcage's containers with their labels and queries a single label without screen-scraping. The `run`/`exec` fail-closed allow-list is untouched; the split is "read-only query verb ⇒ forward the output flags" vs "jail-affecting verb ⇒ curated allow-list".
- The README and verb-help now state the fidelity honestly (they previously over-promised podman vocabulary while ignoring these flags).
- The forced-egress, fail-closed, and label-scope invariants are unchanged: these are read-only queries; `ps` keeps the managed filter enforced, `inspect` keeps the label guard, both stay proxyless and touch no firewall.
