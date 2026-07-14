---
title: Wire the ports verb: label-scoped sidecar /proc/net/tcp enumeration + human table + --json contract
slug: ports-verb-wiring-and-json
spec: ports-verb-list-jail-listeners
blockedBy: [proc-net-tcp-listener-parser, ports-verb-cli-parse]
covers: [1, 2, 5, 7, 8]
---

## What to build

The enumeration MECHANISM behind the parsed `ports` verb: an `internal/ports` package (mirroring `internal/forward`'s Runner-seam + label-scoping shape) that resolves the named container to a netcage-managed jail, reads the in-jail listeners via the SIDECAR, feeds them through the pure parser, and renders either a human table or the `--json` contract.

End-to-end behaviour:

- Resolve the named container to a netcage-managed run via the `netcage.managed` label -> run id -> sidecar name; refuse a non-netcage or unknown container loudly, and refuse a stopped jail loudly (nothing to enumerate), same as forward.
  - **Do NOT fork the resolver a fourth time.** This label->run-id->sidecar resolution ALREADY exists package-private in THREE places (`internal/forward` `resolveManagedTool`/`sidecarNameFor`, `internal/jail/start.go` `resolveManagedTool`, `internal/manage` `guardManaged`). Copying it again is a coherence defect (a forked concept under a new name). EXTRACT a single shared, exported resolver (e.g. in `internal/jail` or a small shared package) that `ports` and, ideally, `forward` both call, OR reuse `manage.guardManaged`. Pick one home and converge; note the choice in the ADR/done record. If a full 3-way de-dup is too broad for this task, AT MINIMUM export/share the one `forward` uses and have `ports` call it (not a copy).
- Enumerate IMAGE-INDEPENDENTLY: `podman exec <sidecar> cat /proc/net/tcp` and `podman exec <sidecar> cat /proc/net/tcp6` through the injectable `jail.Runner` seam (the SIDECAR shares the tool's netns and is the netcage-pinned image, so its `/proc/net/tcp*` sees the tool's listeners AND the read never depends on a tool in the user image, ADR-0006). Feed both bodies to `parseProcNetTCP` (the blocker task's pure parser).
- Human output (default): a table of ADDRESS / PORT / SCOPE (loopback vs all-interfaces), sorted stably (e.g. by port). netcage's own DNS forwarder on `127.0.0.1:53` is SHOWN (not filtered), optionally annotated as netcage-internal, so the list never hides a real listener (prd story 8).
- `--json` output: a stable, documented array `[{ "address": string, "port": int, "loopbackOnly": bool }]`, IPv4 + IPv6 in the SAME array, addresses rendered `127.0.0.1` / `0.0.0.0` / `::1` / `::`. This is a REUSE CONTRACT (a caller like anon-pi consumes it to pick a forward target), so document its shape the way `detect-proxy --json` is documented.
- Proxyless / no egress: the verb only reads `/proc`; it sends no traffic and adds NO firewall rule.

Wire `main`'s dispatch to route the parsed `ports` command to this package. Update the README with a `ports` section (the human + `--json` examples and the reuse-contract shape). Record an ADR for the new verb + the `--json` reuse contract (a hard-to-reverse, consumer-facing boundary, mirroring the detect-proxy contract decision).

## Acceptance criteria

- [ ] `netcage ports <container>` prints the in-jail TCP LISTEN sockets (address + port + loopback-vs-all-interfaces), read via the SIDECAR's `/proc/net/tcp*` (works for a tool image with no ss/netstat/nc).
- [ ] `--json` emits the documented `[{address, port, loopbackOnly}]` array (IPv4 + IPv6 in one array); the shape is documented as a reuse contract.
- [ ] The verb refuses a non-netcage-managed or non-running container loudly (label-scoped, same resolver as forward), and carries no proxy / does no egress / adds no firewall rule.
- [ ] netcage's own `127.0.0.1:53` DNS forwarder is shown (not silently filtered).
- [ ] An ADR records the new verb + the `--json` reuse contract.
- [ ] Tests cover the wiring behind the injectable `jail.Runner`: label-scoping refusal, stopped-jail refusal, the exec targets the SIDECAR, and the human vs `--json` rendering (using fixture `/proc/net/tcp*` output; no real container).
- [ ] **Shared-write isolation:** any test standing up a real jail uses a unique run-id + cleanup; the pure-render/parse-wiring tests use fixtures and mutate no host state. `verify` (the forced-egress leak-test) stays green (ports does no egress / adds no rule).

## Blocked by

- `proc-net-tcp-listener-parser` (the pure parser this consumes).
- `ports-verb-cli-parse` (the parsed `Command` shape + proxyless routing).

## Prompt

> Self-contained. Goal: build the `internal/ports` package that executes the parsed `netcage ports <container> [--json]` verb: label-scoped, image-independent enumeration of the jail's TCP LISTEN sockets via the SIDECAR's `/proc/net/tcp*`, rendered as a human table or the `--json` reuse contract, doing no egress.
>
> FIRST check against current reality (launch snapshot): both blockers must be in `tasks/done/`. Read the pure parser from `proc-net-tcp-listener-parser` (the `Listener` type + `parseProcNetTCP`) and the parsed `Command` from `ports-verb-cli-parse`. Read `internal/forward/forward.go` for the label-scoping resolver (`resolveManagedTool` -> run id -> `sidecarNameFor`), the `jail.Runner` seam, and the "exec the SIDECAR, which shares the netns and is the pinned image" insight (finding: forward-connector-must-use-sidecar-nc-not-tool). Read `internal/manage` for the label-scoped-podman-through-the-Runner pattern and `main.go` dispatch. If a blocker landed differently than assumed, route to needs-attention.
>
> Domain + decisions: the prd `work/specs/ready/ports-verb-list-jail-listeners.md`; ADR-0006 (podman is the only host dependency, no host nsenter - so read /proc/net/tcp* via podman exec, never host nsenter); ADR-0009 (label scope); ADR-0003 (TCP-only). The `--json` shape mirrors how `detect-proxy --json` is a documented reuse contract. The `/proc/net/tcp*`-via-sidecar mechanism is already live-proven (a jail's :3001 + the DNS :53 were correctly enumerated with loopback-vs-wildcard distinguished).
>
> Where to look: `internal/forward` (resolver + Runner seam), the pure parser (blocker), `main.go` dispatch, README (add a `ports` section). Seams to test at: the label/stopped refusals, the SIDECAR-exec target, and the human-vs-json rendering - all behind the injectable Runner with fixture `/proc/net/tcp*` bodies; isolate any real-jail test with a unique run-id + cleanup.
>
> "Done" means: `netcage ports` works image-independently, `--json` emits the documented contract, refusals are loud and label-scoped, no egress / no rule, `verify` stays green, an ADR records the verb + contract, and it is tested. Record any non-obvious in-scope decision (table columns, the DNS :53 annotation, json field names) in the ADR / done record.
