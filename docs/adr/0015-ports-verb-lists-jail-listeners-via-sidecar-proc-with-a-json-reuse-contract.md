# `netcage ports` lists a jail's TCP listeners via the sidecar's `/proc/net/tcp*`, and `--json` is a documented reuse contract

**Status:** accepted (builds on ADR-0006 sidecar-owns-netns / no host nsenter, ADR-0009 label scope, ADR-0003 TCP-only, and the forward-connector lesson `work/notes/findings/forward-connector-must-use-sidecar-nc-not-tool.md`)

## Context

A caller wants to know WHICH ports a jailed tool is listening on so a human (or
an agent like anon-pi) can pick one to expose with `netcage forward`, without
knowing the port in advance. Doing this by execing `ss`/`netstat`/`lsof`/`nc`
inside the tool container is unreliable: a minimal tool image may ship none of
them (the real `pi-webveil` image has no `nc`/`netstat`/`ss`), the same lesson
the forward connector already learned. netcage, by contrast, already owns
`podman exec` into the shared netns and pins the sidecar image, so it can
enumerate the listeners itself, image-independently.

## Decision

We add a read verb `netcage ports <container> [--json]` that reports the in-jail
TCP LISTEN sockets, and we make its `--json` output a STABLE, DOCUMENTED reuse
contract (like `detect-proxy --json`).

- **The source of truth is `/proc/net/tcp` + `/proc/net/tcp6`, read via the
  SIDECAR.** `podman exec <sidecar> cat /proc/net/tcp*` (through the injectable
  `jail.Runner`) reads the listeners from inside the shared netns. The sidecar
  shares the tool's netns and is the netcage-PINNED image, so its `/proc/net/tcp*`
  sees the tool's listeners AND the read never depends on a userspace tool in the
  arbitrary user image (ADR-0006: podman is the only host dependency, no host
  nsenter). `/proc/net/tcp*` exists in ANY Linux container regardless of installed
  userspace, so it is the portable source of truth. This is the same
  don't-depend-on-in-image-tools discipline the forward connector adopted.
- **TCP LISTEN only.** Only `st == 0A` (LISTEN) rows survive; established/
  TIME_WAIT/etc. are filtered out, and UDP is not read at all (ADR-0003 hard-drops
  UDP; nothing forwardable is UDP). `ports` answers "what could be forwarded", not
  "what is connected".
- **Loopback-vs-wildcard is reported.** Each listener carries `loopbackOnly`
  (address in `127.0.0.0/8` or `::1`), so a caller can tell a loopback-only server
  (the exact `forward` use case) from one already bound `0.0.0.0`/`::`.
- **Label-scoped, refuses loudly.** The verb resolves the named container to a
  netcage-managed run (ADR-0009) and refuses a non-netcage/unknown container, and
  a STOPPED jail (nothing to enumerate), loudly, the same shape as `forward`.
- **Proxyless / no egress.** `ports` only READS `/proc`: it carries no `--proxy`,
  is not preflighted (`cli.IsProxyless`), sends no traffic, and adds NO firewall
  rule. It is a pure read like `detect-proxy`, so `verify` (the forced-egress
  leak-test) is unaffected.
- **netcage's own `127.0.0.1:53` DNS forwarder is SHOWN, not filtered.** Filtering
  by port would risk hiding a real user listener that happens to sit on `:53`. The
  human table ANNOTATES it (`netcage DNS forwarder`) but the data never lies by
  omission; the `--json` array reports the raw socket with no annotation.

### The `--json` reuse contract

`--json` emits a stable array (IPv4 and IPv6 in the SAME array), one entry per
LISTEN socket:

```json
[
  { "address": "127.0.0.1", "port": 53,   "loopbackOnly": true  },
  { "address": "::1",       "port": 53,   "loopbackOnly": true  },
  { "address": "0.0.0.0",   "port": 3001, "loopbackOnly": false }
]
```

- Field names are exactly `address` (string), `port` (int), `loopbackOnly`
  (bool). These are the fields other tools parse; renaming them is a breaking
  change to the contract.
- `address` is rendered human-readably (`127.0.0.1` / `0.0.0.0` / `::1` / `::` or
  a full specific v6 form), NEVER a hostname.
- The array is sorted stably (by port, then address) so the output is
  deterministic regardless of the kernel's `/proc` row order, and an empty result
  is `[]` (never `null`), so a consumer always parses an array.

## Considered options / notes

- **Exec `ss`/`netstat`/`nc` in the tool image (rejected).** Unreliable: the
  arbitrary tool image may ship none of them (the forward-connector finding). The
  `/proc/net/tcp*`-via-sidecar read is image-independent by construction.
- **Filter netcage's own `:53` DNS forwarder (rejected).** Port-based filtering
  could hide a real user listener on `:53`; annotate-but-show is honest (spec story
  8).
- **A dedicated `Command.PortsJSON` flag (rejected).** `ports` reuses the existing
  `Command.JSON` field, so there is ONE spelling for the machine contract across
  `detect-proxy` and `ports`.
- **Shared resolver:** the label -> run-id resolution the read verbs need was
  forked package-private in several places. This verb converges it into one
  exported `jail.ResolveManagedRun` (+ `jail.ToolNameFor` / `jail.SidecarNameFor`),
  which `forward` now also calls instead of its private copy. `netcage start`'s
  own `resolveManagedTool` stays separate on purpose: it additionally refuses a
  non-tool role (a stricter contract than the role-agnostic read resolution).

## Consequences

- `ports` is a pure read: it never stands up a jail, never egresses, never adds a
  rule, so `verify` stays green and it composes with anon-pi (the agent's `netcage
  run` is unchanged; the caller reads the listeners out-of-band).
- The `--json` field names are now a consumer-facing boundary: adding a field is
  safe, renaming/removing `address`/`port`/`loopbackOnly` is a breaking change.
- Process names / PIDs per socket are Out of Scope (`/proc/net/tcp*` gives the
  inode, not a name without walking `/proc/<pid>/fd`); address + port + scope is
  enough to pick a forward target.
