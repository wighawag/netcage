---
title: Hide host identity in the tool container's jail wiring (/etc/hosts + fixed hostname + pasta interface rename)
slug: hide-host-identity-in-jail-wiring
prd: jail-host-identity-hardening
blockedBy: []
covers: [1, 2, 6, 7]
---

## What to build

Three small, related edits to the jail wiring so a jailed tool can no longer read the host machine name or the host NIC name/MAC from inside the container, with forced egress unchanged:

1. **Sanitize `/etc/hosts`.** Synthesize a minimal localhost-only hosts file (`127.0.0.1 localhost` + `::1 localhost`) and mount it read-only into the TOOL container, mirroring the way netcage already synthesizes and mounts the resolv.conf pointing at the in-netns forwarder. Today the tool inherits podman's default `/etc/hosts`, which under rootless podman carries the host's `127.0.1.1 <hostname>` line and leaks the host machine name.

2. **Fix the hostname.** Set a fixed, neutral `--hostname` (a constant such as `netcage`) on the tool container so `/etc/hostname` and the container's own name do not reveal or mirror the host.

3. **Rename the pasta interface.** Add pasta's `-I,<stable-name>` (e.g. `netcage0`) option to the pasta network argument the sidecar is started with, so the in-netns interface is not named after the host default-route NIC. Under systemd predictable naming the host NIC is often `enx<MAC>`, whose NAME re-exposes the host MAC even though pasta already synthesizes a fake MAC; renaming the interface removes that leak. The route out is still the TUN, so egress is unaffected.

All three are proven to work under the real `--network container:<sidecar>` topology (see the observation referenced below): the `/etc/hosts :ro` mount and `--hostname` are accepted there (unlike `--dns`, which podman refuses under `--network container:`), and `-I,netcage0` renames the interface with egress intact.

## Acceptance criteria

- [ ] The tool container's `/etc/hosts` contains ONLY localhost entries (no host hostname / no `127.0.1.1 <host>` line).
- [ ] `hostname` inside the tool container returns the fixed neutral value, not the host's name.
- [ ] The in-netns interface visible to the tool (in `/sys/class/net` and `ip link`) is the fixed name (e.g. `netcage0`), and NO interface named `enx*` or carrying the host NIC MAC is present.
- [ ] Unit tests assert the sidecar-run args carry the pasta `-I,<name>` option and the tool-run args carry the sanitized-hosts `:ro` mount + `--hostname`.
- [ ] The `verify` forced-egress leak-test still passes unchanged (exit IP is the proxy's, DNS resolves proxy-side, proxy-killed fails closed): none of these changes touch the egress model.
- [ ] Tests cover the new behaviour, mirroring the existing `SidecarRunArgs`/`ToolRunArgs` wiring-test style. The synthesized hosts file is a per-run temp fixture (like the resolv.conf), not a shared/global write.

## Blocked by

- None — can start immediately.

## Prompt

> Goal: stop a tool jailed by netcage from reading the host machine name (via `/etc/hosts`) or the host NIC name/MAC (via the in-netns interface name), while keeping forced egress byte-for-byte intact. This is Leak 1 + Leak 5 of the jail host-identity hardening prd.
>
> Domain vocabulary (see `CONTEXT.md`): the JAIL is the tool container sharing the tun2socks SIDECAR's netns via `--network container:`; FORCED EGRESS routes all TCP/DNS through the socks5h proxy; the sidecar uses the pasta rootless network backend (ADR-0002).
>
> Where to look: `internal/jail` builds the podman args. `ToolRunArgs`/`Run` already synthesize + mount a resolv.conf into the tool (`resolvConfPath` -> `/etc/resolv.conf:ro`) — mirror that pattern for a synthesized localhost-only `/etc/hosts`, and add `--hostname`. `SidecarRunArgs` composes the pasta network arg as `"pasta"` or `"pasta:--map-host-loopback,"+addr` — add the `-I,<name>` option there (compose it alongside any existing pasta opts). Seams to test at: the `SidecarRunArgs` and `ToolRunArgs` builders (unit) and the existing verify/jail integration path (the leak-test stays green).
>
> Constraints: ADR-0013 (host-identity hardening scope) records this decision and the tested provenance is in `work/notes/observations/jail-leaks-host-identity-metadata-not-network.md` — read both. Do NOT weaken forced egress: the interface rename and the hosts/hostname changes are network-neutral (the route out is the TUN). `--dns` is refused under `--network container:` but `/etc/hosts` mount and `--hostname` are NOT (verified) — so no refusal to design around.
>
> FIRST, check this task against current reality (drift check): confirm `ToolRunArgs`/`SidecarRunArgs` still have the shapes described (the resolv.conf mount seam, the pasta arg composition) before building; if they landed differently, route to needs-attention rather than build on a stale premise.
>
> RECORD non-obvious in-scope decisions (e.g. the exact fixed hostname value; whether the interface name is a constant or run-scoped) briefly in the done record / PR; ADR-0013 already owns the durable why.
