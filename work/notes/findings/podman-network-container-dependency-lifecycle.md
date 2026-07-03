---
title: podman `--network container:<sidecar>` dependency lifecycle (removal cascade + start auto-revives the sidecar, unjailed)
slug: podman-network-container-dependency-lifecycle
source: "captured live from podman 5.4.2 on this host, 2026-07-03 (rootless, /dev/net/tun present); commands + outputs in this file's body"
---

## What was tested

Reproduced netcage's topology with plain alpine stand-ins: a "sidecar"
(`nc-test-sidecar`, `sleep 600`) and a "tool" container joined to its netns via
`--network container:nc-test-sidecar` (never `--rm`, so it persists). Then probed
what podman does across the sidecar's lifecycle. Podman 5.4.2, rootless.

## Facts observed (all reproduced)

1. **Podman REFUSES to remove the sidecar while a dependent (`--network
   container:`) container still exists** - even with `-f`, even when the sidecar
   is already stopped:

   ```
   Error: container <sidecar> has dependent containers which must be removed
   before it: <tool>: container already exists
   ```

   So you CANNOT "remove the sidecar but leave the tool": the dependency edge
   blocks it.

2. **`podman rm -f --depend <sidecar>` removes the sidecar AND cascades to remove
   the dependent tool container too.** `--depend` is the only way to drop the
   sidecar, and it takes the tool with it. So the only two reachable end-states
   under the current coupling are: (a) both present, or (b) both gone. "Sidecar
   gone, tool kept" is NOT reachable while the `--network container:` edge exists.

3. **`podman start <tool>` of a leftover tool AUTO-STARTS its stopped sidecar
   dependency** (podman brings the dependency up automatically), then joins the
   tool to it. Observed: after `podman start -a nc-test-tool`, the sidecar went
   from `Exited` to `Up`, freshly started.

4. **The auto-started sidecar has NO netcage firewall/DNS, so the tool egresses
   on a WORKING, UNJAILED network.** In the test the tool fetched its real host
   exit IP (`http://api.ipify.org` returned the host's public IP, "GOT_IP").
   netcage applies the firewall and the DNS forwarder at RUNTIME via `podman
   exec` (ADR-0006), NOT baked into the sidecar image, so a raw `podman start`
   that revives the sidecar revives it WITHOUT those rules. The tool is therefore
   **NOT network-dead** - it has a fully working, un-jailed network.

## Why this matters for the PRD (podman-fidelity-and-lifecycle)

- **Premise "remove the sidecar always; without `--rm`, leave the stopped tool
  container" is not achievable as stated** (fact 1/2): the `--network
  container:` edge means the tool cannot survive the sidecar's removal. Leaving a
  reusable tool container requires a different mechanism than "keep the tool,
  drop the sidecar" (e.g. leave BOTH the tool and its stopped sidecar, and have
  `netcage start` re-apply the firewall/DNS before re-entering).

- **Q2's assumption "a raw `podman start` of a left-behind container is
  network-DEAD (fail-closed)" is FALSE on podman 5.4.2** (fact 3/4): a raw
  `podman start` auto-revives the sidecar and gives the tool a working UNJAILED
  network - a real leak, not a fail-closed dead end. The network-dead property
  cannot be relied on; the jail's fail-closed comes from the firewall/DNS that
  netcage applies via `podman exec` at runtime, which a raw `podman start` does
  NOT re-apply. Any "leave a reusable container" design MUST account for this
  (e.g. do not leave the sidecar in a startable state that podman will
  auto-revive unjailed; or make `netcage start` the only path that re-applies the
  firewall; or strip the tool's `--network container:` linkage on teardown).

## Reproduction (abridged)

```
podman run -d --name S alpine sleep 600
podman create --name T --network container:S alpine sh -c 'wget -qO- -T5 http://api.ipify.org && echo GOT_IP || echo NO_EGRESS'
podman stop S
podman rm S            # -> Error: has dependent containers ... (rc still 0 but no removal)
podman rm -f S         # -> same refusal
podman start -a T      # -> auto-starts S, prints the HOST public IP + GOT_IP (unjailed egress!)
podman rm -f --depend S   # -> removes BOTH S and T
```
