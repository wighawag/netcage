---
title: Spike — pasta host-loopback reachback, scoped to the sidecar
slug: spike-pasta-loopback-reachback
prd: netcage
blockedBy: []
covers: [2]
---

## What to build

A spike that PROVES the load-bearing assumption behind ADR-0002 (pasta reachback, sidecar-scoped): under rootless Podman, **pasta** lets the redirector sidecar reach a SOCKS5h proxy on the host's `127.0.0.1:<proxyport>` and **NOTHING ELSE** on the host, while the tool container's netns can reach **NO** host loopback at all (its only route is the TUN, per ADR-0001). This is the single most leak-prone seam in the whole project, so it gets a real probe, not a paper assumption.

End-to-end thin path: stand up two trivial host-loopback listeners (one on the intended proxy port, one on a DIFFERENT control port). With pasta configured to forward only the proxy port to the sidecar netns, assert: (a) the sidecar reaches the proxy port; (b) the sidecar CANNOT reach the control port (proves the hole is narrow, not "all host loopback"); (c) a process in the tool netns reaches NEITHER port (proves the tool has no host reachback). Capture the exact pasta invocation/flags in a `work/notes/findings/<slug>.md` with a dated `source:`.

If pasta cannot enforce the narrow per-port scope (e.g. it only does all-or-nothing loopback), record THAT as the finding — it forces an ADR-0002 revisit (the slirp4netns-vs-pasta decision would re-open).

This task MUTATES THE SYSTEM (creates netns/containers, binds host loopback ports). Run by a human or with explicit confirmation; it is not a pure-Go unit. Use a high, unprivileged control port and confirm it is free before binding (do not collide with a real service).

## Acceptance criteria

- [ ] Probes are written FIRST and RED before the wiring: the three reachability assertions (sidecar→proxy-port reachable; sidecar→control-port UNreachable; tool-netns→both UNreachable) fail until pasta scoping is configured.
- [ ] With pasta configured to forward ONLY the proxy port, all three assertions go GREEN — OR a clean negative result is captured if pasta cannot scope to a single port.
- [ ] The exact pasta invocation/flags + the two-netns topology are recorded in `work/notes/findings/<slug>.md` with a dated `source:`.
- [ ] Teardown: the spike removes its containers/netns and releases the host ports it bound; nothing left behind (normal exit AND failure).
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).
- [ ] Host ports used are unprivileged and confirmed free before binding; the real host loopback services are untouched after the run.

## Blocked by

- None — can start immediately. Run this (and `spike-rootless-tun-routing`) FIRST; their results clear `needsAnswers` on the tasks that depend on them.

## Prompt

> Goal: prove (or disprove) that pasta gives the sidecar reachback to EXACTLY the host-loopback proxy port and nothing else, while the tool netns has no host reachback — the assumption ADR-0002 rests on. Read `docs/adr/0002-host-loopback-reachback-via-pasta.md` and `CONTEXT.md` (domain terms: reachback, jail, redirector) first.
>
> FIRST, check this task against current reality: does ADR-0002 still describe the chosen reachback mechanism? If superseded, route to needs-attention rather than spiking a dead mechanism.
>
> This spike MUTATES THE SYSTEM (netns/containers + host loopback port binds). Do NOT run it unattended — get explicit confirmation before creating netns/containers or binding host ports, and explain what you will create. Pick a high unprivileged control port and confirm it is free first so you do not collide with a real service.
>
> Write the three failing probes BEFORE the wiring (testFirst is ON): (1) sidecar reaches the proxy port; (2) sidecar CANNOT reach a second host-loopback control port; (3) a process in the tool netns reaches NEITHER. Probe 2 and 3 are the leak-proof guarantees — they must be RED until pasta is correctly scoped, then GREEN. Then configure pasta to forward only the proxy port.
>
> "Done" means: all three probes green (or a clean documented negative result if pasta can't scope per-port), the exact pasta flags + two-netns topology captured in `work/notes/findings/<slug>.md` with a dated `source:`, host ports released, and no netns/containers left behind. RECORD any non-obvious in-scope decision (a needed pasta flag, a topology choice) in the finding so the jail task reuses it.
