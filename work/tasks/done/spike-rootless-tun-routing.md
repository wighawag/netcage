---
title: Spike — rootless TUN routing under Podman
slug: spike-rootless-tun-routing
prd: tooljail
blockedBy: []
covers: [13]
---

## What to build

A spike that PROVES the load-bearing assumption behind ADR-0001 (tun2socks sidecar): under **rootless Podman (netavark)**, a container can be given `/dev/net/tun` plus `CAP_NET_ADMIN` inside its user namespace, can bring up a TUN interface, set it as the default route, and route real traffic through it. This is the first task on purpose: if rootless TUN does not work cleanly, ADR-0001's chosen mechanism is wrong and we must know on day one, not day ten.

End-to-end thin path: spin a minimal container with the device + cap, configure a TUN, point the default route at it, run a user-space reader on the TUN that echoes/forwards, and assert a packet emitted by a process in the container is observed arriving at the TUN (i.e. the route really goes through the TUN, not a real gateway).

Capture the EXACT working invocation (the `--device`, `--cap-add`, any `--security-opt`, sysctls, and the in-container `ip`/route commands) as a `work/notes/findings/<slug>.md` with a `source:` describing how it was verified (captured live on this host + date). That finding is what later tasks (the jail, the vendor-pin) build against. If it does NOT work rootless, record THAT (with the failure mode) as the finding — a negative result is a valid, valuable spike outcome that forces an ADR-0001 revisit.

This task MUTATES THE SYSTEM (creates containers and a TUN/netns). It must be run by a human or with explicit confirmation; it is not a pure-Go unit.

## Acceptance criteria

- [ ] Test/probe is written FIRST and is RED before the wiring: an assertion that a packet sent by an in-container process is observed at the user-space TUN reader (route goes through the TUN), failing until the TUN + route are stood up.
- [ ] A working rootless-Podman invocation stands up `/dev/net/tun` + `CAP_NET_ADMIN`, brings up the TUN, sets it as default route, and the assertion goes GREEN — OR a clean negative result is captured with the exact failure.
- [ ] The exact working (or failing) recipe is recorded in `work/notes/findings/<slug>.md` with a `source:` line (captured live on this host, dated).
- [ ] Teardown: the spike removes its own container/TUN/netns; nothing is left behind after it runs (normal exit AND on failure).
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- None — can start immediately. Run this (and `spike-pasta-loopback-reachback`) FIRST; their results clear `needsAnswers` on the tasks that depend on them.

## Prompt

> Goal: prove (or disprove) that rootless Podman can route a container's traffic through a TUN device, the assumption ADR-0001 (tun2socks sidecar) rests on. Read `docs/adr/0001-redirector-is-tun2socks-sidecar.md` and `CONTEXT.md` (domain terms: jail, redirector, forced egress) first.
>
> FIRST, check this task against current reality: does ADR-0001 still describe the chosen redirector? If a sibling decision superseded it, route to needs-attention rather than spiking a dead mechanism.
>
> This spike MUTATES THE SYSTEM (it creates a Podman container and a TUN/netns). Do NOT run it unattended — get explicit confirmation before creating containers/netns, and explain what you will create first. Prefer a single throwaway container you tear down in the same run.
>
> Write the failing probe BEFORE the wiring (the repo's testFirst nudge is ON): assert that a packet from an in-container process is observed at a user-space reader on the TUN, i.e. the default route truly goes through the TUN and not a real gateway. Then do the minimum to make it pass: pass `/dev/net/tun` in, add `CAP_NET_ADMIN` inside the userns, bring up the TUN, set the default route to it.
>
> "Done" means: the probe is green (or a clean, documented negative result), the exact working/failing recipe (device flags, caps, security-opts, route commands) is captured in `work/notes/findings/<slug>.md` with a dated `source:`, and the spike leaves NO container/TUN/netns behind. RECORD any non-obvious in-scope decision (e.g. a needed `--security-opt` or sysctl) in the finding so the jail task can reuse it verbatim.
