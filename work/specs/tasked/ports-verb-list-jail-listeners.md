---
title: A `netcage ports` verb that lists a jailed container's open TCP listeners, image-independently
slug: ports-verb-list-jail-listeners
taskedAfter: []
---

> Launch snapshot - records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked - they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

A caller wants to know WHICH ports are open inside a jail so a human (or an agent) can pick one to expose with `netcage forward`. The motivating caller is anon-pi: a jailed `pi` spins up a dev/preview server on some port, and anon-pi wants to show "these ports are open in this jail; which do you want on your host?" without the user having to know the port in advance.

Doing this by execing `ss` / `netstat` / `lsof` / `nc` inside the tool container is unreliable: a minimal tool image may have none of them (the real anon-pi image `pi-webveil` has no `nc`, `netstat`, or `ss`). This is the SAME lesson the `forward` connector fix just learned (ADR-0014 hardening, `work/notes/findings/forward-connector-must-use-sidecar-nc-not-tool.md`): netcage must NOT depend on tools existing inside the arbitrary user image. netcage already owns `podman exec` into the shared netns and pins the sidecar image, so it can enumerate the listeners itself, image-independently.

## Solution

A new verb `netcage ports <container> [--json]` that reports the in-jail TCP LISTENING sockets, without assuming any userspace tool exists inside the tool image.

```
netcage ports netcage-run-<id>-tool
# ADDRESS      PORT   SCOPE
# 127.0.0.1    53     loopback      (netcage's in-jail DNS forwarder)
# 0.0.0.0      3001   all-interfaces
```

```
netcage ports netcage-run-<id>-tool --json
# [{"address":"127.0.0.1","port":53,"loopbackOnly":true},
#  {"address":"0.0.0.0","port":3001,"loopbackOnly":false}]
```

The mechanism (live-proven against a real jail): read `/proc/net/tcp` + `/proc/net/tcp6` from within the shared netns via `podman exec <sidecar> cat /proc/net/tcp*`, parse the hex `local_address` (little-endian IP + big-endian port) and keep only rows in the LISTEN state (`st == 0A`). `/proc/net/tcp*` is present in ANY Linux container regardless of installed userspace, so it is the portable source of truth. The sidecar (netcage's pinned redirector image) shares the tool's netns, so its `/proc/net/tcp*` sees the tool's listeners; execing the SIDECAR (not the tool) keeps this image-independent, exactly like the forward connector fix.

Guardrails (all load-bearing, none new to netcage):

- **Image-independent.** No reliance on `ss`/`netstat`/`lsof`/`nc` in the tool image; the source is `/proc/net/tcp*`, read via the SIDECAR. Keeps ADR-0006 ("podman is the only host dependency, no host nsenter").
- **TCP only, LISTEN only.** Consistent with the jail's UDP hard-drop (ADR-0003) and the fact that a listener is what `forward` can expose. Non-LISTEN sockets are filtered out.
- **Loopback-vs-wildcard is reported.** `loopbackOnly` (address is `127.0.0.0/8` or `::1`) distinguishes a loopback-only server (the exact `forward` use case) from a `0.0.0.0`/`::`-bound one, so a caller can highlight the forwardable ones.
- **Label-scoped to netcage-managed containers** (ADR-0009): refuse a non-netcage or stopped container loudly, same resolver as `forward` (`resolveManagedTool` -> run id -> sidecar).
- **Proxyless / no egress** (like `forward` / `detect-proxy` / `setup-default`): it sends no traffic out, so it carries NO `--proxy` and is NOT preflighted.
- **`--json` is a stable, documented reuse contract.** An array of `{address, port, loopbackOnly}` (IPv4 and IPv6 in the same array, address rendered `127.0.0.1` / `0.0.0.0` / `::1` / `::`), mirroring how `detect-proxy --json` is consumed. netcage's own in-jail DNS forwarder on `127.0.0.1:53` is SHOWN (not filtered): filtering by port would risk hiding a real user listener that happens to sit on 53; the human table may annotate it as netcage-internal, but the data does not lie by omission.

## User Stories

1. As anon-pi (an agent driving netcage), I want `netcage ports <container> --json` to tell me which TCP ports the jailed tool is listening on, so I can show the user a pick-list and then `netcage forward` the chosen one, without the user knowing the port in advance.
2. As an operator, I want `netcage ports <container>` to work even when the tool image has no `ss`/`netstat`/`nc`, so a minimal or distroless image is not a blind spot.
3. As an operator, I want each listener reported with its bind address + port AND whether it is loopback-only vs all-interfaces, so I can tell a forwardable local server (127.0.0.1) apart from one already exposed in-netns on 0.0.0.0.
4. As an operator, I want `ports` to only report TCP LISTEN sockets (not established connections, not UDP), so the output is exactly "what could be forwarded", consistent with the jail's TCP-only/UDP-drop model.
5. As a security-conscious operator, I want `ports` to work only on netcage-managed containers (label-scoped) and to refuse a non-netcage or stopped container loudly, so it cannot be pointed at an arbitrary container and it fails clearly when the jail is not up.
6. As an operator, I want `ports` to carry no `--proxy` and do no egress (it only reads `/proc`), so it is a pure read like `detect-proxy`, not a jailed run.
7. As an agent integrator, I want `--json` to emit a stable, documented shape (`[{address, port, loopbackOnly}]`, IPv4 + IPv6 in one array) so I can consume it as a reuse contract without screen-scraping the human table.
8. As an operator, I want netcage's own in-jail DNS forwarder (`127.0.0.1:53`) to be shown rather than silently filtered, so the list never hides a real listener and I can see exactly what the netns exposes.

### Autonomy notes

- **`humanOnly` NOT set (prd-level):** this repo runs no CI / autonomous tasker, so the flag's sole effect (blocking auto-tasking) is inert; a human drives the tasking here by circumstance.
- **`needsAnswers`:** NOT set. The `/proc/net/tcp*`-via-sidecar mechanism is LIVE-PROVEN (a jail's `:3001` + the DNS `:53` were correctly enumerated with loopback-vs-wildcard distinguished), the guardrails are decided, and the `--json` contract shape is settled. Remaining choices (exact table columns, error wording) are tasking-time details.

> Tasked 2026-07-04 (human-driven path). The launch-time Implementation Decisions and Testing Decisions have been relocated into the emitted tasks (`proc-net-tcp-listener-parser`, `ports-verb-cli-parse`, `ports-verb-wiring-and-json` in `work/tasks/ready/`), which own what-to-build and how-to-test. The new-verb + `--json` reuse-contract decision is to be recorded as an ADR by the wiring task. The durable framing below (Problem / Solution / User Stories / Out of Scope) remains.

## Out of Scope

- **UDP listeners.** TCP-only (ADR-0003); a UDP `/proc/net/udp*` read is not built (nothing forwardable is UDP in the jail model).
- **Non-LISTEN sockets** (established connections, TIME_WAIT, etc.). Only LISTEN is reported; `ports` answers "what could be forwarded", not "what is connected".
- **Auto-forwarding.** `ports` only LISTS; picking and forwarding is the operator/agent + `netcage forward`. No coupling.
- **Process names / PIDs per socket.** `/proc/net/tcp*` gives the socket inode, not a friendly process name without walking `/proc/<pid>/fd` (which needs the tool image's `/proc` layout + more exec calls). Out of scope; address+port+scope is enough to pick a forward target.

## Further Notes

- Motivating trail: the `netcage forward` host-access work (ADR-0014) surfaced the anon-pi UX need "show the user which port to forward". `ports` is the read half; `forward` is the act half. Both deliberately avoid depending on in-image tools (the connector fix `work/notes/findings/forward-connector-must-use-sidecar-nc-not-tool.md` proved why: arbitrary tool images ship nothing).
- Reuses the exact seams `forward` established: the `netcage.managed` label resolver, the sidecar-shares-the-netns insight, the podman-exec-only (ADR-0006) discipline, and the proxyless-verb parse pattern of `detect-proxy` / `setup-default`.
- The `/proc/net/tcp*`-via-sidecar mechanism was live-verified against a running jail before this prd was written (the anon-pi jail's `:3001` server and the netcage DNS `:53` were both correctly decoded, with loopback-vs-wildcard distinguished).
