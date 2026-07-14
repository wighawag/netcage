---
title: Host access to a jailed server via a `netcage forward` verb (loopback by default, `--bind 0.0.0.0` for LAN)
slug: host-access-forward-verb
taskedAfter: []
---

> Launch snapshot - records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked - they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

A jailed tool sometimes runs a server the human wants to reach from the host: a dev server, a preview, a local API on `:3001`. The motivating case is anon-pi (a jailed `pi` that spins up a dev/preview server the operator wants to open in a host browser). Today this is impossible: `-p`/`--publish` is refused (`internal/cli/cli.go` `denyReasons`: "publishing ports would open an inbound path around the jail"), and the tool joins the sidecar's netns (`--network container:<sidecar>`), so there is no host port map. The only in-jail access that works is `netcage exec <container> curl localhost:3001` or a `--shell`, neither of which opens the server in a host browser, which is the actual need.

The refusal exists to keep the jail leak-proof, and reopening `-p` naively WOULD be dangerous: podman's `-p` defaults to publishing on `0.0.0.0`, and it couples the inbound decision to run time (handing the jailed agent a flag it could misuse). But the underlying question, whether host access is separable from the forced-EGRESS invariant, was reasoned through and answered YES: a host -> `127.0.0.1:port` -> in-jail-server connection is host-originated, the reply rides the established inbound socket via pasta's interface and never touches the TUN/proxy OUTPUT path, and an inbound accept grants the tool no new way to originate escaping egress. So inbound-to-loopback is orthogonal to forced egress. See `work/notes/observations/host-access-to-in-jail-server-inbound-loopback.md` and ADR-0014.

## Solution

A new on-demand verb, `netcage forward <container> <port>`, that stands up ONE host `127.0.0.1:<port>` -> in-jail `<port>` forward, on demand, for as long as the verb runs, and tears it down when it ends. It is the netcage analogue of `kubectl port-forward` / `ssh -L`: an explicit, later, out-of-band, auditable action, NOT a property of the run. The `run` path stays `-p`-free and leak-proof; `-p`/`--publish` stays refused (its message gains a pointer to this verb).

From the operator's perspective (anon-pi's dev/preview case):

```
# terminal 1: jailed agent spins up a dev server on :3001 (unchanged)
netcage run --proxy socks5h://127.0.0.1:9050 -it -v ./app:/work <image> sh
# ...inside, the tool starts `npm run dev` on :3001...

# terminal 2: the HUMAN opens the window, explicitly, per port
netcage forward netcage-run-<id>-tool 3001
# -> forwarding http://127.0.0.1:3001 -> <container>:3001 (Ctrl-C to stop)
# now `curl localhost:3001` / a host browser reaches the in-jail server
```

By default the forward binds host `127.0.0.1` only, so nothing off-box can reach the in-jail server. A LAN bind is available but is a SEPARATE, louder, explicitly-flagged opt-in:

```
netcage forward --bind 0.0.0.0 netcage-run-<id>-tool 3001
# -> WARNING: exposing <container>:3001 on ALL interfaces (0.0.0.0); any host on
#    your LAN can reach the jailed tool's server. Ctrl-C to stop.
```

Guardrails that keep it from becoming a leak (all load-bearing):

- **Loopback by default.** The bare verb binds `127.0.0.1`. A LAN bind requires an explicit `--bind 0.0.0.0` and prints a warning naming what it exposes. This mirrors ADR-0005 exactly (private/contained is fine by default; a broader/public exposure is a separate louder opt-in). `--bind 0.0.0.0` is NOT a forced-egress leak (the reply rides the inbound socket; the tool's own outbound stays proxy-forced), but it IS an anonymity opt-in (it advertises the untrusted tool's server to the LAN, ADR-0013), so it must be a deliberate, visible act, never the default.
- **Egress firewall untouched.** The forward NEVER adds an OUTPUT rule. Forced egress is exactly as before; the tool's own outbound (SSRF-style: the server dials out in response to a request) still hits the TUN -> proxy or is dropped.
- **TCP only.** UDP stays hard-dropped (ADR-0003); the forward is TCP-only.
- **Exactly the one named port.** The verb forwards the single port named, nothing wider.
- **netcage-managed containers only.** The verb is label-scoped (`netcage.managed`) so it only forwards into a netcage-owned netns, never an arbitrary container.
- **Lifetime-bounded, no persistence.** The forward is a host process that lives ONLY for the verb's lifetime; Ctrl-C or a reboot ends it, and nothing revives it. Persistent auto-restarting host-access is a non-goal (it would be the user's own systemd unit), for the same reason `0.0.0.0` is not the default: a standing inbound exposure must be deliberate.
- **verify stays green.** Standing up (and tearing down) a forward must leave the forced-egress leak-test green: the three core assertions (exit-IP is the proxy's, DNS is proxy-side, fail-closed on proxy-kill) still hold with a forward active.

## User Stories

1. As an operator running a jailed agent (anon-pi) that spins up a dev/preview server on `:3001`, I want `netcage forward <container> 3001` to make it reachable at `http://127.0.0.1:3001` on my host, so that I can open it in a host browser without weakening the jail.
2. As a security-conscious operator, I want the forward to bind `127.0.0.1` by DEFAULT, so that nothing off-box can reach the jailed tool's server unless I explicitly ask.
3. As an operator who genuinely needs LAN access (e.g. to view the preview from a phone on the same network), I want `netcage forward --bind 0.0.0.0 <container> <port>` to bind all interfaces, so that the LAN case is possible when I deliberately choose it.
4. As a security-conscious operator, I want `--bind 0.0.0.0` to print a clear WARNING naming what it exposes, so that I never expose the untrusted tool's server to the LAN by accident.
5. As a security-conscious operator, I want the forward to NEVER touch the egress firewall (no OUTPUT rule), so that forced egress and fail-closed are exactly as before while the forward is active.
6. As a security-conscious operator, I want the forward to be TCP-only and limited to exactly the one named port, so that no UDP side channel or extra port opens.
7. As an operator, I want the forward to work only against netcage-managed containers (label-scoped), so that a typo cannot forward into an arbitrary container.
8. As an operator, I want the forward to live only while the verb runs and end on Ctrl-C, so that an inbound window never outlives the reason I opened it, and a reboot leaves nothing forwarding.
9. As an operator whose jailed run is a KEPT pair, I want the documented post-reboot sequence to be `netcage start <container>` (restore the jail), relaunch the server if it was a tool-run process, then `netcage forward` again, so that I understand nothing about host-access persists and how to re-establish it.
10. As a CI maintainer, I want `verify` (or an equivalent acceptance check) to prove the forced-egress three-point leak-test still passes with a forward active, so that host access is proven not to weaken the egress guarantee.
11. As an operator who reaches for `-p`, I want the refused `-p`/`--publish` message to point me at `netcage forward`, so that I discover the safe path instead of hitting a dead end.
12. As an operator, I want a clear error if I `netcage forward` a container that is not running (or not netcage-managed), or a port that nothing is listening on, so that a mistake fails loud rather than appearing to work.

### Autonomy notes

- **`humanOnly` NOT set (prd-level):** this repo runs no CI / autonomous tasker, so the flag's sole effect (blocking auto-tasking) would be inert; a human drives the tasking here by circumstance. (If an autonomous tasker were ever added, revisit: this feature deliberately opens a guardrailed inbound path, the kind of security-relevant decomposition a human should drive.)
- **`needsAnswers`:** NOT set. The mechanism is reasoned through and recorded (ADR-0014 + the observation), the guardrails are decided, and the direction is clear. One de-risking spike (the socat-into-netns forward is loopback-tight and leaves `verify` green) is the first task, not an open question.

> Tasked 2026-07-04 (human-driven path). The launch-time Implementation Decisions and Testing Decisions have been relocated into the emitted tasks (`spike-socat-forward-into-jail-netns`, `forward-verb-cli-parse`, `forward-verb-wiring-and-bind`, `verify-forward-keeps-egress-tight` in `work/tasks/ready/`), which now own what-to-build and how-to-test. The durable decision + guardrails (verb not `-p` flag; loopback default; `--bind 0.0.0.0` guardrailed opt-in; no persistence) live in ADR-0014, and the feasibility reasoning in `work/notes/observations/host-access-to-in-jail-server-inbound-loopback.md`. The durable framing below (Problem / Solution / User Stories / Out of Scope) remains.

## Out of Scope

- **`-p`/`--publish` as a run flag.** Stays refused. Host access is the `forward` verb, not a run-time publish flag (ADR-0014).
- **A run-time `--expose-loopback <port>` flag.** Considered and rejected as the primary path (it puts an inbound capability ON THE RUN, handed to the jailed agent, decided before the server exists). Kept only as a possible fallback in ADR-0014 if the post-hoc forward proves impractical; NOT built here.
- **Binds other than `127.0.0.1` and `0.0.0.0`.** A specific-interface bind (`--bind 192.168.1.10`) is a plausible later refinement but is not in v1; only loopback (default) and all-interfaces (`0.0.0.0`, warned) are accepted.
- **Persistent / auto-restarting host-access.** A standing forward that survives Ctrl-C or reboot is a non-goal; if wanted it is the user's own systemd unit, never a netcage default (ADR-0014 Lifecycle).
- **UDP forwards.** ADR-0003 hard-block stands; the forward is TCP-only.
- **Multi-port / port-range forwards.** v1 forwards exactly one named port; a range is a future refinement, not this feature.

## Further Notes

- Motivating trail: the design/feasibility question "can netcage let the host reach a server running inside the jail without breaking forced egress" was reasoned through in `work/notes/observations/host-access-to-in-jail-server-inbound-loopback.md`, concluded YES (inbound-to-loopback is orthogonal to forced EGRESS), and recorded as ADR-0014 (the verb, not a `-p` flag; loopback by default; `--bind 0.0.0.0` as a guardrailed opt-in; no persistence).
- Composes with anon-pi: the jailed `pi`'s `netcage run` is unchanged and gains no inbound flag it could misuse; the HUMAN opens the window explicitly, per port, for as long as they watch.
- Reuses existing seams: the podman exec seam (ADR-0006), the `netcage.managed` label (ADR-0009) for scoping, and the verb-parse pattern of `detect-proxy` / `setup-default` for a proxyless, non-preflighted surface.
