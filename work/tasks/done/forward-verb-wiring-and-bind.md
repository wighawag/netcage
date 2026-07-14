---
title: Wire the forward verb: label-scoped loopback forward with a warned --bind 0.0.0.0
slug: forward-verb-wiring-and-bind
spec: host-access-forward-verb
blockedBy: [spike-socat-forward-into-jail-netns, forward-verb-cli-parse]
covers: [1, 4, 5, 6, 7, 8, 9]
---

## What to build

The forward MECHANISM behind the parsed verb: a new `internal/forward` package (mirroring `internal/manage`'s pattern of a label-scoped podman client through the shared Runner seam) that stands up ONE host `<bind>:<port>` -> in-jail `<port>` forward on demand, holds it for the verb's lifetime, and tears it down when the verb ends.

End-to-end behaviour:

- Resolve the named container to a netcage-managed jail via the `netcage.managed` label (ADR-0009); refuse a container that is not netcage-managed or not running, loudly.
- Stand up the forward using the recipe the spike proved (a host-side listener binding `<bind>` whose connect side reaches the in-jail server's port; the spike finding names the exact host-listener/netns-connect shape that works. Use the ADR-0014 fallback only if the spike came back negative).
- Bind `127.0.0.1` by DEFAULT. For `--bind 0.0.0.0`, print a clear WARNING before forwarding, naming what it exposes (the container, the port, and that ANY LAN host can reach the jailed tool's server). This is the guardrailed anonymity opt-in (ADR-0013 / ADR-0005 precedent), not a forced-egress change.
- TCP only; exactly the one named port; NEVER add an OUTPUT rule (the egress firewall is untouched, so forced egress and fail-closed are exactly as before).
- Lifetime-bounded: the forward is a host process that ends on Ctrl-C (and dies on reboot); nothing revives it. On exit, leave no listener and no host state behind.
- Print a clear line on start (e.g. `forwarding http://<bind>:<port> -> <container>:<port> (Ctrl-C to stop)`), and document the post-reboot sequence in help/README: `netcage start <container>`, relaunch the server if it was a tool-run process, then `netcage forward` again (nothing about host-access persists).

Wire `main`'s dispatch to route the parsed `forward` command to this package.

## Acceptance criteria

- [ ] `netcage forward <container> <port>` makes the in-jail server reachable at `http://127.0.0.1:<port>` on the host, and Ctrl-C tears it down cleanly (no leftover listener).
- [ ] The verb refuses a non-netcage-managed or non-running container, loudly (label-scoped).
- [ ] `--bind 0.0.0.0` binds all interfaces AND prints a warning naming what it exposes; no other bind value is accepted (enforced at parse, honoured here).
- [ ] The forward is TCP-only, exactly one port, and adds NO OUTPUT rule (egress firewall untouched).
- [ ] The forward does not outlive the verb (ends on Ctrl-C; nothing persists it); the post-reboot re-establish sequence is documented.
- [ ] Tests cover the wiring: label-scoping refusal, the bind default vs the warned `0.0.0.0` path, and the lifetime/teardown, mirroring `internal/manage` test style.
- [ ] **Shared-write isolation:** any test that stands up a real jail / forward uses a unique run-id and cleans up (podman is host-global state); a test asserting the forward command shape does so without mutating host networking. The real host loopback/LAN state is untouched after the run.

## Blocked by

- `spike-socat-forward-into-jail-netns` (the forward mechanism must be proven loopback-tight + leak-test-green first, or the fallback selected).
- `forward-verb-cli-parse` (the parsed `Command` shape + the proxyless routing this package consumes).

## Prompt

> Self-contained. Goal: build the `internal/forward` package that executes the parsed `netcage forward <container> <port>` verb: a label-scoped, loopback-by-default, single-port, lifetime-bounded host->jail forward, with a warned `--bind 0.0.0.0` LAN opt-in, that NEVER touches the egress firewall.
>
> FIRST check against current reality (launch snapshot): the two blockers must be in `tasks/done/` — read the spike's finding (`work/notes/findings/`) for the proven forward recipe (or its negative result selecting the ADR-0014 fallback) and confirm the parsed `Command` shape from `forward-verb-cli-parse`. Read `internal/manage` for the label-scoped-podman-through-the-Runner pattern, the `netcage.managed` label constants in `internal/jail/jail.go` (ADR-0009), and the podman exec seam (ADR-0006). If either blocker landed differently than assumed, route to needs-attention rather than building on a stale premise.
>
> Domain vocabulary + decisions: ADR-0014 (the verb, loopback default, `--bind 0.0.0.0` guardrailed opt-in, no persistence, `-p` stays refused), ADR-0013 (the anonymity invariant `0.0.0.0` must not breach by default), ADR-0003 (UDP stays hard-dropped; forward is TCP-only), and `work/specs/tasked/host-access-forward-verb.md`. The load-bearing constraint: the forward adds NO OUTPUT rule, so forced egress / fail-closed are exactly as before; it only lets a host-originated connection reach the in-jail server and get its reply on the established inbound socket.
>
> Where to look: `internal/manage` (label-scoping + Runner seam), the spike finding (the forward recipe), `main.go` dispatch (route the verb). Seams to test at: the label-scoping refusal, the bind-default-vs-warned-`0.0.0.0` decision, and the lifetime/teardown — mirror `internal/manage`'s test style; isolate any real-jail test with a unique run-id + cleanup.
>
> "Done" means: the verb works loopback-by-default, warns on `--bind 0.0.0.0`, refuses non-managed containers, is TCP/single-port, adds no OUTPUT rule, does not persist, and is tested. Record any non-obvious in-scope decision (warning wording, teardown-on-signal handling) in the done record or an ADR if it meets the gate.
