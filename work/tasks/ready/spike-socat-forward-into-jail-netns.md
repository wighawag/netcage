---
title: Spike a host-side socat forward into the jail netns and prove verify stays green
slug: spike-socat-forward-into-jail-netns
prd: host-access-forward-verb
blockedBy: []
covers: [1, 5, 10]
---

## What to build

A de-risking spike (end-to-end, throwaway) that proves the chosen forward mechanism is sound BEFORE the `forward` verb is built on it, and records the result as a finding.

Stand up a real netcage jail whose tool runs a trivial HTTP server on a fixed port (e.g. `:3001`). Then, from the HOST, stand up a userspace forward whose LISTENER binds the HOST's `127.0.0.1:3001` (so it is host-reachable) and whose CONNECT side reaches the in-jail server's port. The host-listener / netns-connect split is exactly what this spike must DETERMINE, not assume: a `socat` run INSIDE the netns (via `podman exec`) binding `127.0.0.1` would bind the CONTAINER's loopback, NOT the host's, so it would not be host-reachable. Candidate shapes to try: a host-side `socat TCP-LISTEN:3001,bind=127.0.0.1,fork` that dials the in-jail server (reaching the netns however the exec seam / pasta allows), or a host listener paired with a `podman exec` socat on the connect side. Record which actually works. Confirm:

1. `curl http://127.0.0.1:3001` on the host reaches the in-jail server (loopback bind works).
2. With the forward active, the forced-egress leak-test still passes: exit-IP is the proxy's, DNS is proxy-side, and killing the proxy fails closed. The forward must add NO OUTPUT rule; egress is exactly as before.
3. The forward is a host process that dies when it (or the spike) ends: nothing is left listening, no host state is mutated.

Also probe the `--bind 0.0.0.0` variant enough to confirm it binds all interfaces (reachable off-loopback) and is otherwise identical, so the later verb's warning path is grounded in a proven mechanism, not an assumption.

Write the result to `work/notes/findings/` with a `source:` line (live provenance: host, podman version, the exact commands + observed banners), the working recipe for the verb task to reuse, and any gotchas (e.g. how the exec seam addresses the in-netns server, whether socat must run on the host or inside a helper). If the mechanism does NOT hold loopback-tight or breaks the leak-test, record that instead and flag the verb wiring task (`forward-verb-wiring-and-bind`) as needing the fallback (`--expose-loopback`, ADR-0014) rather than emitting a broken verb.

## Acceptance criteria

- [ ] A real jail with an in-jail HTTP server on a fixed port is stood up and torn down, no residue.
- [ ] Host `curl http://127.0.0.1:<port>` reaches the in-jail server via the `socat`-into-netns forward (loopback bind).
- [ ] With the forward active, the three-point forced-egress leak-test still passes (exit-IP is the proxy's, DNS proxy-side, fail-closed on proxy-kill) and NO OUTPUT rule was added.
- [ ] The `--bind 0.0.0.0` variant is confirmed to bind all interfaces (reachable off-loopback), documenting the LAN path the verb will guard.
- [ ] A finding is written to `work/notes/findings/` with a `source:` line, the reusable recipe, and any gotchas (or a NEGATIVE result routing the verb task to the ADR-0014 fallback).
- [ ] The spike leaves no host state behind (no leftover listeners, containers, or rules); it is a throwaway proof, not shipped code.

## Blocked by

- None — can start immediately.

## Prompt

> Self-contained. Goal: PROVE, on a live host, that netcage can let the host reach a server running inside the jail WITHOUT weakening forced egress, using a host-side `socat` forward into the sidecar netns, so the `forward` verb (built in a later task) rests on a de-risked mechanism.
>
> FIRST check this task against current reality (it is a launch snapshot): the jail topology is `internal/jail/jail.go` (the tool joins the sidecar's netns via `--network container:<sidecar>`; egress is forced by routing to the TUN -> tun2socks -> proxy; the firewall is an `iptables OUTPUT` script baked into the sidecar's `EXTRA_COMMANDS`, ADR-0008; the sidecar owns the netns + firewall + DNS, ADR-0006). Confirm these still hold before building on them.
>
> Domain vocabulary: jail, forced egress, fail-closed, sidecar, reachback, verify/leak-test (see `CONTEXT.md`). The design decision this spike de-risks is ADR-0014 (host access is a loopback-by-default `forward` verb, not a `-p` flag; `--bind 0.0.0.0` is a guardrailed opt-in) and the reasoning in `work/notes/observations/host-access-to-in-jail-server-inbound-loopback.md`. The threat-model crux: a host -> `127.0.0.1:port` -> in-jail-server connection is host-originated, the reply rides the established inbound socket via pasta's interface and never touches the TUN/proxy OUTPUT path, so inbound-to-loopback is ORTHOGONAL to forced egress. This spike is the empirical confirmation of exactly that.
>
> Where to look: the podman exec seam and the `netcage.managed` labels (ADR-0009) for addressing the running jail; `work/notes/findings/spike-pasta-loopback-reachback.md` for the prior pasta reachback spike shape (the SYMMETRIC outbound case) and its teardown-evidence discipline; the existing verify leak-test for the three assertions to re-run with the forward active.
>
> "Done" means: the finding exists with live provenance and a reusable recipe (positive result), OR a negative result that routes `forward-verb-wiring-and-bind` to the ADR-0014 fallback. Record any non-obvious in-scope decision (e.g. socat-on-host vs socat-in-helper, how the exec seam addresses the in-netns server) in the finding.
