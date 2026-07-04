---
title: Host access to an in-jail server is separable from forced EGRESS; the safe shape is a separate `netcage forward` verb (loopback-only, single-port), NOT a run-time -p flag
slug: host-access-to-in-jail-server-inbound-loopback
---

# Host access to a server running inside the jail: feasibility + threat model

Captured while evaluating whether netcage could let the host reach a server a
jailed tool runs (e.g. `curl localhost:3001`, or a host browser hitting an
in-jail dev/preview server). The `-p`/`--publish` refusal
(`internal/cli/cli.go`, `denyReasons`) stands today with the message
"publishing ports would open an inbound path around the jail". The question was
whether INBOUND-to-loopback-only is separable from the forced-EGRESS invariant
and can be a safe, explicit opt-in.

**Verdict: it IS separable, and it CAN be done safely, but the safe shape is a
separate on-demand verb (`netcage forward <container> <port>`), NOT a
run-time `-p`-like flag.** The decision is recorded in ADR-0014.

## What the topology actually is (why this is subtle)

- The tool container has NO netns of its own: it joins the sidecar's netns via
  `--network container:<sidecar>` (`jail.go` `ToolRunArgs`). So "the container's
  ports" ARE the sidecar's netns ports. Any inbound forward lands in the SIDECAR
  netns, which is also where forced egress lives.
- Egress is forced by ROUTING: unmarked traffic goes to the TUN -> tun2socks ->
  proxy (the rootless-TUN + clone-main spikes). tun2socks marks its own dialer so
  its proxy egress escapes the TUN.
- The firewall is an `iptables OUTPUT`-chain script baked into the sidecar's
  `EXTRA_COMMANDS` (ADR-0008): it drops egress UDP and narrows host-loopback
  reachback. **It touches only OUTPUT (egress).** There is no INPUT-chain policy
  today; inbound is simply absent because nothing forwards a port in.
- pasta is the userspace host<->netns bridge and ALREADY does surgical, per-port
  host-loopback forwarding for the OUTBOUND reachback
  (`--map-host-loopback,169.254.1.1`, ADR-0002 + spike-pasta-loopback-reachback).
  pasta's `-T`/`-U` (tcp/udp port forwarding) is the symmetric INBOUND primitive:
  host `127.0.0.1:<port>` -> netns `<port>`.

## The threat-model reasoning (the crux)

The invariant netcage protects is **forced EGRESS through the proxy,
fail-closed**: every packet the tool ORIGINATES leaves through the proxy. A
host -> `127.0.0.1:3001` -> in-jail-server path is the OPPOSITE direction: the
host originates the connection, the in-jail server ACCEPTS it and replies on the
SAME established socket.

- The reply travels back on the accepted connection. The kernel routes a reply on
  an established inbound socket back out the interface the SYN arrived on (pasta's
  netns interface), NOT via the default route. So the reply does NOT get pushed
  into the TUN, and it does NOT need to. It never touches the forced-egress
  OUTPUT path at all. **Inbound-to-loopback is orthogonal to forced EGRESS.**
- The real risk is NOT the reply. It is whether inbound gives the in-jail tool a
  new way to ORIGINATE egress that escapes the proxy. It does not, IF the forward
  is loopback-scoped and the egress firewall is unchanged:
  - The forward is host `127.0.0.1` only (never `0.0.0.0`), so nothing off-box can
    reach it: no LAN, no deanonymization-by-inbound-scan vector.
  - Forced egress is unchanged: the tool's OWN outbound (SSRF-style: the server
    dials out in response to a request) still hits the TUN -> proxy or is dropped,
    exactly as today. Inbound does not add an egress route; it only lets a reply
    return on an already-open socket. An `iptables` INPUT accept for the one
    forwarded port grants no new OUTPUT capability.
  - UDP stays hard-dropped (ADR-0003): the forward is TCP-only.

So the leak vectors to guard are concrete and small: (a) binding host `0.0.0.0`
SILENTLY / by default (would expose the in-jail server to the LAN by accident);
(b) the forward accidentally widening the egress firewall (it must not touch
OUTPUT); (c) forwarding more than the one named port. All three are avoidable by
construction.

## 0.0.0.0 (LAN bind) is not an egress leak, but it IS an anonymity opt-in

Binding `0.0.0.0` is orthogonal to forced egress for the SAME reason loopback is:
the reply rides the established inbound socket, the tool's own outbound stays
proxy-forced. So `0.0.0.0` is not refused on egress grounds. It is refused AS A
DEFAULT on the SEPARATE anonymity invariant (ADR-0013: run untrusted tools
without revealing who/where you are): `0.0.0.0` advertises the in-jail server to
every LAN host, which is a machine correlator and lets a hostile LAN peer probe
the very tool you jailed. This mirrors ADR-0005 exactly (private direct is fine,
a PUBLIC direct is a separate louder opt-in). So the LAN bind is ALLOWED but only
behind an explicit `netcage forward --bind 0.0.0.0 <container> <port>` that
warns what it exposes; the bare verb is always `127.0.0.1`.

## Reboot / persistence: nothing about host-access survives, by design

The forward is a host process living ONLY for the verb's lifetime: Ctrl-C or a
reboot ends it, and there is no unit to revive it (deliberate: an inbound window
must not outlive the reason it was opened). The SERVER behind it survives a
reboot only as far as the kept pair (ADR-0009): a plain `netcage run` leaves a
stopped, restartable tool+sidecar, but a reboot stops them and a kept pair at
rest is not serving. Post-reboot sequence: `netcage start <container>`
(re-applies the baked firewall, re-execs DNS), relaunch the server if it was a
tool-run process rather than the entrypoint, then `netcage forward` again.
Persistent auto-restarting host-access is a NON-goal (it would be the user's own
systemd unit, never a netcage default) for the same reason `0.0.0.0` is not the
default: a standing inbound exposure must be a deliberate, visible act.

## Why a VERB, not a `-p` flag (the design decision)

A run-time `-p`/`--publish` flag is the wrong shape even though it is technically
feasible, because:

- **`-p` is podman-native and blunt.** Users/agents reach for `-p 3001:3001` and
  podman's default publishes on `0.0.0.0`. Honouring `-p` means re-implementing
  podman's publish semantics with a forced `127.0.0.1` rewrite and hoping no one
  writes `-p 0.0.0.0:3001:3001`. The current flat refusal is a clean, teachable
  boundary; reopening `-p` muddies it.
- **Inbound is a SEPARATE, later, auditable action, not a property of the run.**
  You usually decide to view the server AFTER it is up (kubectl port-forward /
  `ssh -L` are on-demand, out-of-band actions, not `docker run` flags). A verb
  matches that: `netcage forward <container> 3001` stands up ONE host
  `127.0.0.1:3001` -> netns `3001` forward on demand, tears it down on Ctrl-C, and
  is a distinct line in the audit trail. The run path stays leak-proof and
  `-p`-free.
- **It composes with anon-pi.** anon-pi (a jailed pi that spins up a dev/preview
  server the user wants to view) keeps its `netcage run` unchanged; the human
  runs `netcage forward <container> <port>` when they want to look. The jailed
  agent never gets an inbound flag it could misuse; the HUMAN opens the window,
  explicitly, per port, for as long as they watch.

## Wiring cost (sketch, for when/if it is built)

- New verb `forward <container> <port>` in `internal/cli` parse (its own tiny
  surface like `detect-proxy`/`setup-default`: one container name + one port, no
  proxy, no run allow-list). Route to a new `internal/forward` (mirroring
  `internal/manage`), scoped by the `netcage.managed` label so it only forwards
  into a netcage-owned container.
- The forward itself: the sidecar owns the netns and the pasta network, but pasta
  port-forwarding is set at `podman run --network pasta:...,-T,<port>` CREATE
  time, so a post-hoc verb cannot ask pasta to add a port to a running sidecar.
  Two implementable options: (a) a host-side userspace forwarder whose LISTENER
  runs on the HOST binding the host's `127.0.0.1` (so it is host-reachable) and
  whose CONNECT side reaches the in-jail server's port in the netns (e.g. a
  host-side `socat TCP-LISTEN:3001,bind=127.0.0.1,fork` dialing the netns, or a
  host listener paired with a `podman exec` socat on the connect side). The exact
  host-listener / netns-connect split is precisely what the de-risking spike must
  determine (a socat run INSIDE the netns binding `127.0.0.1` binds the
  CONTAINER's loopback, NOT the host's, so it would not be host-reachable). It
  lives only while the verb runs; or (b) bake an
  OPT-IN pasta inbound map at run time behind an explicit `--expose-loopback
  <port>` that ONLY ever composes `127.0.0.1`-bound pasta `-T` and adds an INPUT
  accept for that one port, never touching OUTPUT. (a) keeps the run path
  untouched (preferred); (b) is closer to `-p` and reintroduces the
  "flag on the run" shape the verb was meant to avoid.
- Must NOT: bind `0.0.0.0`; add any OUTPUT rule; forward UDP; forward a port not
  named; forward into a non-netcage container; persist past the verb's lifetime.

## Bottom line

Inbound-to-loopback is genuinely orthogonal to the forced-EGRESS invariant, so
the `-p` refusal is NOT protecting egress from this path; it is protecting
against the BLUNTNESS of `-p` (0.0.0.0 default, run-time coupling). The safe,
explicit, auditable answer is a separate loopback-only single-port `netcage
forward` verb. See ADR-0014.
