# Host access to an in-jail server is a separate loopback-only `forward` verb, not a `-p`/`--publish` run flag

**Status:** proposed (design decision; no implementation yet. Builds on ADR-0002 pasta reachback, ADR-0006 sidecar-owns-netns, ADR-0008 baked firewall, ADR-0005 guardrailed-hole precedent)

## Context

A jailed tool sometimes runs a server (dev server, preview, local API) on a port
the human wants to reach from the host (`curl localhost:3001`, a host browser).
Today `-p`/`--publish` is refused (`internal/cli/cli.go` `denyReasons`:
"publishing ports would open an inbound path around the jail"). The open question
was whether INBOUND-to-loopback-only is separable from netcage's guarantee
(forced EGRESS through the socks5h proxy, fail-closed) and can be a safe,
explicit opt-in. Full reasoning + wiring sketch:
`work/notes/observations/host-access-to-in-jail-server-inbound-loopback.md`.

## Decision

**Inbound-to-host-loopback is separable from forced egress, and we WILL support
it, but as a separate on-demand verb `netcage forward <container> <port>`, NOT by
reopening `-p`/`--publish`.** The `-p` refusal STAYS.

Rationale, in one line each:

- **It is orthogonal to the invariant.** The invariant is that the tool's
  ORIGINATED egress leaves through the proxy (OUTPUT-chain, fail-closed). A host
  -> `127.0.0.1:port` -> in-jail-server connection is host-originated; the reply
  returns on the established inbound socket via pasta's interface and never
  touches the TUN/proxy OUTPUT path. An inbound INPUT accept grants no new OUTPUT
  capability, so forced egress is untouched. The tool's own outbound (SSRF-style)
  stays proxy-forced or dropped, exactly as today.
- **Loopback-by-default removes the deanonymization vector.** The forward binds
  host `127.0.0.1` by DEFAULT: nothing off-box can reach the in-jail server, so
  there is no inbound-scan / LAN-pivot / fingerprint vector. A LAN bind
  (`0.0.0.0`) is possible but is a SEPARATE, louder, explicitly-flagged opt-in
  (see the guardrailed-LAN-bind decision below), never the default the verb hands
  you.
- **A verb is the right shape; a run flag is not.** Viewing the server is a
  SEPARATE, later, auditable action (like `kubectl port-forward` / `ssh -L`), not
  a property of the run. A verb stands up ONE `127.0.0.1:port` forward on demand,
  tears it down when it ends, and keeps the run path `-p`-free and leak-proof. It
  composes with anon-pi: the jailed agent's `netcage run` is unchanged and gains
  no inbound flag it could misuse; the HUMAN opens the window explicitly, per
  port, for as long as they watch.

## Considered options

- **`netcage forward <container> <port>` verb (chosen).** On-demand, out-of-band,
  loopback-by-default, single-port, self-tearing-down, label-scoped to
  netcage-owned containers. Preferred wiring: a host-side userspace forwarder
  (`socat TCP-LISTEN:port,bind=127.0.0.1,fork` into the netns via the podman exec
  seam) that lives only for the verb's lifetime, leaving the run path and the
  baked firewall completely untouched.
- **Reopen `-p`/`--publish` (rejected).** Technically feasible (rewrite to
  `127.0.0.1`, add an INPUT accept for the one port, never touch OUTPUT), but `-p`
  is podman-native and blunt: its default publishes on `0.0.0.0`, it couples the
  inbound decision to run time, and it invites `-p 0.0.0.0:3001:3001`. The flat
  refusal is a clean, teachable boundary; a per-run publish flag muddies it.
- **A LAN bind (`0.0.0.0`) as a flat prohibition (rejected); it is a guardrailed
  secondary opt-in instead.** Binding `0.0.0.0` is NOT a forced-egress leak (the
  reply still rides the established inbound socket; the tool's own outbound stays
  proxy-forced), so the objection is the SEPARATE anonymity invariant (ADR-0013:
  run untrusted tools without revealing who/where you are), not the egress one.
  `0.0.0.0` advertises the in-jail server to every LAN host: a machine correlator
  and a pivot surface that lets a hostile LAN peer probe the very tool you jailed
  because you did not trust it. This is the exact shape ADR-0005 already drew for
  `--allow-direct`: private/contained is fine by default, PUBLIC exposure is a
  separate louder opt-in. So a LAN bind is allowed but ONLY behind an explicit
  `netcage forward --bind 0.0.0.0 <container> <port>` (or `--lan`) that prints a
  warning naming what it exposes; it is never implied by the bare verb. A blanket
  refusal was rejected because the LAN case is genuinely useful and is not an
  egress leak; a silent-default `0.0.0.0` (podman's `-p` behaviour) was rejected
  because it exposes the untrusted tool to the network by accident.
- **A run-time `--expose-loopback <port>` flag (rejected as the primary path).**
  Cleaner than raw `-p` (netcage owns the `127.0.0.1` bind and the single INPUT
  accept), but still puts an inbound capability ON THE RUN, handed to the jailed
  agent, decided before the server exists. Kept only as a possible secondary
  affordance if the verb's post-hoc forward proves impractical (pasta port maps
  are create-time), never as the default.
- **"Just refuse, use `netcage exec ... curl`" (rejected as insufficient).**
  Already works for in-netns access and stays the answer for scripted checks, but
  it cannot open the server in a host browser, which is the actual need
  (anon-pi's dev/preview case).

## Consequences

- The `-p`/`--publish` refusal in `denyReasons` STAYS, and its message can gain a
  pointer: "to view an in-jail server on the host, use `netcage forward
  <container> <port>` (loopback-only)". The refusal now protects against the
  BLUNTNESS of `-p`, not against an egress leak this path does not create.
- The forward must, by construction: bind `127.0.0.1` by DEFAULT (a LAN bind only
  behind the explicit `--bind 0.0.0.0`/`--lan` flag, with a warning); never add an
  OUTPUT rule (egress firewall untouched); be TCP-only (UDP stays hard-dropped,
  ADR-0003); forward exactly the one named port; only enter a netcage-managed
  netns (label-scoped); and not outlive the verb.
- **Lifecycle / reboot: nothing about host-access persists, by design.** The
  forward is a host process living ONLY for the verb's lifetime (Ctrl-C or a
  reboot ends it); there is no unit/service to revive it, deliberately, so an
  inbound window never outlives the reason it was opened. The SERVER behind it
  survives a reboot only as far as the kept pair does (ADR-0009): a plain
  `netcage run` leaves a stopped, restartable tool+sidecar, but a reboot stops
  them and a kept pair at rest is not serving. So the post-reboot sequence is
  `netcage start <container>` (re-applies the baked firewall, re-execs DNS),
  relaunch the server if it was a process the tool ran rather than the
  entrypoint, then `netcage forward` again. Persistent host-access (a standing
  auto-restarting forward) is explicitly a NON-goal: if ever wanted it is the
  user's own systemd unit, never a netcage default, for the same reason `0.0.0.0`
  is not the default: a standing inbound exposure must be a deliberate, visible
  act, not something netcage leaves running on your behalf.
- This is a PROPOSED design, not a committed build: it needs its own prd/task
  (verb parse in `internal/cli`, an `internal/forward` package mirroring
  `internal/manage`, and a spike confirming the socat-into-netns forward is
  loopback-tight and leaves egress green under `verify`). No code ships from this
  ADR.
