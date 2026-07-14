---
title: Widen the fail-closed run-flag allow-list with vetted network-irrelevant flags (and fix the env/user/entrypoint pass-through that is silently dropped)
slug: widen-run-flag-allowlist
spec: podman-fidelity-and-lifecycle
blockedBy: [teardown-split-honour-rm]
covers: [4, 5]
---

## What to build

Widen netcage's curated, FAIL-CLOSED run-flag allow-list with vetted
network/isolation-IRRELEVANT podman flags, while keeping the jail-breaching
deny-set explicit and refusing every unknown flag (fail-closed on the unknown).
Do NOT invert to pass-through-minus-deny-set.

Vetting checklist (the durable rule - a flag is ALLOWABLE iff it cannot):
(i) alter the container's network/netns, (ii) add capabilities/devices/privilege,
(iii) publish or bind ports, (iv) affect DNS/resolv, or (v) collide with a
name/lifecycle field netcage owns (`--name`, `--rm`, `--network`). A value-taking
flag MUST be parsed as taking a value so its value is not mis-scanned as the
positional image.

Add (vetted per the checklist): `--memory`, `--cpus`, `--memory-swap`,
`-l`/`--label`, `--tmpfs`, `--read-only`, `--hostname`, `--pull`, `--platform`,
`--env-file`, `--ulimit`, `--shm-size`. Each is passed THROUGH to the tool
container's podman run args.

Keep REFUSED (jail/isolation-relevant): the existing deny-set (`--network`,
`-p`/`--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`, `--name`)
with their current messages, PLUS `--add-host` (it can pin a hostname->IP that
sidesteps proxy-side DNS - refused for now, with a message saying so), and
anything unlisted (unknown-flag refusal). NOTE: `--rm` is NO LONGER in the
deny-set - the `teardown-split-honour-rm` task (this task's blocker) removed it
and made it a netcage-owned ephemeral-run flag; do NOT re-add `--rm` to the
deny-set.

ALSO fix a live drift bug: `-e`/`--env`, `-u`/`--user`, and `--entrypoint` are
already PARSED into the CLI command but are NEVER wired into the jail config /
tool run args, so they are silently DROPPED today. Wire them through so they
actually reach the tool container (they are already vetted-allowed by being in
the parser; this task makes them functional).

## Acceptance criteria

- [ ] Each newly-allowed flag (the list above) is accepted by the parser (both
      `--flag value` and `--flag=value` where applicable) and passed through to
      the tool container's podman run args.
- [ ] Every deny-set flag is still REFUSED with its explanatory message,
      including `--add-host` (new refusal, with a DNS-sidestep reason).
- [ ] An UNKNOWN/unlisted flag is still refused by default (fail-closed on the
      unknown); the refusal message lists the accepted flags.
- [ ] `-e`/`--env`, `-u`/`--user`, `--entrypoint` now actually reach the tool
      container (previously parsed-but-dropped): a run with `-e KEY=VALUE` sees
      the env inside the container; `-u` runs as that user; `--entrypoint`
      overrides it.
- [ ] The forced-egress invariant is untouched: no newly-allowed flag can alter
      the network/netns, add caps/devices/privilege, publish ports, or affect
      DNS; the deny-set + unknown-flag refusal keep it fail-closed.
- [ ] Tests: table-driven unit tests (mirroring the existing CLI parse tests) for
      each newly-allowed flag (accepted + passed through), each deny-set flag
      (refused with message), `--add-host` (refused), an unknown flag (refused),
      and the env/user/entrypoint wiring reaching the tool run args.

## Blocked by

- `teardown-split-honour-rm` - that task removes `--rm` from the CLI deny-set
  (`denyReasons`) and makes it a netcage-owned ephemeral flag; this task also
  edits `denyReasons` (adds `--add-host`, widens the allow-list). Serialised
  after it to avoid a merge conflict on the same map and so `--rm` is not
  re-added here. Otherwise this task is CLI-surface-local and independent of the
  jail-package work.

## Prompt

> Goal: widen netcage's fail-closed run-flag allow-list with vetted
> network-irrelevant podman flags, keep the deny-set + unknown-flag refusal, and
> fix the env/user/entrypoint pass-through that is currently parsed but silently
> dropped.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm the CLI still uses an ALLOW-LIST parser with a `denyReasons`
> map for jail-breaching flags and an "unknown flag" default refusal (look in the
> cli package's `Parse`/`ParseWithEnv` and `denyReasons`). Confirm the drift bug
> is still present: `-e`/`--env`, `-u`/`--user`, `--entrypoint` are parsed into
> the command struct but NOT wired into the jail config or the tool-run-args
> builder (grep the jail package for Env/User/Entrypoint - they are absent). If
> the structure changed, adapt or route to needs-attention.
>
> Domain: netcage is a drop-in `podman` replacement that forces all container
> egress through a socks5h proxy, fail-closed. It OWNS the container's network,
> DNS, name, and lifecycle, so it refuses any flag that could breach the jail and
> refuses unknown flags by default (a future podman network flag must not silently
> pass through). The allow-list is deliberately curated, NOT deny-list-only.
>
> The vetting checklist (record it as the durable rule, e.g. a comment near the
> allow-list and/or a short ADR): a flag is allowable iff it cannot alter
> network/netns, add caps/devices/privilege, publish/bind ports, affect
> DNS/resolv, or collide with netcage-owned name/lifecycle (`--name`/`--rm`/
> `--network`). `--add-host` FAILS this (it can pin a hostname->IP that sidesteps
> proxy-side DNS) -> refuse it, with a message.
>
> Where to look / seams: the CLI flag-parse loop and `denyReasons` (add the new
> allowed flags as parse cases that append to pass-through slices; add `--add-host`
> to the deny-set); the jail Config + tool-run-args builder (wire the new
> pass-through values, AND wire the already-parsed env/user/entrypoint that are
> dropped today). Test at the parser seam (accepted/refused per flag) and the
> tool-run-args seam (the flag reaches the podman argv).
>
> Preserve the forced-egress invariant: no added flag may touch network, netns,
> caps, devices, privilege, ports, or DNS; the deny-set and unknown-flag refusal
> stay intact and tested.
>
> Done = the vetted flags pass through, the deny-set (incl. `--add-host`) and
> unknown-flag refusals hold with messages, env/user/entrypoint actually reach the
> container, and the tests cover accept/refuse/passthrough for each.
