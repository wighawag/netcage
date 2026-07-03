# The run-flag allow-list is widened only with vetted, network/isolation-IRRELEVANT flags; it stays fail-closed on the unknown

**Status:** accepted

netcage's `run` accepts a CURATED, FAIL-CLOSED allow-list of podman flags: a
jail-breaching flag is refused with an explanatory message, and any UNKNOWN flag
is refused by default (so a future podman network flag cannot silently pass
through and open an egress path). This ADR records the durable RULE for widening
that allow-list, so the fail-closed bias is preserved as the surface grows.

We do NOT invert to pass-through-minus-deny-set. Fail-closed on the unknown is
required for a security tool: a flag netcage has never seen must be refused, not
forwarded.

## The vetting checklist (the durable rule)

A flag is ALLOWABLE (may be passed through to the tool container) IFF it CANNOT:

1. alter the container's network or network namespace,
2. add capabilities, devices, or privilege,
3. publish or bind ports,
4. affect DNS / resolv, or
5. collide with a name/lifecycle field netcage OWNS (`--name`, `--rm`,
   `--network`).

If a flag fails ANY clause it is REFUSED (added to the deny-set with a message,
or left to the unknown-flag refusal). A value-taking allowable flag MUST be
parsed as taking a value, so its value is not mis-scanned as the positional
image.

## Widened in this decision (all pass the checklist)

`--memory`, `--cpus`, `--memory-swap`, `-l`/`--label`, `--tmpfs`, `--read-only`,
`--hostname`, `--pull`, `--platform`, `--env-file`, `--ulimit`, `--shm-size`.
These are resource limits, metadata, image-pull/platform selection, and
container-local filesystem/hostname settings: none touches network/netns, caps,
devices, privilege, ports, or DNS. Each is passed THROUGH verbatim (in argv
order, repetition preserved) to the tool container's podman run args. `-l` is
canonicalised to its long form `--label` so the pass-through carries a single
spelling.

## `--add-host` is REFUSED (it fails clause 4)

`--add-host name:IP` pins a hostname->IP mapping in the container's `/etc/hosts`,
which is consulted BEFORE the resolver, so it SIDESTEPS netcage's proxy-side DNS:
the tool could reach an attacker-chosen IP for a name without the proxy resolving
it. It therefore fails the DNS clause and is added to the deny-set with a message
saying so. (It stays refused for now; it is called out as out-of-scope-to-allow
in the prd.)

## The env/user/entrypoint drift fix

`-e`/`--env`, `-u`/`--user`, and `--entrypoint` were already PARSED by the CLI
(they pass the checklist: env vars, the in-container uid/gid, and the command the
container starts are not network/isolation-relevant) but were NEVER wired into
the jail config / tool run args, so they were silently DROPPED. They are now
wired through `jail.Config` (Env/User/Entrypoint) into `ToolRunArgs`, emitted
BEFORE the image, so `-e KEY=VALUE` sets the env, `-u` runs as that user, and
`--entrypoint` overrides the image entrypoint. Empty values leave the image's own
defaults intact (like plain `podman run`).

## Where the rule lives (single source of truth)

- The CLI parse loop + `denyReasons` (the deny-set) + `passThroughValueFlags`
  (the widened value-taking allow-set) in `internal/cli/cli.go` are the canonical
  vetting record: to widen the list, add a flag to the allow-set (or a dedicated
  parse case) ONLY after checking it against the checklist above.
- The pass-through carries through `cli.Command.PassThroughFlags` (an ordered,
  verbatim token stream) into `jail.Config.PassThroughFlags`, emitted before the
  image by `ToolRunArgs`.

## Consequences

- More network-irrelevant podman flags work with `netcage run` (podman fidelity),
  while the forced-egress invariant is untouched: no newly-allowed flag can alter
  the network/netns, add caps/devices/privilege, publish ports, or affect DNS.
- The deny-set (now including `--add-host`) and the unknown-flag refusal keep the
  allow-list fail-closed; both are covered by table-driven parser tests, and the
  pass-through / env-user-entrypoint wiring is covered at the tool-run-args seam.
- A future contributor widening the list has a written checklist to vet against,
  so the fail-closed bias is not eroded flag-by-flag.
