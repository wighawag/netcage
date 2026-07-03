# `netcage start <name>` revives the kept jail (refusing a changed config), extending the fail-loud layer to the resume path

**Status:** accepted (builds on ADR-0006, ADR-0008, ADR-0009)

`netcage start <name>` is the jail-aware exception to the pass-through management
verbs (ADR-0009): it RESUMES a KEPT, netcage-managed tool container with its full
forced-egress jail restored, so a named reusable jailed container is a durable
environment (prd stories 7 + 9, the primitive a downstream "machine" is built
from). It is NOT a thin `podman start` pass-through, so it lives in the jail
package (`jail.Start`), not `internal/manage`, and CARRIES a `--proxy` (and any
`--allow-direct`) that it RECONCILES against the container's baked jail config.

Reviving the EXISTING sidecar is sufficient and idempotent across cycles (proven
by spiking, see `work/notes/findings/netcage-start-sidecar-revive-is-sufficient.md`):
a plain `podman start` of the stopped sidecar re-runs the baked `EXTRA_COMMANDS`
firewall (ADR-0008), re-establishes the TUN + routing, and stays fail-closed on a
dead proxy. The ONE case a plain revive would be WRONG is a CHANGED jail config
(the sidecar bakes `PROXY` / `TUN_EXCLUDED_ROUTES` / `EXTRA_COMMANDS` at CREATE
time, so a revive re-runs the ORIGINAL values); the safe default there is to
REFUSE, not silently revive a stale jail or rebuild-and-lose container state.

## The start sequence (jail restored BEFORE the tool runs)

1. Resolve `<name>` to a netcage-MANAGED TOOL container by the `netcage.managed`
   label (+ `role=tool`), reading its run id; a non-netcage or unknown container
   (or a bare sidecar name) is REFUSED before any jail work.
2. RECONCILE (below): same config -> revive; changed -> refuse.
3. Revive the sidecar (`podman start <sidecar>`; the baked firewall re-applies),
   then VERIFY the firewall via the same `iptables -S` probe as the run path
   (`verifyFirewall`), aborting loudly if partial. The fail-loud layer (ADR-0008)
   now applies to `start`, not just `run`.
4. Re-exec the `netcage-dns` forwarder INTO the sidecar (a SEPARATE process, NOT
   baked into `EXTRA_COMMANDS`, so a restart leaves it dead until this restores
   it) and re-materialise the tool's resolv.conf, THEN start/attach the tool.

The forced-egress invariant holds throughout: the tool never starts until the
firewall is verified present and DNS is up. A raw `podman start` outside netcage
stays fail-closed (LAN/UDP dropped via the baked firewall) but leaves DNS dead;
`netcage start` is the supported path that also restores DNS.

## Reconcile compares the DERIVED baked env, not the raw flags

`jail.Start` reads the sidecar's create-time `PROXY`, `TUN_EXCLUDED_ROUTES`, and
`EXTRA_COMMANDS` env (via `podman inspect --format {{json .Config.Env}}`) and
compares them against what the REQUESTED config would bake
(`sidecarProxyURL` / `excludedRoutes` / `firewallScript`). Equal baked env means
an identical jail, so this one comparison covers the proxy host/port/auth AND the
whole allowlist (accepts + excluded routes + RFC1918 drops) as the container will
ACTUALLY run them on revive. `.Config.Env` is read as JSON, not a newline-joined
text template: the `EXTRA_COMMANDS` firewall value itself contains newlines, so a
`{{range}}...{{"\n"}}` template would split one env var across lines and truncate
the baked firewall to its first line, making every reconcile falsely see a
changed config.

A changed config returns `ErrJailConfigChanged` with an actionable message:
"this container was jailed with a different proxy/allowlist (... differs); remove
it and run again, or start it with the same jail config". (An explicit rebuild
flag that preserves-or-drops state can be a follow-up; the state-preserving
default is refuse.)

## In-scope choices recorded

- **How the baked config is read:** the sidecar's create-time env, as JSON, is
  the single source of truth (the firewall script + excluded routes encode the
  allowlist; PROXY encodes `--proxy`), so no separate metadata store is needed.
- **The exact refuse message:** names the mismatch and the two safe options
  (remove + re-run, or start with the same jail config), so the refusal is
  self-correcting rather than opaque.
- **`start` attaches by default:** non-interactive `netcage start <name>` runs
  `podman start -a` (attach stdout/stderr, output flows through); `netcage start
  -it <name>` runs `podman start -ai` with raw stdio passthrough (a resumed shell
  in the durable environment), mirroring `netcage run -it`. It NEVER `podman run`s
  a fresh container (that would lose state); it starts the EXISTING one.
- **`--rm` on start is ephemeral-this-resume:** honours the ADR-0009 split
  (remove both on exit); without it the pair is left stopped again, fail-closed
  via the baked firewall.
- **`start` refuses create-time flags** (`-v`/`-w`/`-e`/`-u`/`--entrypoint` + the
  widened pass-throughs): they are fixed at create time and a `podman start` takes
  none of them, so accepting-and-ignoring them would silently mislead; they are
  refused loudly. `--proxy`/`--allow-direct` (reconciled) and `-i`/`-t`/`--rm` are
  the flags `start` does take.

## Kept container's resolv.conf must be durable

A KEPT tool container bind-mounts a host resolv.conf; podman re-mounts that SAME
source path on every restart, so the path must OUTLIVE the run. The path is now
run-attributable and STABLE (`$TMPDIR/netcage-resolv-<runID>.conf`), cleaned up
ONLY on an ephemeral run; `netcage start` re-materialises it idempotently before
reviving, so a resume works even if the durable file was swept. (A previous
random `os.CreateTemp` name removed on run exit made even a raw `podman start` of
a kept container fail with crun "cannot stat".)

## Consequences

- A kept jailed container is a durable environment: `netcage run` (no `--rm`)
  leaves it, `netcage start <name>` resumes it with state intact and a leak-tight
  jail (firewall verified, DNS restored), and a changed jail config is refused.
- `start` gets the fail-loud firewall verification, so a half-applied firewall on
  a revive aborts the resume loudly (never a partial jail).
- Removing a kept pair leaves its durable resolv.conf orphaned in `$TMPDIR` (a
  harmless 2-line file); see `work/notes/observations/kept-run-resolvconf-orphans-in-tmp.md`.
