# The netcage config file is a NEW proxy SOURCE, never a bypass; the persisted default is credential-free; and a netcage-only verb must never shadow a podman verb

**Status:** accepted (builds on ADR-0005, ADR-0009; foundation of the `netcage-config-and-proxy-setup` prd)

netcage gains a persisted config file (`~/.config/netcage/config.json`,
XDG-aware) so a configured user runs `netcage run <img>` with no `--proxy` and it
Just Works, making netcage a true drop-in `podman` replacement. This ADR records
the two DURABLE, hard-to-reverse invariants that a future reader/writer of that
file must not silently erode. (The lighter choices below are noted as done-record
context, not ADR-worthy.)

## 1. Config is a new proxy SOURCE for the SAME strict proxy, NEVER a bypass

Proxy resolution becomes **`--proxy` flag > `NETCAGE_PROXY` env > config file >
refuse**. Config is the LOWEST-priority default (env still wins, so anon-pi / CI
overrides are unaffected); if none of the three yields a proxy, netcage STILL
refuses with today's fail-closed message.

The fail-closed invariant (CONTEXT.md; the reason this project exists) is NOT
weakened by adding this source:

- The config `proxy` is a full `socks5h://host:port` URL STRING that round-trips
  the SAME `ParseProxy` the flag/env paths use. A plain `socks5://` (a DNS leak)
  or a malformed proxy in config is rejected exactly as on the flag: the config
  path is NEVER laxer. There is ONE validator, not a second lenient one.
- Each config `allowDirect` entry round-trips the SAME `parseAllowDirect`
  (RFC1918 / link-local only; public / hostname / malformed rejected loudly on
  load), so a config split-tunnel hole can never be WIDER than a `--allow-direct`
  hole (ADR-0005's guardrail holds for the config path too).
- A config-sourced proxy is STILL preflighted (reachability-checked, fail-closed)
  on EVERY run, exactly like a flag/env proxy. A down / misconfigured config proxy
  still refuses loudly; it never falls back to the host network.
- A MISSING config file is a clean no-op (not an error), so a user with no config
  and no flag/env still hits today's refusal. A PRESENT-but-broken file (corrupt
  JSON, bad proxy, bad direct) is a LOUD error, never silently ignored.

Only the ERGONOMICS of supplying the proxy change, never the guarantee. Because
the config loader lives INSIDE `internal/cli`, it reuses the exported `ParseProxy`
AND the unexported `parseAllowDirect` without exporting a second, weaker path.

## 2. The persisted default is CREDENTIAL-FREE by construction

`~/.config/netcage/config.json` must never accumulate secrets at rest (backups /
dotfile repos / screen-shares stay safe). The invariant is enforced at the
WRITER, not the reader: `setup-default` (task 4, the ONLY config writer) REFUSES
to persist a proxy carrying embedded `user:pass@` credentials and directs the user
to keep authed proxies in `NETCAGE_PROXY` / `--proxy` (transient). The env/flag
paths still accept credentials freely; only the persisted default is
credential-free. This ADR records the invariant so a future writer honours it.

The LOADER (this task) deliberately does NOT hard-refuse a hand-edited
credentialed config: a user who manually put `user:pass@` in their file still gets
a working run (the restriction is on what netcage WRITES, not a refusal to read),
matching how env/flag already carry credentials. This keeps the reader simple and
the invariant located in exactly one place (the writer). A future reader must not
silently ERODE the source-precedence or the credential-free-write guarantee.

## 3. Naming invariant: a netcage-only verb must never shadow a podman verb

netcage's identity is a drop-in `podman` replacement, so a netcage-ONLY verb that
COLLIDES with a real podman verb (a different meaning under the same name) would
break that identity. `init` is the cautionary example: it was the obvious name for
the onboarding writer, but **`podman init` is a real podman verb** (initialize a
container's OCI spec). So the config writer is named `setup-default` (no podman
collision; the name also signals the silent-default tradeoff), and the detection
primitive is `detect-proxy` (no collision), following the existing `verify`
pattern (a netcage-only verb precisely because podman has no `verify`). No
prefixing (`netcage-init`): a non-colliding, non-generic name is the rule.

## Consequences

- `verify` (task 2) resolves the proxy the SAME way and gets config resolution for
  free; it only adds a `source: flag|env|config` line. The `ProxySource` signal is
  owned at the single resolution point in `internal/cli` so `verify` /
  `setup-default` READ it rather than re-derive it.
- `--allow-direct` precedence is REPLACE, not additive: an explicit CLI
  `--allow-direct` supplies the COMPLETE allowlist and fully overrides the config
  list (nothing implicitly rides along); the config list applies only when no CLI
  `--allow-direct` is given. Consistent with the proxy precedence (a flag, when
  given, IS the answer) and safe (additive would silently widen the jail). This is
  a done-record note, not a separate ADR.
- `netcage start`'s reconcile (ADR-0011) now compares against the config-resolved
  proxy/allowlist when no flag is given, so a bare `netcage start <name>` reconciles
  the config default against the container's baked config, same as `run` resolves it.
