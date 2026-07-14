# Proxy detection + a persisted default proxy belong in netcage (not anon-pi); and a netcage-only verb must never shadow a podman verb

2026-07-04 (decided in a netcage session; captures a decision + a drift + a naming invariant)

## The decision

Two capabilities are **tool-agnostic** and belong in **netcage itself**, so any
netcage user gets them and downstream wrappers (anon-pi) REUSE rather than
reimplement:

1. **Proxy detection** - "probe common SOCKS ports (9050 Tor, 9150 Tor Browser,
   1080 wireproxy/generic), confirm SOCKS5 via an RFC1928 handshake, run `verify`,
   show the exit IP." *Any* netcage user wants "help me find/confirm my proxy and
   prove it anonymizes"; it has nothing to do with pi. -> `netcage detect-proxy`.
2. **A persisted default proxy** (a netcage config file) so `netcage run` needs no
   `--proxy` - netcage becomes a true drop-in podman replacement. -> `netcage
   setup` writes `~/.config/netcage/config.json`; proxy precedence becomes
   `--proxy` flag > `NETCAGE_PROXY` env > config > refuse.

The test applied for the netcage-vs-anon-pi split: **"would a non-pi, non-anon-pi
user of netcage want it? If yes -> netcage."** Both pass cleanly.

**Fail-closed is preserved:** a config/detected proxy is STILL socks5h-validated
and preflighted on every run. Config adds a *source* for the same strict proxy,
never a bypass; a down config proxy still refuses loudly.

## The drift this records

The tool-agnostic proxy DETECTION was originally designed (netcage session,
2026-07-02) as belonging in netcage - a `netcage detect-proxy` / `netcage verify
--detect` primitive that anon-pi's `init` would CALL. But when built, it landed
IN anon-pi (`cli-init-onboarding`, anon-pi PR #18): the probe + SOCKS5 handshake +
findings-without-labels formatter live in anon-pi's `src/anon-pi.ts`, not netcage.
So today the reusable primitive is misplaced one layer up. This note + the
`netcage-config-and-proxy-setup` prd close that gap by putting `detect-proxy` in
netcage; anon-pi can later switch its `init` to reuse it (out of THIS repo's
scope). anon-pi's behaviour is UNCHANGED regardless: it always FORCES a specific
proxy + `--allow-direct` on the netcage launch (via anon-pi config / env), so it
never falls through to netcage's config defaults.

## The naming invariant (load-bearing; `init` was the cautionary example)

**A netcage-ONLY verb must NEVER shadow a real podman verb with a different
meaning** - it would break netcage's drop-in-podman identity. netcage's verbs
split into (a) podman verbs it mirrors faithfully (`run`/`start`/`commit`/`exec`/
`ps`/`logs`/`inspect`/`stop`/`rm`/`images`) and (b) netcage-only verbs whose names
podman does NOT use (`verify` today). A netcage-only verb works precisely BECAUSE
podman has no such verb to collide with.

Concrete near-miss: the onboarding verb was going to be `netcage init`, but
**`podman init` is a REAL podman verb** (initialize a container's OCI spec/mounts).
`netcage init` would shadow it with a completely different meaning -> rejected.
Chosen instead: **`netcage setup`** (onboarding) + **`netcage detect-proxy`**
(primitive), both non-colliding, non-generic. **No prefixing** (`netcage-init`):
`verify` proves a clean, unprefixed netcage-only name is the right pattern; the
rule is simply "pick a name podman does not use."

Checked against the live podman surface (podman <ver> on this host): `init` IS a
podman verb; `verify`, `detect-proxy`, `setup` are NOT. Caveat: podman could add a
verb later - we cannot control that, but we CHECK at authoring time, and this
invariant tells a future author to re-check.

## Where this goes next

Staged as `work/specs/proposed/netcage-config-and-proxy-setup.md` (review-first;
promote -> ready -> task via the normal flow). An ADR is likely warranted for the
fail-closed-source-precedence decision and/or the naming invariant (decide at
tasking).
