---
title: netcage config file - a persisted, credential-free default proxy (+ allowDirect list) as a new lowest-priority proxy source
slug: config-file-and-proxy-precedence
spec: netcage-config-and-proxy-setup
blockedBy: []
covers: [1, 6]
---

## What to build

Add a netcage config file so a configured user runs `netcage run -it alpine sh`
with NO `--proxy` and it Just Works - making netcage a true drop-in podman
replacement. Today proxy resolution is `--proxy` flag > `NETCAGE_PROXY` env >
refuse; this task adds a persisted config as a NEW, lowest-priority source, so it
becomes **flag > env > config > refuse**.

- **Config file:** `~/.config/netcage/config.json` (honour `XDG_CONFIG_HOME`).
  Minimal shape: `{ "proxy": "socks5h://host:port", "allowDirect": ["192.168.1.0/24", "10.0.0.5:8080"] }`.
  - `proxy`: the full socks5h URL STRING, validated by the SAME socks5h-enforcing
    proxy parser the flag/env paths use (a plain `socks5://` in config is rejected
    exactly as on the flag - the config path is NOT laxer).
  - `allowDirect`: a JSON ARRAY of raw `--allow-direct` strings (multiple entries),
    each fed through the SAME allow-direct validator on load (RFC1918 / link-local
    only; loud reject on public / hostname / malformed).
- **Proxy precedence:** flag > env > config > refuse. Config is the lowest-priority
  DEFAULT; env still wins (so anon-pi / CI env overrides are unaffected). If none
  of the three yields a proxy, netcage STILL refuses (fail-closed unchanged).
- **`--allow-direct` precedence: REPLACE, not additive.** An explicit
  `--allow-direct` on the CLI supplies the COMPLETE allowlist for that run and
  fully overrides the config `allowDirect`; config directs are NOT implicitly
  carried along. Only when NO `--allow-direct` is given does the config list apply.
  (Rationale: `--allow-direct` is the one hole-opening feature, so what the user
  types is the complete set of holes - additive would silently widen the jail.)
- **Credential-free by construction:** the LOADER accepts a credential-free
  persisted proxy; the WRITER (task 4, `setup-default`) is what refuses to persist
  a `user:pass@` proxy. This task's job is the load + precedence + validation; note
  the invariant in the ADR so a future writer honours it. (Loading a config that a
  user hand-edited to include credentials should still WORK - the restriction is on
  what netcage WRITES, not a hard refusal to read; decide + record whether the
  loader warns on hand-edited credentials or accepts them silently. Lean: accept,
  since env/flag also carry credentials.)
- **A missing config file is a no-op** (not an error): a user with no config and no
  flag/env still gets today's "no proxy: refuse" message.
- **Expose which SOURCE won.** The resolution must record/return which of
  flag / env / config supplied the proxy, so downstream verbs can report it (task 2
  prints `source: ...`; task 4 reads it). Own this signal HERE so those tasks read
  it rather than retrofit it into this task's code.

Where it lives: the config loader belongs INSIDE `internal/cli` so it can reuse
the exported proxy parser AND the UNEXPORTED allow-direct validator without
exporting the latter. Wire it into the existing proxy-resolution point (where
`flag > env > refuse` is decided today) as the new fallback rung, and into the
`--allow-direct`-vs-config REPLACE decision.

## Acceptance criteria

- [ ] With a config file holding a valid `proxy`, `netcage run <img>` (no `--proxy`,
      no `NETCAGE_PROXY`) resolves the config proxy and runs; precedence is
      flag > env > config > refuse (an explicit flag or env still wins).
- [ ] Proxy resolution RECORDS which source won (flag | env | config) and exposes
      it (so tasks 2/4 can report it); a test asserts the correct source is recorded
      for each of flag / env / config.
- [ ] The config `proxy` goes through the SAME socks5h-enforcing validation as the
      flag/env: a `socks5://` (or malformed) proxy in config is rejected loudly,
      not accepted laxer.
- [ ] Config `allowDirect` is a LIST; each entry is validated by the same
      allow-direct validator (RFC1918/link-local only; public/hostname/malformed
      rejected). An explicit `--allow-direct` on the CLI REPLACES the config list
      wholesale (config directs not carried along); with no CLI `--allow-direct`,
      the config list applies.
- [ ] A MISSING config file is a no-op: with no config AND no flag/env, netcage
      still refuses with the existing fail-closed "no proxy" message. Fail-closed
      is unchanged: a config/down proxy is still preflighted and refused if
      unreachable.
- [ ] An ADR is authored (see the Prompt) recording the fail-closed source
      precedence + credential-free persistence invariant + the podman-non-shadowing
      naming invariant.
- [ ] Tests cover: precedence resolution (flag/env/config/none), config socks5h
      validation (reject `socks5://`), `allowDirect` list parse + REPLACE semantics,
      and the missing-file no-op - mirroring the existing `internal/cli` parse tests
      (injectable env + a config path/loader seam, no real `$HOME` mutation).
- [ ] **Shared-write isolation:** the config lives in a real user dir
      (`~/.config/netcage`). Tests MUST point the config location at a temp/scratch
      dir (via `XDG_CONFIG_HOME` or an injectable path seam) AND assert the real
      `~/.config/netcage` is UNTOUCHED after the run.

## Blocked by

- None - can start immediately. Builds on the shipped `internal/cli` proxy
  resolution (`ParseProxy`, the `NETCAGE_PROXY` env fallback, `parseAllowDirect`).

## Prompt

> Goal: give netcage a persisted config file (`~/.config/netcage/config.json`) so
> `netcage run` needs no `--proxy` - a new, LOWEST-priority proxy source making
> proxy resolution `--proxy` flag > `NETCAGE_PROXY` env > config > refuse. This is
> the foundation task of the `netcage-config-and-proxy-setup` prd; the verify /
> detect-proxy / setup-default tasks build on it.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm `internal/cli` still resolves the proxy as flag > env > refuse
> (the `proxyFromFlag` / `NETCAGE_PROXY` lookup in `ParseWithEnv`), that
> `ParseProxy` is the exported socks5h-enforcing validator, and that
> `parseAllowDirect` is UNEXPORTED in `package cli` (so the config loader must live
> in `internal/cli` to reuse it, or you must export it - prefer keeping it in
> `internal/cli`). If any landed differently, adapt or route to needs-attention.
>
> Domain: netcage is a drop-in podman replacement forcing all egress through a
> socks5h proxy, fail-closed. The proxy is REQUIRED (netcage refuses to run
> without one, never leaking to the host network). `--allow-direct` opens a narrow,
> validated split-tunnel hole for RFC1918/link-local LAN destinations only.
>
> Where to look / seams: the proxy-resolution block in `internal/cli`'s parse (add
> config as the fallback after env, before the refuse); `ParseProxy` (reuse for the
> config proxy - do NOT write a second, laxer validator); `parseAllowDirect` (reuse
> for each config `allowDirect` entry); the `--allow-direct`-collected list (make an
> explicit CLI list REPLACE the config list). Add a small config loader
> (`~/.config/netcage/config.json`, `XDG_CONFIG_HOME`-aware) with an injectable path
> for tests. A missing file is a clean no-op.
>
> Preserve fail-closed: config is a new SOURCE for the same strict proxy, NEVER a
> bypass. A config proxy is still socks5h-validated and still preflighted
> (reachability-checked) on every run; a down/misconfigured config proxy still
> refuses loudly. No config + no flag/env still refuses with today's message.
>
> Credential note: this task LOADS config; the REFUSAL to PERSIST credentials is
> task 4 (`setup-default`, the writer). Decide + record whether the loader warns on
> a hand-edited credentialed proxy or accepts it (lean: accept, matching env/flag).
>
> RECORD the durable decisions as ONE ADR in `docs/adr/` (this task authors it):
> (1) **fail-closed source precedence** - config is a NEW proxy source but NEVER a
> bypass (still socks5h-validated + preflighted every run), and the persisted
> default is CREDENTIAL-FREE by construction (the writer refuses `user:pass@`); a
> future reader must not silently erode this; and (2) the **naming invariant** - a
> netcage-ONLY verb must never shadow a podman verb, with `init` as the cautionary
> example (`podman init` is real; that is why the config writer is `setup-default`,
> not `init`). The lighter choices (URL-string storage, REPLACE semantics) are
> done-record notes, not ADR-worthy.
>
> Done = a configured user runs `netcage run <img>` with no `--proxy` and it uses
> the config proxy; precedence is flag > env > config > refuse; config proxy +
> allowDirect are validated by the same validators; explicit `--allow-direct`
> replaces the config list; missing config is a no-op; fail-closed intact; the ADR
> is written; tests cover precedence + validation + REPLACE + missing-file, with
> the config location isolated to a temp dir and the real one asserted untouched.
