---
title: `netcage setup-default` - interactive onboarding that detects/confirms/verifies a proxy and persists it (credential-free) as netcage's default
slug: setup-default-onboarding
spec: netcage-config-and-proxy-setup
blockedBy: [detect-proxy-verb-with-json]
covers: [1, 2, 7]
---

## What to build

Add `netcage setup-default`: the interactive, re-runnable onboarding that installs
a DEFAULT proxy into `~/.config/netcage/config.json`, so a bare `netcage run`
needs no `--proxy`. It is the ONLY thing that WRITES the config file; it composes
the three pieces the earlier tasks built.

- **Flow:** run `detect-proxy` (task 3) -> let the user CHOOSE a detected proxy or
  enter `host:port` -> run `netcage verify` (task 2) on the choice and show the
  exit IP as evidence it differs from the host -> WARN about the silent-default
  tradeoff -> WRITE the chosen `socks5h://...` (and optionally an `allowDirect`
  list) into the config.
- **The verb is named `setup-default`, NOT `setup`** - the name itself signals "you
  are installing a DEFAULT proxy that a bare `netcage run` will silently use". The
  one-time tradeoff WARNING lives here, at write time ("from now on a bare
  `netcage run` uses this proxy with no per-run reminder; run `netcage verify` any
  time to confirm which proxy you are on and that your exit IP is not the host's").
- **Credential-free by construction:** `setup-default` REFUSES to persist a proxy
  carrying embedded `user:pass@` credentials, directing the user to keep authed
  proxies in `NETCAGE_PROXY` / `--proxy` (transient) instead. So the config file
  never holds secrets at rest. The env/flag paths still accept credentials freely -
  only the PERSISTED default is credential-free.
- **Write `0600`** (owner-only) regardless.
- **Re-runnable (doubles as reconfigure):** shows current config values pre-filled;
  never destroys machines/state; never clobbers silently (confirm before
  overwriting an existing config).
- **`setup-default` is a NETCAGE-ONLY verb** (podman has no such verb; `init` was
  rejected because `podman init` is real - see the ADR from task 1). No `--proxy`
  preflight (it is establishing the proxy, not egressing a jailed run).

## Acceptance criteria

- [ ] `netcage setup-default` runs detection, lets the user choose/enter a proxy,
      verifies it (shows the exit IP differs from host), warns about the
      silent-default tradeoff, and writes the choice to `~/.config/netcage/config.json`.
- [ ] After `setup-default`, a bare `netcage run <img>` (no `--proxy`, no env) uses
      the persisted proxy (the task-1 precedence resolves it).
- [ ] `setup-default` REFUSES to persist a `user:pass@` (credentialed) proxy, with
      a clear message pointing at `NETCAGE_PROXY` / `--proxy` for authed proxies;
      the config file is never written with credentials.
- [ ] The config file is written `0600`.
- [ ] Re-running `setup-default` shows current values and does not clobber silently
      (confirms before overwriting); it never destroys unrelated state.
- [ ] Tests cover the pure DECISION logic (choice handling, the credential-refusal,
      the pre-filled-reconfigure path, the warning text) with impure prompt/verify/
      write I/O behind injectable seams (mirror how the codebase tests interactive/
      impure flows; no real podman needed for the decision tests).
- [ ] **Shared-write isolation:** `setup-default` writes a real user config
      (`~/.config/netcage/config.json`). Tests MUST point the config location at a
      temp/scratch dir (via `XDG_CONFIG_HOME` or an injectable path seam) AND assert
      the real `~/.config/netcage` is UNTOUCHED after the run.

## Blocked by

- `detect-proxy-verb-with-json` - composes it (detection engine). Transitively also
  needs `config-file-and-proxy-precedence` (the config loader/writer + precedence)
  and `verify-report-resolved-proxy-and-source` (the verify evidence step); the
  single blocker suffices since the chain 1 -> 2 -> 3 enforces the full order, and
  all four edit `internal/cli` so serialising keeps rebases trivial.

## Prompt

> Goal: add `netcage setup-default` - the interactive, re-runnable onboarding that
> detects a SOCKS proxy (via `detect-proxy`), lets the user choose/enter one,
> verifies it, WARNS about the silent-default tradeoff, and PERSISTS it
> (credential-free) into `~/.config/netcage/config.json`, so a bare `netcage run`
> needs no `--proxy`. It is the final task of the `netcage-config-and-proxy-setup`
> prd and the ONLY config writer.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm the three tasks it composes landed - `config-file-and-proxy-
> precedence` (config loader + write path + precedence + credential-free invariant,
> and the ADR), `detect-proxy-verb-with-json` (the detection engine, callable
> in-process), and `verify-report-resolved-proxy-and-source` (verify usable as the
> evidence step). If any landed differently (e.g. the config writer/seam is shaped
> differently than assumed, or detect-proxy is not callable in-process), adapt or
> route to needs-attention - do NOT build on a stale seam.
>
> Domain: netcage forces egress through a socks5h proxy, fail-closed; the proxy is
> REQUIRED. This verb makes the proxy a persisted DEFAULT so netcage feels like
> podman. The honesty model (settled in the prd): the verb NAME carries the weight
> (`setup-default`, not an innocent `setup`), the tradeoff warning fires ONCE here
> at write time (no per-run chatter), and the persisted default is CREDENTIAL-FREE
> by construction (authed proxies stay in env/flag). Never label the exit provider
> (inherited from detect-proxy's evidence-only output).
>
> Where to look / seams: add `setup-default` to the netcage-only verb surface
> (`internal/cli` parse + `main.go` routing) as a non-jail utility (no `--proxy`
> preflight). Compose the in-process detect-proxy engine, the verify evidence step,
> and the config WRITE path from task 1 (reuse its writer + credential-free rule;
> do not fork a second writer). Keep the DECISION logic pure/testable (choice,
> credential-refusal, reconfigure-prefill, warning text) with the prompt/verify/
> write I/O behind injectable seams. Write `0600`. Re-runnable + confirm-before-
> overwrite.
>
> Preserve the invariants: credential-free persistence (REFUSE a `user:pass@`
> proxy at write, point to env/flag); fail-closed unchanged (a persisted proxy is
> still validated + preflighted on every run - that is task 1's job, not weakened
> here); config location isolated in tests with the real one asserted untouched.
>
> Done = `netcage setup-default` detects/chooses/verifies/warns/writes a
> credential-free default proxy `0600`; a subsequent bare `netcage run` uses it;
> credentialed proxies are refused at persist with a clear redirect; it is
> re-runnable without clobbering; tests cover the decision logic + credential
> refusal + the shared-write isolation of the config location.
