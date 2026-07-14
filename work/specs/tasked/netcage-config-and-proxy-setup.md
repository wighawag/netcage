---
title: netcage config + `setup-default`/`detect-proxy` - a persisted (credential-free) default proxy so netcage is a true drop-in podman replacement (no --proxy needed)
slug: netcage-config-and-proxy-setup
---

> Launch snapshot - records intent at creation, NOT maintained. Current truth:
> `docs/adr/` (decisions) + the code; remaining work: `work/tasks/`. TASKED: the
> implementation detail + the ADR now live in `work/tasks/` (the 4 tasks below)
> and `docs/adr/`; this prd is trimmed to its durable framing.

## Problem Statement

netcage's identity is a **drop-in `podman` replacement whose container egress is
forced through a socks5h proxy, fail-closed**. Today the proxy MUST be supplied
on every invocation: proxy resolution is **`--proxy` flag > `NETCAGE_PROXY` env >
refuse** (`internal/cli/cli.go`). So a user who always uses the same proxy still
has to type `--proxy socks5h://...` (or export the env) on every `netcage run`,
which breaks the "just use it like podman" feel. `podman run alpine sh` needs no
setup; `netcage run alpine sh` refuses with "no proxy".

Two capabilities are missing and, per the netcage-vs-anon-pi placement analysis
(see `work/notes/observations/proxy-detection-and-config-belong-in-netcage.md`),
BOTH are tool-agnostic and belong in netcage itself, not in a downstream wrapper:

1. **A persisted default proxy** (a netcage config file), so a configured user
   runs `netcage run -it alpine sh` with NO `--proxy` and it Just Works.
2. **Proxy DETECTION** ("probe common SOCKS ports, confirm SOCKS5, verify, show
   the exit IP") - completely tool-agnostic; any netcage user wants "help me
   find/confirm my proxy and prove it anonymizes". It is currently (mis)placed in
   anon-pi's `init` (shipped as anon-pi PR #18); the reusable primitive should
   live in netcage so anon-pi's onboarding CALLS it (via a `--json` contract)
   rather than reimplementing.

### Honesty model (settled in grilling - the load-bearing shape)

The fail-closed invariant is preserved AND made honest without per-run chatter:

- **The verb name carries the weight.** The config writer is `setup-default`, NOT
  an innocent `setup`: the name itself signals "you are installing a *default*
  proxy that bare `netcage run` will silently use." The one-time tradeoff warning
  lives IN `setup-default` at write time ("from now on a bare `netcage run` uses
  this proxy with no per-run reminder").
- **NO per-run warning line.** A bare `netcage run` resolving its proxy from config
  is SILENT (podman-like). We dropped the every-run stderr line.
- **Runs stay fast + structurally fail-closed, exit-IP-BLIND (unchanged).** A run
  today only TCP-dials the proxy (Preflight) + verifies the firewall + reachback;
  it does NOT fetch/compare the exit IP. We keep it that way (no probe-container
  cost on the hot path).
- **The "am I actually anonymized / which proxy am I on?" proof lives in `verify`.**
  `netcage verify` resolves the proxy the SAME as a run (flag > env > config) and
  ALREADY asserts the exit IP DIFFERS from the host IP (the shipped
  `forced-egress-exit-ip-differs-from-host` leak check in `internal/verify`,
  comparing `ExitIPProbe` to `hostExitIP`). The ONLY enhancement this prd adds is
  that `verify` PRINTS the resolved proxy AND its source
  (`proxy: ... (source: flag|env|config)`) in its report - so it also answers
  "which proxy am I on?". Once config is a proxy source (task 1), `verify` gets
  config resolution for FREE (it uses the CLI-resolved proxy). This absorbs the
  inspector role, so there is NO separate `config show` verb. `setup-default` runs
  `verify` as evidence before writing.

**The fail-closed invariant is NOT weakened by any of this** (the load-bearing
constraint): a config proxy is still socks5h-validated and still preflighted
(reachability-checked, fail-closed) on EVERY run. The config file only adds a new
*source* for the same strict proxy; it is never a bypass. A down / misconfigured
config proxy still refuses loudly. Only the ERGONOMICS of supplying the proxy
change, never the guarantee.

## Solution

### 1. netcage config file (a new, lowest-priority proxy source)

- Location: `~/.config/netcage/config.json` (XDG; honour `XDG_CONFIG_HOME`).
- Minimal shape:
  ```json
  { "proxy": "socks5h://127.0.0.1:9050", "allowDirect": ["192.168.1.0/24", "10.0.0.5:8080"] }
  ```
  - `proxy`: a socks5h URL, validated by the SAME `ParseProxy` (socks5h-enforcing;
    a plain socks5:// in config is rejected exactly as on the flag - the config
    path is NOT laxer).
  - `allowDirect`: a JSON ARRAY of raw `--allow-direct` strings (MULTIPLE entries),
    each fed through the SAME `parseAllowDirect` validation on load (RFC1918 /
    link-local only, loud reject on public/hostname/malformed). Mirrors that
    `--allow-direct` is already repeatable on `run`.
- **Config `proxy` is stored as the full URL STRING** (`socks5h://host:port`), not
  structured host/port/auth: it round-trips the SAME socks5h-enforcing
  `ParseProxy` the flag/env paths use (one validator, no laxer second path). All
  three sources carry the identical artifact; the loader hands whichever URL to
  `ParseProxy`.
- **The persisted default is CREDENTIAL-FREE by construction.** `setup-default`
  REFUSES to write a proxy carrying embedded `user:pass@` credentials, directing
  the user to keep authed proxies in `NETCAGE_PROXY`/`--proxy` (transient). The
  env/flag paths STILL accept credentials freely; only the persisted default is
  credential-free, so `~/.config/netcage/config.json` never accumulates secrets at
  rest (backups / dotfile repos / screen-shares stay safe). The config file is
  written `0600` regardless. (The convenience feature targets the local auth-less
  proxy - exactly what `detect-proxy` finds - so this costs the common case
  nothing.)
- **Proxy precedence becomes: `--proxy` flag > `NETCAGE_PROXY` env > config file >
  refuse.** Config is the lowest-priority DEFAULT; env still wins (so anon-pi and
  CI overrides are unaffected). If none of the three yields a proxy, netcage still
  REFUSES (fail-closed unchanged).
- **`--allow-direct` precedence: REPLACE, not additive.** An explicit
  `--allow-direct` on the CLI supplies the COMPLETE allowlist for that run and
  fully OVERRIDES the config `allowDirect`; config directs are NOT implicitly
  carried along. Only when NO `--allow-direct` is given does the config list
  apply. Rationale: `--allow-direct` is the one hole-opening feature, so "what you
  type is the complete set of holes, nothing hidden rides along" is the safe
  surprise (additive would silently widen the jail beyond what the user typed).
  Consistent with the proxy precedence (a flag, when given, IS the answer). anon-pi
  is unaffected (it always passes explicit `--allow-direct`).

### 2. `netcage verify` (enhanced - report the resolved proxy + its source)

- Resolves the proxy the SAME as a run: `flag > env > config > refuse`, so `netcage
  verify` with no `--proxy` proves the config default. This falls out of task 1
  wiring config into CLI proxy resolution (verify uses the CLI-resolved proxy), so
  it is essentially free.
- Prints the resolved proxy AND its source in the report:
  `proxy: socks5h://... (source: flag|env|config)`. This is the ONLY new behaviour.
- **The exit-IP-vs-host proof ALREADY EXISTS** (the shipped
  `forced-egress-exit-ip-differs-from-host` leak check compares `ExitIPProbe` to
  `hostExitIP`; a same-as-host exit already fails as a leak). Do NOT re-add it -
  task 2 is JUST the resolved-proxy + source line.
- This absorbs the config-inspector role: there is NO separate `config show` verb.

### 3. `netcage detect-proxy` (the reusable detection primitive)

- Probes common SOCKS ports: `127.0.0.1:9050` (Tor), `127.0.0.1:9150` (Tor
  Browser), `127.0.0.1:1080` (wireproxy / generic).
- CONFIRMS each open port is really SOCKS5 via a minimal RFC1928 handshake (an
  open port is not enough).
- Presents FINDINGS: which ports answered, which spoke SOCKS5, and (for a chosen
  one) the real `netcage verify` exit IP as proof it is not the host IP.
- **Honesty constraint (load-bearing for an anonymity-adjacent tool):** presents
  EVIDENCE ONLY (open ports, the SOCKS5 handshake result, the real exit IP) plus
  WEAK, HEDGED, provider-AGNOSTIC process hints ("a `tor` process is running ->
  likely Tor"). It MUST NEVER claim/label the exit provider (a SOCKS proxy does
  not announce Mullvad/Proton; a false label is a dangerous lie). A test asserts
  no provider label is ever emitted.
- **`--json` machine output from day one (the reuse CONTRACT).** Detection lives in
  netcage SO IT CAN BE CALLED; without `--json`, anon-pi cannot reuse it and the
  drift re-opens. The JSON serialises the structured facts already computed
  (`{port, open, socks5, processHint?}` per candidate, plus `exitIP`), has a
  `schemaVersion` (additive-only changes), and by CONSTRUCTION has NO
  `provider`/`label` field - making the never-label-the-provider honesty a
  STRUCTURAL property of the output (a test asserts the schema has no provider
  field), not just a runtime rule.

### 4. `netcage setup-default` (interactive onboarding - the ONLY config writer)

- The one-time (re-runnable) onboarding: runs `detect-proxy`, lets the user CHOOSE
  a detected proxy or enter `host:port`, runs the enhanced `netcage verify` on the
  choice and shows the exit IP (proof it differs from host), WARNS about the
  silent-default tradeoff, then WRITES the chosen `socks5h://...` (and optionally
  `allowDirect`) into `~/.config/netcage/config.json`.
- REFUSES to persist a credentialed proxy (see the credential-free invariant
  above); writes `0600`.
- Re-runnable: doubles as reconfigure; shows current config values pre-filled;
  never clobbers silently.
- `setup-default` is the ONLY thing that writes config; `detect-proxy` is the
  reusable probe; `verify` is the proof. Named `setup-default` (not `setup`) so the
  verb itself signals "install a silent default proxy."

### Naming (a real podman-conflict was avoided - see the observation note)

- `init` was the obvious name but **`podman init` is a REAL podman verb**
  (initialize a container's OCI spec) - a netcage-only verb must NEVER shadow a
  podman verb with a different meaning (it would break the drop-in identity). So
  the onboarding verb is **`setup-default`** (no podman collision; the name also
  signals the silent-default tradeoff), and the primitive is **`detect-proxy`**
  (no collision). Verified against the live podman surface: `init` IS a podman
  verb; `setup-default`, `detect-proxy`, `verify`, `config` are NOT. This follows
  the existing pattern: `verify` is already a netcage-only verb precisely because
  podman has no `verify`. NO prefixing (`netcage-init`) - a non-colliding,
  non-generic name is the rule, as `verify` proves. (`config` is also collision-
  free but we chose NOT to add a `config`-family verb: `verify` absorbs the
  inspector role.)

## User Stories

1. As a netcage user with a stable proxy, after `netcage setup-default` once, I run
   `netcage run -it alpine sh` with NO `--proxy` and it works - netcage is a true
   drop-in podman replacement.
2. As a first-time user, `netcage setup-default` PROBES for my SOCKS proxy (Tor /
   wireproxy / generic), CONFIRMS it is SOCKS5, VERIFIES the exit IP (proof it
   differs from host), WARNS me I am installing a silent default, and saves it - I
   never have to know the URL format.
3. As any netcage user, `netcage detect-proxy` finds/confirms my proxy and proves
   it anonymizes, presenting EVIDENCE ONLY and NEVER labelling the exit provider;
   `--json` gives a stable machine contract.
4. As an operator, `netcage verify` (with no `--proxy`) tells me WHICH proxy a bare
   run resolves to and its SOURCE, and proves my exit IP is not the host IP - so I
   can check "am I on the right proxy / am I anonymized?" on demand (no per-run
   chatter, no per-run cost).
5. As the anon-pi maintainer, anon-pi's `init` CALLS `netcage detect-proxy --json`
   instead of reimplementing the probe + handshake. anon-pi's own behaviour is
   UNCHANGED: it still FORCES a specific proxy (via anon-pi config / env) and
   `--allow-direct` on the netcage launch, so it NEVER falls through to netcage's
   config defaults - it always specifies both explicitly.
6. As a security-conscious user, netcage NEVER persists proxy credentials:
   `setup-default` refuses to write a `user:pass@` proxy and points me to env/flag,
   so my config file never holds secrets at rest.
7. As a user, `netcage setup-default` is re-runnable (reconfigure), shows current
   values, and never destroys anything silently.

## Out of Scope

- Any weakening of fail-closed: a config/detected proxy is STILL socks5h-validated
  and preflighted on every run. No silent host-network fallback, ever.
- Labelling / naming the exit provider (Mullvad/Proton/...): forbidden by the
  honesty constraint; detection is evidence-only.
- Multi-profile config / named proxy profiles: a single default proxy +
  allowDirect list for now; profiles can be a follow-up.
- Persisting CREDENTIALED proxies: forbidden by construction (authed proxies use
  env/flag). An explicit escape hatch could be a later, off-by-default feature.
- A separate `config`/`config show` verb: NOT built; `verify` absorbs the inspector
  role.
- A per-run "using proxy from config" stderr line: deliberately dropped (the
  `setup-default` verb name + one-time warning carry the honesty; `verify` gives
  the on-demand proof).
- Exit-IP verification on the `run` hot path: OUT. Runs stay fast + structurally
  fail-closed but exit-IP-blind, as today; exit-IP proof lives in `verify` /
  `setup-default` only.
- Changing anon-pi: anon-pi keeps forcing its own proxy + allow-direct explicitly.
  The only anon-pi-side change (out of THIS repo's scope) is that its `init`
  reuses `detect-proxy --json`.

## Resolved decisions (grilled 2026-07-04)

All open questions resolved. The implementation detail now lives in the tasks;
the durable rationale (fail-closed source precedence + credential-free persistence
+ the podman-non-shadowing naming invariant) is relocated to the ADR that task 1
authors (`docs/adr/`). Kept here as the durable summary:

- **Proxy precedence:** `--proxy` flag > `NETCAGE_PROXY` env > config > refuse.
- **Config `proxy` shape:** full URL string (round-trips `ParseProxy`).
- **Persisted default is credential-free by construction:** `setup-default` refuses
  `user:pass@`; env/flag still accept it; file is `0600`.
- **`--allow-direct` vs config list:** REPLACE (flag is the complete set; nothing
  implicitly carried).
- **Inspector:** no `config show`; `verify` reports resolved proxy + source. The
  exit-IP-vs-host proof ALREADY ships in `verify` (unchanged).
- **`detect-proxy --json`:** from day one; `schemaVersion`; NO provider field by
  construction.
- **Naming:** `setup-default` + `detect-proxy` (both podman-collision-free; `init`
  rejected because `podman init` exists).

## Tasks

Decomposed into 4 dependency-ordered tasks in `work/tasks/` (all edit `internal/cli`,
serialised to keep rebases trivial):

1. `config-file-and-proxy-precedence` - the config loader + precedence + REPLACE
   semantics + the ADR. (covers 1, 6)
2. `verify-report-resolved-proxy-and-source` - the verify source-report line only.
   (covers 4)
3. `detect-proxy-verb-with-json` - the probe + SOCKS5 handshake + `--json` contract.
   (covers 3, 5)
4. `setup-default-onboarding` - the interactive, credential-free config writer.
   (covers 1, 2, 7)
