---
title: `netcage detect-proxy` - probe common SOCKS ports, confirm SOCKS5, evidence-only (never label the provider), with a `--json` reuse contract
slug: detect-proxy-verb-with-json
spec: netcage-config-and-proxy-setup
blockedBy: [verify-report-resolved-proxy-and-source]
covers: [3, 5]
---

## What to build

Add `netcage detect-proxy`: a reusable, tool-agnostic primitive that helps a user
find and confirm a local SOCKS proxy, presenting EVIDENCE ONLY. It is the engine
`setup-default` (task 4) drives interactively, and the primitive anon-pi's `init`
CALLS (via `--json`) instead of reimplementing.

- **Probe common SOCKS ports:** `127.0.0.1:9050` (Tor), `127.0.0.1:9150` (Tor
  Browser), `127.0.0.1:1080` (wireproxy / generic). Report which answered.
- **Confirm real SOCKS5:** for each open port, perform a minimal RFC1928 SOCKS5
  handshake (a no-auth method negotiation is enough) - an open port is NOT enough,
  netcage must confirm it actually speaks SOCKS5.
- **Present FINDINGS:** which ports were open, which confirmed SOCKS5, plus WEAK,
  HEDGED, provider-AGNOSTIC process hints ("a `tor` process is running -> likely
  Tor"). Optionally, for a candidate, show the real exit IP as proof (reuse
  `netcage verify`'s exit-IP machinery; do not reinvent it).
- **HONESTY CONSTRAINT (load-bearing for an anonymity-adjacent tool):** the output
  presents EVIDENCE ONLY (open ports, SOCKS5 handshake result, exit IP) and weak
  process hints. It MUST NEVER claim/label the exit PROVIDER (a SOCKS proxy does
  not announce Mullvad/Proton; a false label is a dangerous lie). A test asserts no
  provider label is ever emitted.
- **`--json` machine output from day one (the REUSE CONTRACT):** without it,
  anon-pi cannot reuse this and the "detection belongs in netcage" drift re-opens.
  The JSON serialises the structured facts already computed - per candidate
  `{ port, open, socks5, processHint? }` plus an overall `exitIP?` - and carries a
  `schemaVersion` (additive-only evolution). By CONSTRUCTION the schema has NO
  `provider` / `label` field, making the never-label-the-provider honesty a
  STRUCTURAL property (a test asserts the schema has no provider field), not just a
  runtime rule.
- `detect-proxy` is a NETCAGE-ONLY verb (podman has no `detect-proxy`); it does NOT
  egress like a jailed run and carries NO `--proxy` (it is looking FOR one), so it
  is not subject to the run flag allow-list or the proxy preflight - route it like
  a non-jail utility verb.

## Acceptance criteria

- [ ] `netcage detect-proxy` probes 9050 / 9150 / 1080, confirms SOCKS5 via an
      RFC1928 handshake on each open port, and prints human-readable findings.
- [ ] Findings present EVIDENCE ONLY (open ports, handshake result, weak hedged
      process hints) and NEVER claim/label the exit provider. A test asserts no
      provider label is emitted.
- [ ] `netcage detect-proxy --json` emits structured findings: per-candidate
      `{ port, open, socks5, processHint? }`, an overall `exitIP?`, and a
      `schemaVersion`. The JSON schema has NO provider/label field (asserted by a
      test).
- [ ] `detect-proxy` carries no `--proxy` and is not run through the run flag
      allow-list / proxy preflight (it is looking for a proxy, not egressing).
- [ ] Tests cover: the port-probe + handshake decisions (pure, against a
      fixture/injected socket - reuse `internal/socks5hfixture` where it fits; NO
      dependency on a real Tor), the evidence-only / no-provider-label guarantee,
      and the `--json` shape incl. schemaVersion and the structural absence of a
      provider field.
- [ ] **Shared-write isolation:** if any test opens real localhost ports, it uses
      an ephemeral fixture (e.g. `internal/socks5hfixture` on `127.0.0.1:0`) it
      tears down; it never assumes or mutates a host-global proxy.

## Blocked by

- `verify-report-resolved-proxy-and-source` - not a functional dependency, but it
  edits `internal/cli` verb dispatch (adding a new verb), so it is serialised after
  the verify task to keep the shared `internal/cli` rebases trivial; `detect-proxy`
  also reuses `verify`'s exit-IP machinery for the optional exit-IP evidence.

## Prompt

> Goal: add `netcage detect-proxy` - probe common SOCKS ports (9050 Tor / 9150 Tor
> Browser / 1080 generic), confirm real SOCKS5 via an RFC1928 handshake, present
> EVIDENCE-ONLY findings, and emit a `--json` reuse contract. It is the reusable
> primitive `setup-default` drives and anon-pi's `init` calls. Part of the
> `netcage-config-and-proxy-setup` prd.
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm how netcage adds a NETCAGE-ONLY verb today (e.g. `verify` -
> parsed in `internal/cli`, routed in `main.go`, carries no proxy/allow-list),
> confirm `internal/socks5hfixture` exists as an in-process SOCKS5 fixture to test
> the handshake against, and confirm `internal/verify`'s exit-IP probe is reusable
> for the optional exit-IP evidence. If any landed differently, adapt or route to
> needs-attention.
>
> Domain: netcage forces egress through a socks5h proxy, fail-closed. This verb is
> the OPPOSITE end - it HELPS FIND the proxy. It is tool-agnostic (any netcage user
> wants "find/confirm my proxy"), which is why it lives in netcage, not in a
> wrapper. The honesty constraint is load-bearing: netcage is an anonymity-adjacent
> tool, so detection must present evidence and NEVER label the exit provider (a
> false "you are on Mullvad" is a dangerous lie).
>
> Where to look / seams: add `detect-proxy` to the netcage-only verb surface
> (`internal/cli` parse + `main.go` routing) as a non-jail utility (no `--proxy`, no
> preflight, no run allow-list). Put the PURE detection decisions (port list,
> handshake result -> findings, findings -> human text, findings -> JSON) in a
> testable seam; keep the impure socket I/O thin. Reuse `internal/socks5hfixture`
> to test the RFC1928 handshake without a real Tor. Reuse `internal/verify`'s
> exit-IP machinery for the optional exit-IP evidence; do not reinvent it.
>
> The `--json` schema IS the cross-repo reuse contract: `{ schemaVersion,
> candidates: [{ port, open, socks5, processHint? }], exitIP? }` (shape it cleanly;
> additive-only changes). It MUST have NO provider/label field - make the
> no-provider-label honesty a STRUCTURAL property of the schema, and assert it in a
> test.
>
> Done = `netcage detect-proxy` probes + confirms SOCKS5 + presents evidence-only
> findings (never a provider label); `--json` emits the versioned, provider-field-
> free contract; the verb carries no proxy/preflight; tests cover the probe/
> handshake decisions, the no-label guarantee, and the JSON shape, using the
> in-process fixture (no real Tor, no host-global proxy assumption).
