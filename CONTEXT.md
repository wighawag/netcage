# CONTEXT — netcage domain language

The domain glossary for `netcage`. Agents and skills use THIS vocabulary when naming modules, tests, and discussing the system. Architectural rationale lives in `docs/adr/` (decisions); product framing lives in `work/prds/`.

## What netcage is

netcage is a Go CLI that runs any containerized tool with all its TCP and DNS egress forced through a SOCKS5h proxy, fail-closed, so recon/scan tools cannot leak the real IP or DNS. It wraps an existing image + command + a socks5h URL, and ships a verify leak-test that proves no traffic escapes the proxy.

## Core domain terms

- **jail** — the confined execution environment for one wrapped tool: a network namespace whose only route to the outside is the redirector, plus the fail-closed firewall rules. "netcage" = it jails a tool's network.
- **forced egress** — the design guarantee that EVERY packet the wrapped tool emits (TCP and DNS) is pushed into the proxy by the network layer, not by the tool's own proxy awareness. The opposite of app-level `ALL_PROXY`/`HTTP_PROXY` (which raw sockets and DNS ignore, and which therefore leaks). Forced egress is leak-proof by construction.
- **fail-closed** — if the proxy is unreachable, traffic does NOT fall back to the host network; it is dropped. Proxy-down means the tool fails, never that it leaks. The inverse (fail-open) is the bug this whole project exists to prevent.
- **socks5h** — SOCKS5 with remote (proxy-side) DNS resolution: the `h` means hostnames are resolved BY the proxy, so DNS queries never hit the host resolver. netcage's egress backend; plain `socks5://` (local DNS) is a leak and is not the target.
- **redirector** — the component that takes the jail's traffic and dials it out over socks5h (candidate: a vendored `tun2socks`/gVisor sidecar, or `redsocks`+nft). It is the jail's only route out. Its choice is an open decision (see the prd / a future ADR).
- **reachback** — how the jailed container reaches a SOCKS5h proxy listening on the HOST's loopback (the common case, e.g. a local Tor/ssh `-D`). The single most leak-prone seam under rootless Podman; the exact mechanism (slirp4netns `allow_host_loopback` vs pasta) is an open decision.
- **verify (leak-test)** — netcage's built-in proof, and the project's top acceptance seam: run a probe through the same jail and assert (1) the observed exit IP is the PROXY's, (2) a unique hostname resolves through the proxy's resolver not the host's, and (3) with the proxy killed, the probe FAILS CLOSED (no egress). Run during dev/CI, not per-use.
- **wrapped tool** — the arbitrary containerized command netcage confines (e.g. `nuclei`, `nikto`, `ffuf`, or any image). v1 wraps an EXISTING image + command; it does not build images.
- **kept run / ephemeral run** — the two tool-container lifecycles (ADR-0009). A KEPT run (a plain `netcage run`, no `--rm`) LEAVES the stopped tool container and its stopped sidecar behind, inspectable/restartable like `podman run` and fail-closed via the baked firewall (ADR-0008). An EPHEMERAL run (the netcage-owned `--rm` flag, and every internal one-shot: verify probes, reachback/direct probes, declarative runs) removes BOTH on exit, no residue. "Sidecar gone, tool kept" is unreachable (the `--network container:` edge blocks it), so the only end-states are both-kept and both-gone. `--rm` is a NETCAGE-owned flag netcage interprets, never a raw podman `--rm` smuggled through; `--name` stays owned by netcage.
- **netcage-managed label** — `netcage.managed=true` (+ `netcage.role=tool|sidecar` + `netcage.run-id=<id>`), stamped on the tool and sidecar at create time (ADR-0009). The robust discriminator (a label, not the `netcage-run-<id>-*` name convention) that makes a left-behind pair identifiable at rest; the pass-through verbs and `netcage start` scope on it.
- **promptGuidance** — the per-repo NUDGE namespace in `.dorfl.json` whose members (currently just `testFirst`) strengthen the wording in the worker's in-band prompt. NOT a gate: the `verify` step is still the only acceptance bar. Omitted ⇒ off; absence is the default. Here it is ON (the project's acceptance bar is itself a leak-test, so test-first is the natural default).
- **work/ contract** — the on-disk system this repo uses, defined by the reference docs in **`work/protocol/`** (copied here by `setup`): `WORK-CONTRACT.md` (the contract), `CLAIM-PROTOCOL.md`, `REVIEW-PROTOCOL.md`, `task-template.md`, `prd-template.md`, `ADR-FORMAT.md`. Three REGIME umbrellas — `notes/` (capture buckets), `tasks/` (the build board), `prds/` (the prd lifecycle) — plus top-level `questions/` and `protocol/`. One markdown file per item, status = the folder it lives in (never a field). Capture buckets: `notes/ideas/` (proposed), `notes/observations/` (spotted, unverified, append-only), `notes/findings/` (verified external/domain ground truth, each with a `source:`). ADRs (`docs/adr/`, format in `work/protocol/ADR-FORMAT.md`) record what WE decided and why.

## Conventions

Standing per-change rules agents must follow in this repo.

<!-- No standing per-change rule recorded yet (no changeset/CHANGELOG/news-fragment convention). Add yours here, or delete this section. For enforcement, wire your own check into the `.dorfl.json` `verify` gate. -->

## Skills this repo uses

- Required: `setup` (onboarding/migration), `to-prd`, `to-task`.
- Recommended: `review`, `grilling`.
