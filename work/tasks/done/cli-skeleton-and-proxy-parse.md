---
title: CLI skeleton — run/verify commands, socks5h parse, fail-loud on unreachable proxy
slug: cli-skeleton-and-proxy-parse
prd: netcage
blockedBy: []
covers: [3, 10]
---

## What to build

The `netcage` CLI surface for `run` and `verify`, plus the proxy-URL contract and the startup fail-loud path — all WITHOUT the jail itself yet. This is the thin CLI-to-error tracer: parse, validate, and fail correctly.

End-to-end thin path:

- `netcage run --proxy socks5h://[user:pass@]host:port --image <image> -- <tool> <args...>` and `netcage verify --proxy socks5h://...` parse into a typed config (proxy URL incl. optional user:pass auth, image, and the post-`--` tool argv).
- **socks5h is required**: a plain `socks5://` (local DNS) URL is REJECTED with a clear message — it is a DNS leak by definition and is not the target (CONTEXT.md).
- **Fail-loud, fail-closed startup**: when the proxy is unreachable at startup, the command exits NON-ZERO with a clear message (story 10) — never a silent no-op, never a silent leak. (At this stage "unreachable" can be a direct reachability check to the proxy address; the jailed path comes later.)

No sidecar/netns/nft here — this task is pure Go and writes nothing to the system, so it is parallel-safe with the spikes and the fixture.

## Acceptance criteria

- [ ] Tests are written FIRST and RED before the wiring: parse of a full `socks5h://user:pass@host:port` + `--image` + post-`--` argv yields the expected typed config; a `socks5://` URL is REJECTED; an unreachable proxy makes the command exit non-zero with the documented message.
- [ ] `run` and `verify` subcommands exist and parse their flags; unknown/missing required flags fail loudly.
- [ ] Plain `socks5://` (and any non-socks5h scheme) is rejected with a leak-explaining message.
- [ ] Unreachable-proxy-at-startup ⇒ non-zero exit + clear message (no silent no-op).
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- None — can start immediately. Pure Go; parallel-safe with the spikes and fixture.

## Prompt

> Goal: build the `netcage run` / `netcage verify` CLI surface, the socks5h proxy-URL contract, and the fail-loud-on-unreachable-proxy startup path — WITHOUT the jail yet. Read `CONTEXT.md` (domain terms: socks5h, fail-closed, forced egress) and the prd Solution section (the two command shapes).
>
> FIRST, check against current reality: confirm the command shapes in the prd Solution section and that socks5h (not socks5) is the required scheme (ADR-0001/0003 context).
>
> Write tests FIRST (testFirst is ON): parse a full `socks5h://user:pass@host:port --image X -- tool args` into typed config; assert `socks5://` is rejected as a leak; assert an unreachable proxy exits non-zero with a clear message. Then implement the minimum CLI to pass.
>
> Pure Go, NO system mutation (no podman/netns/nft) — that lands in the `jail-run-forced-egress` task, which builds ON this skeleton. Keep the proxy config type and the unreachable-check reusable by the jail and verify tasks. "Done" means the CLI parses both commands, enforces socks5h, and fails loud + non-zero when the proxy is unreachable, all under green tests. RECORD any non-obvious in-scope decision (e.g. the exact exit code chosen for unreachable-proxy) per the task-template guidance.
