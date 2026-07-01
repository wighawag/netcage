---
title: podman-shaped CLI flag parsing, gated network flags, and TOOLJAIL_PROXY env
slug: podman-shaped-cli-flag-parsing
prd: jailed-interactive-repo-run
blockedBy: []
covers: [6, 7, 8, 9]
---

## What to build

Reshape `tooljail run`'s CLI so it uses `podman run`'s flag spellings (an agent already knows them), accepts only a CURATED allow-list of container flags, REJECTS loudly any flag that would breach the jail, and can take the proxy from a `TOOLJAIL_PROXY` env var so an agent's command line carries nothing tooljail-specific.

End-to-end thin path (parse -> validated config/argv -> fail-loud on breach or missing proxy):

- **Allow-list, passed through verbatim to the tool container:** `-i`, `-t`, `-it` (and `-ti`), `-v`/`--volume` (already parsed today), `-w`/`--workdir`, `-e`/`--env`, `-u`/`--user`, `--entrypoint`. Parse both the `--flag value` and `--flag=value` forms, mirroring the existing `-v`/`--volume`/`--volume=`/`-v=` handling.
- **Deny-list, REJECTED with a clear reason naming the flag and WHY it breaches the jail:** `--network`, `-p`/`--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`, `--name`, `--rm`. tooljail OWNS these (it sets `--network container:<sidecar>`, run-attributable `--name`, `--rm`, the in-netns DNS forwarder), so honouring a user/agent-supplied one would either collide or open a leak path. The error message is part of the agent-facing interface: it must name the flag and say tooljail owns the network/isolation to keep the jail leak-proof (a self-correcting nudge).
- **Unknown/unlisted flags: reject by default** (fail-closed on the CLI), so an unaudited podman flag cannot silently ride through into the tool container.
- **Proxy from `--proxy` OR `TOOLJAIL_PROXY` env, precedence flag > env > refuse.** Both paths go through the EXISTING socks5h-enforcing parse (the one that already rejects `socks5://` as a DNS leak); the env path is NOT a laxer path. Neither set => refuse to run with a clear message (extends the existing startup fail-closed invariant to the env case). Never fall back to an unjailed/direct run.
- The `-i`/`-t` interactivity flags are PARSED and recorded on the parsed command here (a boolean the jail run-mode consumes); actually wiring an interactive TTY through the jail is the separate `jailed-interactive-tty` task. This task only needs to parse them and thread the values into the config the jail consumes.

This is a pure parsing + validation change at the CLI boundary; it does NOT stand up the jail, so it is unit-testable with no podman.

## Acceptance criteria

- [ ] Tests written FIRST: parsing `run -it -v a:b -w /work -e K=V -u 1000 --proxy socks5h://127.0.0.1:9050 <image> <cmd...>` yields the right proxy, interactive flags, mounts, workdir, env, user, image, and tool argv.
- [ ] Each jail-breaching flag (`--network host`, `-p 8080:8080`, `--dns 1.1.1.1`, `--privileged`, `--cap-add NET_ADMIN`, `--device ...`, `--name x`, `--rm`) is REJECTED with an error naming the flag and why it breaches the jail (a distinct, testable message), not silently accepted or forwarded.
- [ ] An unknown/unlisted flag is rejected by default (not silently forwarded).
- [ ] `TOOLJAIL_PROXY` is honoured when `--proxy` is absent; `--proxy` wins when both are set; a malformed or `socks5://` value from the env is rejected by the SAME validation as the flag; NEITHER set makes the run refuse to start with a clear fail-closed message (never an unjailed run).
- [ ] Tests cover the new behaviour (mirror the repo's existing `cli` unit-test style); all cases here are pure-logic and need NO podman.

## Blocked by

- None. Can start immediately.

## Prompt

> Goal: make `tooljail run` accept `podman run`-shaped flags (curated allow-list), reject jail-breaching flags loudly, and read the proxy from `--proxy` or the `TOOLJAIL_PROXY` env (flag > env > fail-closed-refuse). Read `CONTEXT.md` (jail, forced egress, fail-closed, socks5h), the `internal/cli` package (the existing `Parse`, `ProxyConfig`, `ParseProxy` that ENFORCES socks5h and rejects `socks5://`, the `Command` type with `Mounts` + `ProxyOnHostLoopback`, and `Preflight`), `main.go`'s `runRun` (how the parsed command maps to `jail.Config`), and the prd `jailed-interactive-repo-run` (Solution + Implementation Decisions).
>
> FIRST, check against current reality: confirm `internal/cli.Parse` currently accepts `--proxy`/`--image`/`-v`/`--volume` and the post-`--` tool argv, and that `ParseProxy` is the single socks5h-enforcing entry both paths must reuse. If the CLI shape has moved since this task was written, reconcile rather than building on the stale assumption.
>
> Write the tests FIRST (testFirst is ON): the allow-list flags parse into the command; each deny-list flag is rejected with a message naming it and why; an unknown flag is rejected; `TOOLJAIL_PROXY` precedence (flag > env > refuse) and the malformed/`socks5://` env cases. Then wire the parser: extend the allow-list (both `--flag value` and `--flag=value` forms), add the deny-list with explanatory rejections, reject-unknown-by-default, and the env-proxy resolution reusing `ParseProxy`. Record the interactive `-i`/`-t` booleans on the parsed command for the jail run-mode task to consume (do NOT wire the TTY here).
>
> "Done" means an agent can drive `tooljail run` with podman-shaped flags, a jail-breaching flag is refused with a self-explanatory error, the proxy can come from the env, and a missing/invalid proxy refuses to run (never leaks). Keep the verify gate green. RECORD non-obvious in-scope decisions (the exact final allow/deny lists, the reject-unknown default, the env-var name) per the task-template guidance (a `## Decisions` note, or an ADR if a choice meets the ADR gate).
