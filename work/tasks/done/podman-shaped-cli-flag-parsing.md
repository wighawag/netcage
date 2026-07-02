---
title: podman-shaped CLI flag parsing, gated network flags, and NETCAGE_PROXY env
slug: podman-shaped-cli-flag-parsing
prd: jailed-interactive-repo-run
blockedBy: []
covers: [6, 7, 8, 9]
---

## What to build

Reshape `netcage run`'s CLI so it uses `podman run`'s GRAMMAR AND flag spellings (an agent already knows them), accepts only a CURATED allow-list of container flags, REJECTS loudly any flag that would breach the jail, and can take the proxy from a `NETCAGE_PROXY` env var so an agent's command line carries nothing netcage-specific.

**This task OWNS the CLI-grammar switch (the pivotal decision of the whole slice).** Move `netcage run` from the current netcage-specific grammar to podman-native POSITIONAL grammar:

- **Current (to be REMOVED):** `netcage run --image <img> [--proxy ...] [-v ...] -- <tool argv>` (image is the `--image` flag; the tool argv is everything after a standalone `--`).
- **New (podman-native):** `netcage run [flags] <image> [<cmd> <args...>]` (image is the first POSITIONAL argument; the tool command + args are the remaining positionals, exactly like `podman run [flags] IMAGE [CMD...]`). There is no `--image` flag and no `--` separator; flags precede the image, positionals follow it, mirroring podman/docker so an agent's `podman run` knowledge transfers verbatim. (Retaining `--` as an OPTIONAL explicit end-of-flags marker before the image is a builder's-discretion nicety, not required; `--image` is gone.)

This grammar change is DELIBERATE and load-bearing (PRD stories 1/5/6/10 all show positional `<image> <cmd>`), and it is the seam the `default-dev-image-and-repo-mount` task builds its positional-image-override and repo-mount defaulting on.

End-to-end thin path (parse positional image+argv + flags -> validated config/argv -> fail-loud on breach or missing proxy):

- **Allow-list, passed through verbatim to the tool container:** `-i`, `-t`, `-it` (and `-ti`), `-v`/`--volume` (already parsed today), `-w`/`--workdir`, `-e`/`--env`, `-u`/`--user`, `--entrypoint`. Parse both the `--flag value` and `--flag=value` forms, mirroring the existing `-v`/`--volume`/`--volume=`/`-v=` handling.
- **Deny-list, REJECTED with a clear reason naming the flag and WHY it breaches the jail:** `--network`, `-p`/`--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`, `--name`, `--rm`. netcage OWNS these (it sets `--network container:<sidecar>`, run-attributable `--name`, `--rm`, the in-netns DNS forwarder), so honouring a user/agent-supplied one would either collide or open a leak path. The error message is part of the agent-facing interface: it must name the flag and say netcage owns the network/isolation to keep the jail leak-proof (a self-correcting nudge).
- **Unknown/unlisted flags: reject by default** (fail-closed on the CLI), so an unaudited podman flag cannot silently ride through into the tool container. (Note: the current `Parse` ALREADY rejects unknown flags in its `default:` case with `unknown flag or argument %q`; this task RESHAPES that into the curated allow-list + explanatory deny-list, it is not greenfield. A positional that appears where the image/argv is expected is NOT an unknown flag, it is the image or a tool arg.)
- **Proxy from `--proxy` OR `NETCAGE_PROXY` env, precedence flag > env > refuse.** Both paths go through the EXISTING socks5h-enforcing parse (the one that already rejects `socks5://` as a DNS leak); the env path is NOT a laxer path. Neither set => refuse to run with a clear message (extends the existing startup fail-closed invariant to the env case). Never fall back to an unjailed/direct run.
- The `-i`/`-t` interactivity flags are PARSED and recorded on the parsed command here (a boolean the jail run-mode consumes); actually wiring an interactive TTY through the jail is the separate `jailed-interactive-tty` task. This task only needs to parse them and thread the values into the config the jail consumes.
- **Own the deletion sweep of the old grammar.** Removing `--image`/`--` is a behaviour change with a concrete blast radius: update the `usage` banner in `main.go`, the existing `internal/cli` tests that drive `--image ... -- <cmd>`, and any `runRun` mapping in `main.go` that assumed the old shape. Do NOT leave stale `--image` examples/tests. (The PARENT prd `netcage.md` story 1 documents the old `--image nuclei -- nuclei -u ...` shape; note in your done record that the documented command shape changed, so a later doc pass can reconcile the parent prd/README. Reconciling the parent prd's prose is out of THIS task's scope, but the drift must be recorded, not silently left.)

This is a pure parsing + validation change at the CLI boundary; it does NOT stand up the jail, so it is unit-testable with no podman.

## Acceptance criteria

- [ ] Tests written FIRST: parsing `run -it -v a:b -w /work -e K=V -u 1000 --proxy socks5h://127.0.0.1:9050 <image> <cmd...>` yields the right proxy, interactive flags, mounts, workdir, env, user, POSITIONAL image, and tool argv (the remaining positionals after the image), with NO `--image` flag and NO `--` separator required.
- [ ] The old grammar is GONE: `--image` is no longer accepted, the `usage` banner reflects the positional shape, and the existing `cli` tests are updated to the new grammar (no stale `--image ... -- <cmd>` invocations remain in tests or the usage string).
- [ ] Each jail-breaching flag (`--network host`, `-p 8080:8080`, `--dns 1.1.1.1`, `--privileged`, `--cap-add NET_ADMIN`, `--device ...`, `--name x`, `--rm`) is REJECTED with an error naming the flag and why it breaches the jail (a distinct, testable message), not silently accepted or forwarded.
- [ ] An unknown/unlisted flag is rejected by default (not silently forwarded).
- [ ] `NETCAGE_PROXY` is honoured when `--proxy` is absent; `--proxy` wins when both are set; a malformed or `socks5://` value from the env is rejected by the SAME validation as the flag; NEITHER set makes the run refuse to start with a clear fail-closed message (never an unjailed run).
- [ ] Tests cover the new behaviour (mirror the repo's existing `cli` unit-test style); all cases here are pure-logic and need NO podman.

## Blocked by

- None. Can start immediately.

## Prompt

> Goal: switch `netcage run` to podman-native POSITIONAL grammar (`run [flags] <image> [<cmd>...]`, no `--image`, no `--`), accept a curated allow-list of `podman run` flags, reject jail-breaching flags loudly, and read the proxy from `--proxy` or the `NETCAGE_PROXY` env (flag > env > fail-closed-refuse). Read `CONTEXT.md` (jail, forced egress, fail-closed, socks5h), the `internal/cli` package (the existing `Parse`, `ProxyConfig`, `ParseProxy` that ENFORCES socks5h and rejects `socks5://`, the `Command` type with `Mounts` + `ProxyOnHostLoopback`, and `Preflight`), `main.go`'s `runRun` + the `usage` banner (how the parsed command maps to `jail.Config`), and the prd `jailed-interactive-repo-run` (Solution + the podman-native grammar it shows in stories 1/5/6/10).
>
> FIRST, check against current reality: confirm `internal/cli.Parse` currently uses the OLD grammar (`--image` flag + `splitDoubleDash` for the post-`--` tool argv) and that `ParseProxy` is the single socks5h-enforcing entry both proxy paths must reuse. THIS task deliberately REPLACES that grammar with positional podman-native parsing (image = first positional, tool argv = the rest); if the CLI shape has ALREADY moved since this task was written, reconcile rather than building on a stale assumption.
>
> Write the tests FIRST (testFirst is ON): positional `run -it -v a:b -w /work -e K=V -u 1000 --proxy socks5h://... <image> <cmd...>` parses into image + argv + flags with NO `--image`/`--`; each deny-list flag is rejected with a message naming it and why; an unknown flag is rejected; `NETCAGE_PROXY` precedence (flag > env > refuse) and the malformed/`socks5://` env cases. Then wire the parser: positional image+argv, the allow-list (both `--flag value` and `--flag=value` forms), the deny-list with explanatory rejections, reject-unknown-by-default, and the env-proxy resolution reusing `ParseProxy`. Record the interactive `-i`/`-t` booleans on the parsed command for the jail run-mode task to consume (do NOT wire the TTY here). OWN the deletion sweep: update the `main.go` `usage` banner and the existing `cli` tests to the new grammar; leave no `--image`/`--` remnants; record in the done note that the documented command shape changed (parent prd `netcage.md`/README reconcile is a separate doc pass).
>
> "Done" means an agent can drive `netcage run` with pure `podman run` grammar (positional image+cmd, podman-shaped flags), a jail-breaching flag is refused with a self-explanatory error, the proxy can come from the env, a missing/invalid proxy refuses to run (never leaks), and the old `--image`/`--` surface is gone (usage + tests updated). Keep the verify gate green. RECORD non-obvious in-scope decisions (the exact positional grammar, whether `--` is kept as an optional end-of-flags marker, the final allow/deny lists, the reject-unknown default, the env-var name) per the task-template guidance (a `## Decisions` note, or an ADR if the grammar switch meets the ADR gate, which it plausibly does as a deliberate deviation from the parent prd's documented shape).
