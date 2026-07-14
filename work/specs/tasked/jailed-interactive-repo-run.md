---
title: Jailed interactive run (podman-shaped CLI so an agent can set up and run a repo's tool without leaking)
slug: jailed-interactive-repo-run
humanOnly: true
taskedAfter: []
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked — they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

I found a tool I want to try, but it is a REPO, not a prebuilt container image, and I do not fully trust it. To use it I have to build it and install its dependencies first (clone sub-deps, `pip install`, `npm install`, `go build`, `cargo build`), and then run it against a target. I want to do all of this WITHOUT leaking my real IP or DNS.

Two things are missing today (this Problem Statement is the launch snapshot at authoring time; the CLI grammar it references, `--image X -- tool args`, has since been replaced by the podman-native positional grammar this prd's tasks delivered, `run [flags] <image> [<cmd>...]`):

1. **There is no jailed interactive shell.** netcage (at authoring time) runs a tool NON-interactively: it streams output but does not attach a TTY or stdin, so I cannot "shell into the jail" and set the repo up by hand. For an untrusted repo I do not want to run its build scripts naked on my host (a malicious `postinstall`/`setup.py` runs with my host IP), so the setup itself should happen jailed. The only way to do that interactively is a jailed shell, which does not exist.

2. **The CLI is netcage-specific, so an agent has to learn it.** An LLM agent already knows `podman run` / `docker run` cold. If netcage's interface mirrors that, an agent can drive it with zero netcage-specific knowledge. Today it invents its own surface (`--image`, and a required `--proxy`), so the agent must be taught netcage.

Note the deliberate non-goal that dissolves most of the surface: a repo the user TRUSTS needs nothing new. They set it up on the host themselves (`cd repo && pip install`) and then `netcage run` the tool. This prd is for the UNTRUSTED case (set up jailed) and for making the whole thing agent-native.

## Solution

Make `netcage run` a leak-proof, jailing wrapper whose CLI is shaped like `podman run`, and give it an interactive mode so a human or an agent can shell into the jail, set the repo up by hand (or via a one-shot command), and run its tool, all with egress forced through the SOCKS5h proxy, fail-closed, exactly as a wrapped tool is today.

From the user's perspective:

- **Interactive (manual setup, untrusted repo):**
  ```
  netcage run -it -v ~/dev/found-tool:/work -w /work <dev-image> bash
  ```
  drops me into a jailed `bash` in the repo folder. Everything I type (clone, `pip install`, build, then run the tool) has its egress forced through the proxy, fail-closed. Writes land on my host folder (the `-v` mount), so my setup persists across sessions.

- **Declarative (one-shot / agent-driven setup + run):**
  ```
  netcage run -v ~/dev/found-tool:/work -w /work <dev-image> \
    sh -c "pip install -e . && found-tool --target https://authorized-target"
  ```
  setup and run in one jailed invocation. This is agent-friendly: an agent iterates the setup command until the tool runs. (This shape already works today; the prd's value here is the podman-shaped flags and the default image, not new plumbing for this case.)

- **Agent-native, no netcage-specific knowledge:** the proxy can come from the `NETCAGE_PROXY` env var instead of a flag, so the agent's command line is PURE `podman run` vocabulary (`-it -v -w -e <image> <cmd>`) with nothing netcage-specific on it. The jail, the leak guarantee, and teardown are unchanged and still proven by `verify`.

The leak guarantee is NOT weakened by any of this. Interactive and declarative runs ride the EXACT same jail (sidecar + shared netns + nft + DNS forwarder + fail-closed + teardown) that `verify` already proves leak-proof; interactivity changes only how stdin/stdout/TTY are wired, not the network jail. Setup is jailed-by-default purely by happening inside the jailed container; there is no host-network escape hatch (the trusted case is served by the user setting up on the host themselves, outside netcage).

## User Stories

1. As an operator with an untrusted repo, I want `netcage run -it -v <repo>:/work -w /work <image> bash` to drop me into an interactive jailed shell in the repo, so that I can build the tool and install its deps by hand with my IP and DNS never leaking.
2. As an operator, I want my keystrokes, Ctrl-C, and the tool's TTY behaviour (prompts, progress bars, pagers) to work in that jailed shell as they would in a normal `podman run -it`, so that interactive setup is actually usable.
3. As an operator, I want writes in the jailed shell to land on my host repo folder (via `-v`), so that the deps and build artifacts I install persist across shell sessions and I do not reinstall every time.
4. As an operator with a repo I DO trust, I want to keep setting it up on the host myself and just `netcage run` the tool, so that netcage adds nothing I do not need (this is the explicit non-goal that keeps the surface small).
5. As an agent (or a human using an agent) setting up a tool, I want to drive setup declaratively with `netcage run -v <repo>:/work -w /work <image> sh -c "<setup> && <tool>"`, so that I can iterate the setup command non-interactively until the tool runs, jailed throughout.
6. As an agent, I want netcage's CLI to use `podman run`'s flag spellings (`-i`/`-t`/`-it`, `-v`/`--volume`, `-w`/`--workdir`, `-e`/`--env`, `-u`/`--user`, `--entrypoint`), so that I can drive it using knowledge I already have, with no netcage-specific onboarding.
7. As a security-conscious operator, I want netcage to REJECT (loudly, with a reason) any podman flag that would breach the jail (`--network`, `-p`/`--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`, and the names/lifecycle flags netcage owns like `--name`/`--rm`), so that an agent reflexively reaching for `--network host` gets a self-correcting error instead of a silent leak.
8. As an agent, I want to supply the proxy via `NETCAGE_PROXY=socks5h://...` in the environment, so that my netcage command line carries nothing netcage-specific and is indistinguishable from a `podman run` I already know how to write.
9. As a security-conscious operator, I want the run to FAIL CLOSED and refuse to start when NEITHER `--proxy` nor `NETCAGE_PROXY` is set (or when either is malformed / not `socks5h`), so that a missing proxy can never silently become an unjailed run.
10. As an operator, I want a sensible DEFAULT dev image (broad, multi-language, pinned) when I do not pass one, so that `netcage run -it -v <repo>:/work -w /work bash` is useful out of the box; and I want an explicit positional image to override it.
11. As an operator, I want the interactive/declarative modes to leave NO residue (container, sidecar, netns, nft, DNS forwarder all torn down on exit or Ctrl-C), exactly as the non-interactive run does today, so that an interactive session is as clean as a wrapped-tool run.
12. As a CI maintainer, I want `verify` to still prove the leak assertions for the jail that interactive/declarative runs use, so that the added modes cannot regress the leak guarantee (an interactive run must stand up the identical jail topology, same nft, same forced egress).

### Autonomy notes

- **`humanOnly: true` (prd-level, DECIDED):** set because this feature is being driven deliberately by a human (the netcage author) and touches the security-critical CLI boundary (which podman flags are safe to pass through vs must be rejected). A human should drive the TASKING so the accept/reject flag policy is reviewed, not auto-decomposed. This does NOT propagate to the emitted tasks' gates; the tasker sets each task's `humanOnly` from its own build-nature (most of these are ordinary agent-buildable tasks).
- **`needsAnswers`:** NOT set. The spec is decided (pragmatic podman-shaped subset + gated network flags; no `shell` subcommand; `run -it` canonical; env-provided proxy with fail-closed precedence; jailed-by-default setup with no host escape hatch; pinned default dev image with override). The two remaining threads (the exact arg grammar around the tool-argv boundary, and how interactive TTY mode interacts with the streaming/capture Runner seam) are tasking-time design choices with a chosen direction, not spec ambiguities that block decomposition.

> Tasked 2026-07-01 (human-driven path). The launch-time Implementation Decisions and Testing Decisions have been relocated into the emitted tasks (`podman-shaped-cli-flag-parsing`, `jailed-interactive-tty`, `default-dev-image-and-repo-mount` in `work/tasks/backlog/`), which now own what-to-build and how-to-test. No decision here met the ADR gate at tasking time (the flag allow/deny policy and the default-image pin are recorded in their tasks, with the base-image pin flagged as possibly-ADR-worthy when its concrete image is chosen). The durable framing below (Problem / Solution / User Stories / Out of Scope) remains.

## Out of Scope

- **Nix / auto-build-from-repo (the larger ambition):** generating a minimal environment (a Nix flake, host-dep reuse) to run an arbitrary repo automatically. Stays deferred; it lives as its own incubating idea in `work/notes/ideas/minimal-setup-image-from-repo.md`. THIS prd is the lighter, distinct "set the repo up yourself, jailed, via an interactive/declarative shell" slice: it does not construct the environment, it confines it.
- **Full `podman run` flag compatibility.** Deliberately a curated allow-list + gated deny-list, not every podman flag (see Implementation Decisions). New podman flags are not automatically supported.
- **A bespoke/owned default dev image (`Containerfile`).** This slice pins a broad EXISTING image; building and maintaining our own is a later decision.
- **A host-network setup escape hatch.** Considered and rejected: the trusted case is served by the user setting up on the host outside netcage (`cd repo && pip install`), so there is no `--setup-on-host` mode to build. Setup inside netcage is always jailed.
- **Non-Podman runtimes, in-process tun2socks, UDP-associate:** unchanged from the parent netcage prd's out-of-scope; not touched here.

## Further Notes

- Motivating trail: exploring running the `web-app-scanner` (webscan) tools through netcage surfaced that (a) stateful tools (nuclei needs templates) want persisted setup, and (b) an untrusted tool's SETUP egress is itself worth jailing, not just its scan egress. That is what this prd captures: jail the setup, not only the run.
- This builds directly on the shipped core (forced-egress jail, teardown invariant, run-cli-wiring) and on `distinguish-podman-failure-from-tool-exit` + `stream-tool-output-live` (the `Runner` seam that interactive mode extends). The interactive TTY task should be `blockedBy` those seam tasks once tasked.
- Relationship to the leak-test: the added modes are IN-scope for `verify`'s guarantee precisely because they reuse the same jail; the prd requires a test proving topological identity so this stays true.
