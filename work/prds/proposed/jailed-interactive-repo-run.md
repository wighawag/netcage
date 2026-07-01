---
title: Jailed interactive run (podman-shaped CLI so an agent can set up and run a repo's tool without leaking)
slug: jailed-interactive-repo-run
humanOnly: true
taskedAfter: []
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked — they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

I found a tool I want to try, but it is a REPO, not a prebuilt container image, and I do not fully trust it. To use it I have to build it and install its dependencies first (clone sub-deps, `pip install`, `npm install`, `go build`, `cargo build`), and then run it against a target. I want to do all of this WITHOUT leaking my real IP or DNS.

Two things are missing today:

1. **There is no jailed interactive shell.** tooljail today runs a tool NON-interactively (`tooljail run --image X -- tool args`): it streams output but does not attach a TTY or stdin, so I cannot "shell into the jail" and set the repo up by hand. For an untrusted repo I do not want to run its build scripts naked on my host (a malicious `postinstall`/`setup.py` runs with my host IP), so the setup itself should happen jailed. The only way to do that interactively is a jailed shell, which does not exist.

2. **The CLI is tooljail-specific, so an agent has to learn it.** An LLM agent already knows `podman run` / `docker run` cold. If tooljail's interface mirrors that, an agent can drive it with zero tooljail-specific knowledge. Today it invents its own surface (`--image`, and a required `--proxy`), so the agent must be taught tooljail.

Note the deliberate non-goal that dissolves most of the surface: a repo the user TRUSTS needs nothing new. They set it up on the host themselves (`cd repo && pip install`) and then `tooljail run` the tool. This prd is for the UNTRUSTED case (set up jailed) and for making the whole thing agent-native.

## Solution

Make `tooljail run` a leak-proof, jailing wrapper whose CLI is shaped like `podman run`, and give it an interactive mode so a human or an agent can shell into the jail, set the repo up by hand (or via a one-shot command), and run its tool, all with egress forced through the SOCKS5h proxy, fail-closed, exactly as a wrapped tool is today.

From the user's perspective:

- **Interactive (manual setup, untrusted repo):**
  ```
  tooljail run -it -v ~/dev/found-tool:/work -w /work <dev-image> bash
  ```
  drops me into a jailed `bash` in the repo folder. Everything I type (clone, `pip install`, build, then run the tool) has its egress forced through the proxy, fail-closed. Writes land on my host folder (the `-v` mount), so my setup persists across sessions.

- **Declarative (one-shot / agent-driven setup + run):**
  ```
  tooljail run -v ~/dev/found-tool:/work -w /work <dev-image> \
    sh -c "pip install -e . && found-tool --target https://authorized-target"
  ```
  setup and run in one jailed invocation. This is agent-friendly: an agent iterates the setup command until the tool runs. (This shape already works today; the prd's value here is the podman-shaped flags and the default image, not new plumbing for this case.)

- **Agent-native, no tooljail-specific knowledge:** the proxy can come from the `TOOLJAIL_PROXY` env var instead of a flag, so the agent's command line is PURE `podman run` vocabulary (`-it -v -w -e <image> <cmd>`) with nothing tooljail-specific on it. The jail, the leak guarantee, and teardown are unchanged and still proven by `verify`.

The leak guarantee is NOT weakened by any of this. Interactive and declarative runs ride the EXACT same jail (sidecar + shared netns + nft + DNS forwarder + fail-closed + teardown) that `verify` already proves leak-proof; interactivity changes only how stdin/stdout/TTY are wired, not the network jail. Setup is jailed-by-default purely by happening inside the jailed container; there is no host-network escape hatch (the trusted case is served by the user setting up on the host themselves, outside tooljail).

## User Stories

1. As an operator with an untrusted repo, I want `tooljail run -it -v <repo>:/work -w /work <image> bash` to drop me into an interactive jailed shell in the repo, so that I can build the tool and install its deps by hand with my IP and DNS never leaking.
2. As an operator, I want my keystrokes, Ctrl-C, and the tool's TTY behaviour (prompts, progress bars, pagers) to work in that jailed shell as they would in a normal `podman run -it`, so that interactive setup is actually usable.
3. As an operator, I want writes in the jailed shell to land on my host repo folder (via `-v`), so that the deps and build artifacts I install persist across shell sessions and I do not reinstall every time.
4. As an operator with a repo I DO trust, I want to keep setting it up on the host myself and just `tooljail run` the tool, so that tooljail adds nothing I do not need (this is the explicit non-goal that keeps the surface small).
5. As an agent (or a human using an agent) setting up a tool, I want to drive setup declaratively with `tooljail run -v <repo>:/work -w /work <image> sh -c "<setup> && <tool>"`, so that I can iterate the setup command non-interactively until the tool runs, jailed throughout.
6. As an agent, I want tooljail's CLI to use `podman run`'s flag spellings (`-i`/`-t`/`-it`, `-v`/`--volume`, `-w`/`--workdir`, `-e`/`--env`, `-u`/`--user`, `--entrypoint`), so that I can drive it using knowledge I already have, with no tooljail-specific onboarding.
7. As a security-conscious operator, I want tooljail to REJECT (loudly, with a reason) any podman flag that would breach the jail (`--network`, `-p`/`--publish`, `--dns`, `--privileged`, `--cap-add`, `--device`, and the names/lifecycle flags tooljail owns like `--name`/`--rm`), so that an agent reflexively reaching for `--network host` gets a self-correcting error instead of a silent leak.
8. As an agent, I want to supply the proxy via `TOOLJAIL_PROXY=socks5h://...` in the environment, so that my tooljail command line carries nothing tooljail-specific and is indistinguishable from a `podman run` I already know how to write.
9. As a security-conscious operator, I want the run to FAIL CLOSED and refuse to start when NEITHER `--proxy` nor `TOOLJAIL_PROXY` is set (or when either is malformed / not `socks5h`), so that a missing proxy can never silently become an unjailed run.
10. As an operator, I want a sensible DEFAULT dev image (broad, multi-language, pinned) when I do not pass one, so that `tooljail run -it -v <repo>:/work -w /work bash` is useful out of the box; and I want `--image`/positional image to override it.
11. As an operator, I want the interactive/declarative modes to leave NO residue (container, sidecar, netns, nft, DNS forwarder all torn down on exit or Ctrl-C), exactly as the non-interactive run does today, so that an interactive session is as clean as a wrapped-tool run.
12. As a CI maintainer, I want `verify` to still prove the leak assertions for the jail that interactive/declarative runs use, so that the added modes cannot regress the leak guarantee (an interactive run must stand up the identical jail topology, same nft, same forced egress).

### Autonomy notes

- **`humanOnly: true` (prd-level, DECIDED):** set because this feature is being driven deliberately by a human (the tooljail author) and touches the security-critical CLI boundary (which podman flags are safe to pass through vs must be rejected). A human should drive the TASKING so the accept/reject flag policy is reviewed, not auto-decomposed. This does NOT propagate to the emitted tasks' gates; the tasker sets each task's `humanOnly` from its own build-nature (most of these are ordinary agent-buildable tasks).
- **`needsAnswers`:** NOT set. The spec is decided (pragmatic podman-shaped subset + gated network flags; no `shell` subcommand; `run -it` canonical; env-provided proxy with fail-closed precedence; jailed-by-default setup with no host escape hatch; pinned default dev image with override). The two remaining threads (the exact arg grammar around the tool-argv boundary, and how interactive TTY mode interacts with the streaming/capture Runner seam) are TASKING-TIME design choices with a chosen direction recorded below, not spec ambiguities that block decomposition.

## Implementation Decisions

Decisions made at launch, to seed tasking (trimmed into tasks/ADRs at tasking-time):

- **Interface philosophy: pragmatic Fork 1 (podman-shaped, CURATED + GATED), not full `podman run` compatibility.** Adopt podman's flag SPELLINGS for the container flags that make sense for a jailed tool so agent knowledge transfers, but do NOT claim or attempt total compatibility. This is a curated allow-list plus an explicit reject-list, because full pass-through would inherit podman's entire flag surface as a security-audit obligation that grows over time.
  - **Pass through verbatim (allow-list, seed):** `-i`, `-t`, `-it`, `-v`/`--volume`, `-w`/`--workdir`, `-e`/`--env`, `-u`/`--user`, `--entrypoint`. (The exact final allow-list is a tasking-time decision; each added flag must be argued leak-safe.)
  - **Own and REJECT loudly (deny-list, seed):** `--network` (tooljail owns it via `--network container:<sidecar>`), `-p`/`--publish`, `--dns` (DNS is the in-netns forwarder), `--privileged`, `--cap-add`, `--device`, `--name`/`--rm` (tooljail sets run-attributable names + `--rm`). Each rejection must name WHY it would breach the jail: the error message is part of the agent-facing interface (a self-correcting nudge), not an afterthought.
  - **Unknown/unlisted flags:** default to REJECT (fail-closed on the CLI too), not silently forward, so an unaudited podman flag cannot ride through. (Tasking-time decision; recorded direction is reject-by-default.)
- **No `shell` subcommand.** `tooljail run -it <image> bash` is the single canonical interactive form. A `shell` sugar was considered and rejected: under a podman-shaped CLI the agent-native form is `run -it`, so inventing `shell` adds surface an agent would not reach for. (May be revisited later as a pure documented alias; not in this slice.)
- **Proxy from flag OR `TOOLJAIL_PROXY` env; precedence flag > env > fail-closed-refuse.** Both paths go through the EXISTING `ParseProxy` validation (which already rejects `socks5://` as a DNS leak and requires `socks5h`), so the env path is not a laxer path. Neither set ⇒ refuse to run with a clear message (extends the existing startup fail-closed invariant, story 10, to the env case). Never a fallback to an unjailed/direct run.
- **Interactive TTY/stdin is the one genuinely new engineering piece.** The tool-run step must be able to run the tool container with `-it` and wire `os.Stdin` + a PTY through, as a DISTINCT run mode behind the existing `Runner` seam. It interacts with the streaming/capture seam (`RunSpec` live sinks + captured return) built by `stream-tool-output-live`: interactive mode wants RAW passthrough (stdin + a TTY, no tee-into-capture), whereas the non-interactive/verify path keeps the capture tee. The design must keep BOTH behind the one `Runner` shape (no third conflicting redesign), and must NOT route the leak-test/verify probes through the interactive path (they need capture). Direction: add an interactive/TTY mode to `RunSpec` (or a sibling spec) that sets stdin + `-it` and skips capture; verify/probes keep the capture path.
- **Default dev image: pin a broad existing multi-language base; do NOT build/own an image in this slice.** Mirror the redirector's digest-pinning discipline (reproducible, no unpinned tag pulled at run time). `--image`/positional image overrides. Owning a bespoke `Containerfile` is explicitly out of scope here to keep the maintenance surface small (it can come later if a curated image is warranted).
- **Repo-mount ergonomics are thin sugar over `-v`, not a new isolation model.** A repo is just a host folder mounted (default target `/work`, workdir there). Writes land on the host folder by design (the user explicitly wants "operate on an existing folder"). This is the same `-v` pass-through the jail already does; the only additions are a sensible default mount target + workdir when a repo/positional path is given. (Whether a bare positional `<repo>` path auto-mounts, vs the user always writing `-v`, is a tasking-time ergonomics decision.)

## Testing Decisions

- **The leak guarantee must be shown to hold for the new modes, not assumed.** A test must assert that an interactive-flagged (and a declarative) run stands up the IDENTICAL jail topology as a plain run: same nft ruleset, same forced-egress route, UDP still dropped, fail-closed still holds. The point is that `-it` cannot accidentally weaken the jail. Prior art: the `TestJail_ForcedEgress_ExitIPIsProxys` + `nftRuleset` unit tests + `verify`'s three assertions.
- **Interactive TTY behaviour is testable at the seam without podman.** The `Runner` seam is already unit-testable with a fake runner (see `stream-tool-output-live`); an interactive-mode test can assert stdin is wired and the capture tee is bypassed using a fake, keeping the plain gate podman-free. The end-to-end TTY behaviour (a real `-it bash` through the jail) is a podman-gated integration test that `t.Skip`s without podman, mirroring the existing gated tests, and must leave no residue.
- **CLI accept/reject policy is pure-logic, test-first.** Parsing `-it -v -w -e` yields the right jail config + tool argv; parsing a jail-breaching flag (`--network host`, `-p ...`, `--dns ...`, `--privileged`) returns a clear rejection error naming the flag and why. `TOOLJAIL_PROXY` precedence (flag > env > refuse) and the malformed/`socks5://` env cases are pure-logic tests reusing `ParseProxy`. No podman needed for any of this.
- **No-residue after an interactive/declarative run** is asserted the same way the teardown-invariant tests do (`podman ps -a` shows no `tooljail-run-<id>-*`, no stray `tooljail-dns`/`nsenter`).

## Out of Scope

- **Nix / auto-build-from-repo (the larger ambition):** generating a minimal environment (a Nix flake, host-dep reuse) to run an arbitrary repo automatically. Stays deferred; it lives as its own incubating idea in `work/notes/ideas/minimal-setup-image-from-repo.md`. THIS prd is the lighter, distinct "set the repo up yourself, jailed, via an interactive/declarative shell" slice: it does not construct the environment, it confines it.
- **Full `podman run` flag compatibility.** Deliberately a curated allow-list + gated deny-list, not every podman flag (see Implementation Decisions). New podman flags are not automatically supported.
- **A bespoke/owned default dev image (`Containerfile`).** This slice pins a broad EXISTING image; building and maintaining our own is a later decision.
- **A host-network setup escape hatch.** Considered and rejected: the trusted case is served by the user setting up on the host outside tooljail (`cd repo && pip install`), so there is no `--setup-on-host` mode to build. Setup inside tooljail is always jailed.
- **Non-Podman runtimes, in-process tun2socks, UDP-associate:** unchanged from the parent tooljail prd's out-of-scope; not touched here.

## Further Notes

- Motivating trail: exploring running the `web-app-scanner` (webscan) tools through tooljail surfaced that (a) stateful tools (nuclei needs templates) want persisted setup, and (b) an untrusted tool's SETUP egress is itself worth jailing, not just its scan egress. That is what this prd captures: jail the setup, not only the run.
- This builds directly on the shipped core (forced-egress jail, teardown invariant, run-cli-wiring) and on `distinguish-podman-failure-from-tool-exit` + `stream-tool-output-live` (the `Runner` seam that interactive mode extends). The interactive TTY task should be `blockedBy` those seam tasks once tasked.
- Relationship to the leak-test: the added modes are IN-scope for `verify`'s guarantee precisely because they reuse the same jail; the prd requires a test proving topological identity so this stays true.
