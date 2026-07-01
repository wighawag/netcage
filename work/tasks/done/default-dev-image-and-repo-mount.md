---
title: Default pinned dev image and repo-mount ergonomics
slug: default-dev-image-and-repo-mount
prd: jailed-interactive-repo-run
blockedBy: [podman-shaped-cli-flag-parsing]
covers: [3, 4, 5, 10]
---

## What to build

Make `tooljail run` useful out of the box for the repo-setup story: supply a sensible DEFAULT dev image when the user does not pass one, and add thin repo-mount ergonomics so a repo folder lands at a known workdir. Both are conveniences over the existing `-v`/image surface, not a new isolation model.

End-to-end thin path:

- **Default dev image.** When no image POSITIONAL is given, use a broad, multi-language dev base (git + common language toolchains) so `tooljail run -it -v <repo>:/work -w /work bash` is useful bare. Pin it by an IMMUTABLE `@sha256:` digest, mirroring the redirector's digest-pinning discipline (reproducible, no unpinned/mutable tag pulled at run time). An explicit positional image OVERRIDES the default. NOTE: this builds on the podman-native POSITIONAL grammar that `podman-shaped-cli-flag-parsing` delivers (image is the first positional; there is no `--image` flag). When no positional image is present, the FIRST positional is the command (e.g. `run -it bash`) and the default image is injected; when a positional image IS present it is used as-is. Distinguishing image-vs-command among the positionals (when the default is in play) is a decision to record (see the prompt).
- **Repo-mount ergonomics.** Provide a sensible default mount target (`/work`) and set the container workdir there when the user mounts a repo, so setup/build/run happen in the repo without hand-writing `-w` every time. Writes land on the host folder by design (the user explicitly wants to operate on an existing folder); this is the same `-v` pass-through the jail already does.

This builds on the podman-native positional CLI surface from `podman-shaped-cli-flag-parsing` (positional image/argv + `-v`/`-w` flags already parsed there) and only adds the DEFAULTING behaviour + the pinned image reference; it touches the same `cli`/`main` mapping, so it is serialised after that task.

## Acceptance criteria

- [ ] Tests written FIRST: with no positional image supplied, the resolved run config uses the pinned default dev image; an explicit positional image overrides it. The default image reference is pinned by an `@sha256:` digest (asserted, mirroring the redirector-pin test), never a mutable tag.
- [ ] With a repo mount and no explicit workdir, the resolved config sets the default mount target `/work` and workdir `/work` (a repo dropped in is worked in without hand-writing `-w`); an explicit `-w`/`--workdir` overrides.
- [ ] A podman-gated integration test (t.Skip without podman) runs the default dev image through the jail and confirms it starts and its egress is forced through the proxy (exit IP is the proxy's), leaving NO residue.
- [ ] Tests cover the new behaviour; the config-defaulting cases are pure-logic and need no podman; the default-image run is podman-gated and isolates to throwaway run-attributable resources.

## Blocked by

- `podman-shaped-cli-flag-parsing`: this builds on the parsed image/mount/workdir surface that task establishes, and touches the same `cli`/`main` mapping, so it is serialised after it (must reach `tasks/done/` first) to avoid conflicts.

## Prompt

> Goal: give `tooljail run` a pinned default dev image (used when none is passed, overridable) and repo-mount ergonomics (default `/work` mount target + workdir), so pointing tooljail at a repo folder is useful out of the box. Read `CONTEXT.md`, the `internal/redirector` package (the digest-pinning discipline: `Repository`, `Digest`, `ImageReference()`, which you mirror for the default dev image), the `internal/cli` parsing + `main.go` `runRun` mapping to `jail.Config`, the prd `jailed-interactive-repo-run`, and the done record of `podman-shaped-cli-flag-parsing` (the parsed image/mount/workdir surface you extend).
>
> FIRST, check against current reality: confirm the parsed command from `podman-shaped-cli-flag-parsing` exposes image, mounts, and workdir as this task assumes, and that `internal/redirector` pins its image by an immutable `@sha256:` digest you can mirror. If either landed differently, reconcile rather than building on the stale assumption.
>
> Write the tests FIRST (testFirst is ON): the default image is used when none is given and is digest-pinned; an explicit image overrides; a repo mount with no `-w` defaults the mount target + workdir to `/work`; an explicit `-w` overrides. Then wire the defaulting into the parse->config mapping, and add the pinned default-dev-image reference (digest-pinned like the redirector). Add the podman-gated test that the default image runs through the jail with forced egress and no residue.
>
> Build on the POSITIONAL grammar `podman-shaped-cli-flag-parsing` delivers (image = first positional, no `--image` flag). Decide and record how image-vs-command is told apart when the default image is injected (e.g. `run -it bash` => default image + `bash` as the command), since with a default in play the first positional may be the command, not the image.
>
> "Done" means `tooljail run -it -v <repo>:/work bash` (or with a bare repo path) works with a sensible pinned default image and lands you in the repo dir, an explicit positional image and `-w` override, the default image is reproducible (digest-pinned), and the jail/leak behaviour is unchanged. Keep the verify gate green. RECORD non-obvious in-scope decisions (which base image + digest; the default mount target/workdir; how image-vs-command is disambiguated when the default is used; whether a bare positional repo path auto-mounts) per the task-template guidance (a `## Decisions` note, or an ADR if the base-image choice meets the ADR gate, since a pinned base image is plausibly ADR-worthy).
