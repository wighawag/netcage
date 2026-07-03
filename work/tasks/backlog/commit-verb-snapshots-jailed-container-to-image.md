---
title: Add `netcage commit <container> <image-ref>` - snapshot a netcage-managed (jailed) container's filesystem to an image, podman-faithful and forced-egress-safe
slug: commit-verb-snapshots-jailed-container-to-image
blockedBy: []
covers: []
---

## What to build

Add `netcage commit <container> <image-ref> [flags]` as a new pass-through
management verb that snapshots a netcage-managed container's FILESYSTEM into a new
image, exactly as `podman commit` does. It is the natural podman verb for the
"exploratory machine" loop: a user runs a KEPT jailed container (no `--rm`), plays
with system tools inside it (`apt install ...`, `/usr/local` tweaks), quits,
re-enters via `netcage start`, and eventually SNAPSHOTS the result into a reusable
image with `netcage commit`. Today netcage has no `commit`, so a user must reach
around it to raw `podman commit` (breaking the "netcage owns its containers"
boundary and forcing them to know the internal `netcage-run-<id>-tool` name).

Semantics (podman-faithful, mirrors the existing verbs):

- **Commit the TOOL container**, never the sidecar. The tool container holds the
  played-with filesystem (the apt/system state); the sidecar is just the jail
  plumbing (tun2socks + firewall + DNS). The user names a netcage-managed
  container (typically the tool); `commit` resolves it to the tool and commits
  THAT. (If a user names the sidecar, refuse with a clear message - commit takes
  the tool, like `netcage start` takes the tool.)
- **Scope to netcage-managed containers** via the same `netcage.managed` label
  guard the other named verbs use (`guardManaged`): a non-netcage / unknown
  container is REFUSED before any podman `commit` runs against it.
- **Pass through the safe metadata flags** verbatim: `-m`/`--message`,
  `-a`/`--author`, `-c`/`--change`, `-f`/`--format`, `--pause` (and its negation),
  `-q`/`--quiet`. Per netcage's own vetting checklist (ADR-0010) these are ALL
  network/isolation-IRRELEVANT (they only affect the image manifest / metadata /
  a momentary pause), so they are safe to allow. The `<image-ref>` is the
  new image name (required positional, after the container).
- **Works on a stopped OR running container.** The exploratory flow commits a
  STOPPED kept container (you quit, then bake); podman `commit` handles stopped
  as-is. A running container is fine too (podman's default `--pause` gives a
  consistent snapshot); do not special-case - let podman's own semantics apply.

FORCED-EGRESS INVARIANT (why this is trivially safe): `commit` is a pure
filesystem -> image snapshot. It does NOT start the container, touch the netns,
the firewall, DNS, or any network path - it cannot open a leak by construction.
So unlike `run`/`start` it needs NO sidecar revive / firewall verify: there is no
jail to restore because nothing runs. Note this explicitly (the one management
verb that is inherently jail-neutral), so a future reader does not "add a firewall
check for consistency" where none is meaningful.

## Acceptance criteria

- [ ] `netcage commit <container> <image-ref>` snapshots the resolved TOOL
      container's filesystem into `<image-ref>` (a `podman commit` under the hood),
      scoped by the `netcage.managed` label; a non-netcage / unknown container is
      REFUSED with a clear message before any commit runs.
- [ ] Naming a netcage SIDECAR (role=sidecar) is refused with a message directing
      the user to the tool container name (commit takes the tool, mirroring
      `netcage start`).
- [ ] The safe metadata flags (`-m`/`--message`, `-a`/`--author`, `-c`/`--change`,
      `-f`/`--format`, `--pause`, `-q`/`--quiet`) are accepted and passed through to
      podman `commit` verbatim; an UNKNOWN flag is refused (fail-closed on the
      unknown, like the run allow-list).
- [ ] `commit` works on a STOPPED kept container (the exploratory-machine path:
      run kept -> play -> quit -> commit) AND does not require the jail to be up
      (it never starts the container / touches the netns).
- [ ] The forced-egress invariant is untouched: `commit` is snapshot-only; it
      does not start the container, alter the firewall/DNS/netns, or give any
      container a working un-jailed network. (Documented as the jail-neutral verb.)
- [ ] Tests: unit tests for the verb dispatch + argv construction (the built
      `podman commit ...` argv, incl. the metadata flags + `<image-ref>`, WITHOUT
      executing podman, mirroring the existing manage-verb arg-builder tests) and
      the non-netcage / sidecar refusal; a podman-gated (`integration`) test that
      a kept container is committed to an image and the image exists afterwards.
- [ ] **Shared-write isolation (podman is host-global state):** the integration
      test creates a kept container AND produces a new IMAGE, so it MUST use a
      unique run-id container name AND a unique image tag, and `t.Cleanup` must
      remove BOTH the container pair (`podman rm -f --depend`) AND the created
      image (`podman rmi -f`) even on failure, so it cannot orphan a container or
      an image on the host or collide with a concurrent run.

## Blocked by

- None. It builds on the shipped v0.4.0 `manage` package + label + `start`'s
  tool-resolution, all on main; it adds a new verb without touching their logic.

## Prompt

> Goal: add `netcage commit <container> <image-ref>` - a podman-faithful
> `podman commit` for a netcage-managed (jailed) container, scoped by the
> `netcage.managed` label, committing the TOOL container's filesystem to a new
> image. It closes the exploratory-machine loop (run kept -> play with system
> tools -> quit -> `netcage start` to re-enter -> `netcage commit` to bake an
> image).
>
> FIRST, check this task against current reality (launch snapshot - may have
> DRIFTED): confirm `internal/manage` still dispatches verbs through `manage.Run`'s
> `switch verb` with a `guardManaged` label check on named verbs, that
> `internal/cli` has `managementVerbs` + `IsManagementVerb` (currently
> ps/logs/inspect/exec/stop/rm/images) and routes their positionals verbatim via
> `ManageArgv`, and that a managed container's labels (netcage.managed / role /
> run-id) are read the way `guardManaged` / `start`'s `resolveManagedTool` do. If
> the structure changed, adapt or route to needs-attention.
>
> Domain: netcage is a drop-in podman replacement forcing all egress through a
> socks5h proxy, fail-closed. A run creates a tun2socks SIDECAR (owns netns +
> firewall + DNS) and a TOOL container joined via `--network container:<sidecar>`.
> A non-`--rm` run leaves both stopped + labelled `netcage.managed` (ADR-0009);
> `netcage start` revives the pair to re-enter the tool. The tool container is
> where a user's played-with filesystem (apt/system state) lives.
>
> Where to look / seams: add `commit` to `managementVerbs`/`IsManagementVerb`
> (internal/cli) so it dispatches like the other verbs and carries NO proxy
> preflight (commit does not egress); add a `case "commit"` to `manage.Run` that
> (1) `guardManaged`s the named container, (2) refuses a role=sidecar with a
> message pointing at the tool, (3) resolves the tool container for the run id
> (reuse the sidecar/tool naming already in the jail package, e.g. how `rm`
> resolves the pair), (4) builds `podman commit [safe-flags] <tool> <image-ref>`
> and streams it. Parse/curate the safe metadata flags (`-m`/`--message`,
> `-a`/`--author`, `-c`/`--change`, `-f`/`--format`, `--pause`, `-q`/`--quiet`)
> and the required `<image-ref>` positional; refuse unknown flags (fail-closed).
> Test at the argv-builder seam (assert the built `podman commit` argv without
> running podman, mirroring the existing manage arg-builder tests) + the
> refusal paths; add one podman-gated integration test that commits a kept
> container to a uniquely-tagged image and asserts the image exists, cleaning up
> BOTH the container pair AND the image on `t.Cleanup` even on failure.
>
> Preserve the forced-egress invariant: `commit` is a PURE filesystem->image
> snapshot - it must NOT start the container, touch the netns/firewall/DNS, or
> give any container a working un-jailed network. It needs NO sidecar-revive /
> firewall-verify (there is no jail to restore because nothing runs); it is the
> one management verb that is inherently jail-neutral. Note that in a comment so a
> later reader does not add a meaningless firewall check.
>
> RECORD any in-scope choice in the done record (e.g. exactly which commit flags
> you allow and why they pass the ADR-0010 vetting checklist; whether an ADR is
> warranted - likely NOT, this is a straightforward podman-faithful verb addition
> that does not change a hard-to-reverse decision, so a done-record note is
> enough). Done = `netcage commit <container> <image-ref>` snapshots the tool to
> an image, is label-scoped + refuses non-netcage/sidecar, passes through the safe
> flags + refuses unknown ones, is proven snapshot-only (no jail touch), and the
> tests cover the argv construction + refusals + a podman-gated commit-to-image
> cycle that cleans up its container AND image.
