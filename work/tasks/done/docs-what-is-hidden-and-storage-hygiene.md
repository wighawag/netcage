---
title: Document what a netcage jail does and does NOT hide, plus -v username hygiene and the working clear-storage command
slug: docs-what-is-hidden-and-storage-hygiene
spec: jail-host-identity-hardening
blockedBy: [relocate-graphroot-to-var-tmp-single-store]
covers: [6, 9, 10]
---

## What to build

User-facing documentation (in the README / docs, wherever the run + verify story is already described) covering three things so the residual host fingerprint is documented rather than surprising:

1. **What netcage hides and what it does NOT.** A short, honest statement: netcage GUARANTEES network egress confinement (IP + DNS through the proxy, fail-closed, proven by `verify`); it ALSO hides the host machine name, the operator username (via the relocated store), and the host NIC name/MAC; it does NOT hide host hardware or the kernel version (the kernel is shared: a container is not a VM), nor env baked into the tool/wrapper image. Point to ADR-0013 for the full scope rationale.

2. **`-v` username hygiene.** Note that a `-v` bind mount's SOURCE path is preserved as-is in the container's mount table, so mounting a project from under `$HOME` (e.g. `-v ~/dev/foo:/work`) still reveals the username in that path. Users who care should mount from a path outside `$HOME`.

3. **Clearing netcage's storage (the working way).** Because the relocated graphroot's overlay tree is owned by id-mapped subuids under rootless podman, a plain `rm -rf` FAILS with permission errors. Document the working command: `podman --root <netcage /var/tmp store path> system reset --force`.

This is a docs-only task (no code), but it depends on the graphroot task having chosen the concrete `/var/tmp` store path so the clear-storage command names the real path.

## Acceptance criteria

- [ ] The docs state the network-egress guarantee AND the per-category host-identity disposition (hostname/username/NIC-name hidden; hardware/kernel + image env not), with a pointer to ADR-0013.
- [ ] The docs explain the `-v` source-path username exposure and the "mount outside `$HOME`" mitigation.
- [ ] The docs give the correct clear-storage command (`podman --root <path> system reset --force`) and explicitly warn that `rm -rf` does not work (id-mapped overlay tree), naming the actual store path chosen by the graphroot task.
- [ ] No code change; nothing writes to a shared/global location, so no isolation test needed. (If any doc snippet is exercised by a doc-test harness, it must not mutate the real store.)

## Blocked by

- `relocate-graphroot-to-var-tmp-single-store` — the clear-storage command and the "username hidden via the store" claim must name/reflect the concrete `/var/tmp` path that task chooses.

## Prompt

> Goal: document what a netcage jail hides and does not hide, `-v` username hygiene, and the working clear-storage command, so the residual host fingerprint is documented rather than surprising. This is stories 6/9/10 of the jail host-identity hardening prd.
>
> Where to look: the README's run/verify sections (that is where the guarantee is described today). Read ADR-0013 (`docs/adr/0013-host-identity-hardening-scope.md`) for the authoritative scope and `work/notes/observations/jail-leaks-host-identity-metadata-not-network.md` for the tested detail. Reflect the graphroot path that `relocate-graphroot-to-var-tmp-single-store` actually chose (read its done record / the code) so the clear-storage command is exact.
>
> Content to convey accurately: (a) network egress is the guarantee (verify proves it); hostname/username/NIC-name are additionally hidden; hardware + kernel version + tool-image env are NOT hidden and why (shared kernel; image env is the tool/wrapper's concern). (b) `-v` source paths under `$HOME` still leak the username; mount outside `$HOME` to avoid it. (c) clear storage with `podman --root <path> system reset --force`, NOT `rm -rf` (id-mapped overlay tree fails on permissions).
>
> FIRST, check this task against current reality (drift check): confirm the graphroot task landed with the `/var/tmp` store and read the exact path it uses; if it diverged (e.g. a different neutral path), document what actually shipped, not this task's assumption.
>
> "Done" = a reader understands the netcage jail's identity boundary, can keep their username out of `-v` paths, and can clear storage without hitting a permission error.
