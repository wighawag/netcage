---
title: Promote NETCAGE_GRAPHROOT to a supported private-graphroot knob (dedicated-account deployments)
slug: private-graphroot-for-dedicated-account
---

# Promote NETCAGE_GRAPHROOT to a supported private-graphroot knob

Proposed idea. Today `NETCAGE_GRAPHROOT` exists (`internal/jail/graphroot.go`) but is explicitly documented as **test-only** ("NOT a user-facing knob"), used solely so integration tests can isolate storage. This note asks to promote it (or add a sibling supported mechanism) to a **documented deployment knob**, because a real threat model wants a private, unfindable graphroot that the current `/var/tmp` default deliberately does not provide.

## Context: the driving threat model (from anon-pi)

The sibling project anon-pi wants a **hardened deployment** where anon-pi runs under a dedicated Unix account (`netuser`) so that a coding agent running on the host **as your normal login user** cannot *accidentally* surface your anonymized work (e.g. you ask that host agent "find my previous conversation" and it greps `$HOME` and stumbles onto recon transcripts). The defense is Unix ownership: `netuser` owns the workspace mode-700, your login user is not in it, so a casual `find`/`grep` as you simply cannot read it. This is a **discoverability boundary** (accidental discovery), not hard containment against a determined attacker who deliberately `sudo -u netuser`s.

anon-pi can point its own workspace into `netuser`'s tree via `ANON_PI_HOME` (already supported). But that only covers the launcher-side files. The **container scratch / overlay layers netcage writes still land in the shared graphroot**, which today is world-visible.

## The tension this exposes inside netcage

netcage's current graphroot is hardcoded to `/var/tmp/netcage-storage` and was chosen (ADR-0013, Leak 2) **specifically to be world-writable-sticky and username-free**, so the in-jail tool reading `/proc/self/mountinfo` does not learn the operator's account name. That goal (**hide the username from the confined tool**) pulls in the *opposite* direction from the new goal (**keep the store private and unfindable from other host processes running as the login user**):

- `/var/tmp/netcage-storage` is world-traversable. A host agent running as you can `find /var/tmp/netcage-storage`, see image names, container metadata, and any overlay content readable within your subuid range. (The `diff/` tree is owned by id-mapped subuids, so parts are unreadable, but the path structure and metadata are exposed.)
- Under a dedicated `netuser`, "username-free" no longer matters (the only name that could leak is `netuser`, which is fine / intended). What matters instead is that the store live under `netuser`'s **private mode-700 path** (e.g. `~netuser/.local/share/netcage-storage`), invisible to your login user's casual searches.

So the two threat models want different defaults, and they do not conflict *per deployment*: a normal single-user install keeps the `/var/tmp` username-free default; a dedicated-account install wants a private path. netcage just needs to make the private path a **supported** choice.

## The idea

Make the graphroot relocatable through a **supported, documented** mechanism (not a test-only env seam):

- Keep `/var/tmp/netcage-storage` as the default (unchanged single-user behavior, Leak 2 still served).
- Promote `NETCAGE_GRAPHROOT` (or add an explicit, documented equivalent) to a first-class knob for "point my whole store at this private path," with docs describing exactly the dedicated-account use case.
- Ensure `--runroot` / transient state also lands somewhere `netuser`-private (today the code deliberately leaves `--runroot` at its default to avoid lock-refresh noise; under a dedicated account with lingering this is already `netuser`-owned via `$XDG_RUNTIME_DIR`, but verify it does not spill into a world-visible path).

## Related friction to resolve

- **`manage` verbs refuse a user-supplied `--root`** (`internal/manage/manage.go` ~line 117: "netcage owns the image store location"). That refusal is correct for its purpose (prevent a split store), but it means the env-var path is the *only* way to relocate, reinforcing that the env var must become supported rather than smuggling `--root`.
- The single-injection-seam design (ADR-0013, `podmanGlobalArgs`) is exactly right for this: one resolver already feeds every podman invocation, so promoting the knob is mostly **docs + intent + tests**, not new plumbing.

## Blocks / relates to

- **Blocks** the anon-pi "hardened dedicated-account deployment" idea: without a private graphroot, `netuser`'s container scratch lands in world-visible `/var/tmp` and partially defeats the point.
- **Relates to** the forensic-cleanliness tier: a RAM-backed (tmpfs) graphroot is the stronger variant (unrecoverable on unlink, modulo swap), and is the same knob pointed at a tmpfs path. Worth documenting as the "anti-forensic" option, distinct from the "private/unfindable" option.

## Open threads

- Promote the existing env var, or introduce a clearer name and keep `NETCAGE_GRAPHROOT` test-only? (Fewer knobs vs. clearer intent.)
- Should netcage *validate* the private path's mode (warn if world-readable) when it is set for the private use case, or stay hands-off?
- Document the ADR-0013 tension explicitly: username-free (default) vs. private-and-unfindable (dedicated account) are different goals for different threat models; the default serves the first, the knob enables the second.
