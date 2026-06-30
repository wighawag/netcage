---
title: Minimal-setup base image that runs an arbitrary repo (Nix-flake assisted)
slug: minimal-setup-image-from-repo
---

# Minimal-setup base image that runs an arbitrary repo

Proposed idea, deferred out of tooljail v1 (which wraps an existing image + command).

## The idea

Instead of requiring the user to already have a container image for the tool, let tooljail produce the **minimal setup required to run a repo** on demand:

- a default base image that can run an arbitrary repo;
- if the repo ships a Nix flake, use it; if not, tooljail provides/generates one;
- ideally reuse dependencies already installed on the host so the image stays minimal.

Goal: point tooljail at a tool's *repo* (not a prebuilt image) and have it build the least environment needed to run that repo, then jail its egress as usual.

## Why deferred

- It is a separate, larger surface than the core leak-proof egress jail.
- Making "wrap an arbitrary repo/binary" leak-proof and reproducible is materially harder than wrapping a known image.
- v1's value (force any tool's egress through socks5h, fail-closed, proven by a leak-test) stands alone without it.

## Open threads (for when this is picked up)

- Nix-flake generation for a repo that lacks one: how much can be inferred vs must be declared?
- Host-dep reuse without breaking reproducibility or the jail's isolation.
- Relationship to the egress jail: this is about *constructing* the tool environment; the jail is about *confining* its network. They compose but are independent.
