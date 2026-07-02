---
title: Vendor + pin the tun2socks redirector by digest (reproducible, no scan-time pull)
slug: vendor-pin-redirector
prd: netcage
blockedBy: [spike-rootless-tun-routing]
covers: [13]
---

> `needsAnswers` cleared 2026-06-30: `spike-rootless-tun-routing` returned a POSITIVE result (see `work/notes/findings/spike-rootless-tun-routing.md`) confirming the tun2socks sidecar approach holds under rootless Podman, so pinning the redirector is no longer premised on an unconfirmed mechanism. (Still `blockedBy` the spike's completion record.)

## What to build

Pin the redirector so runs are reproducible and nothing unaudited is pulled at scan time (story 13). The redirector is the `xjasonlyu/tun2socks` project (ADR-0001); it must be referenced by an immutable **digest**, never a mutable tag like `:latest`.

End-to-end thin path: the code/config that selects the redirector image (or vendored binary) references a pinned digest, and a test asserts no mutable tag is used and that the pinned reference is the one the run path consumes.

Pure-ish: this is config + a guard test; it does not itself need to stand up the jail. It depends on the TUN spike only to confirm the tun2socks approach is real before pinning to it.

## Acceptance criteria

- [ ] Test written FIRST and RED before the pin: assert the redirector reference is an immutable digest (e.g. `@sha256:...`) and NOT a mutable tag (`:latest` / a bare tag), and that the run path consumes exactly that pinned reference.
- [ ] The tun2socks redirector is referenced by digest; the digest is recorded in-repo (so a reviewer can audit what is pulled).
- [ ] No scan-time pull of an unpinned/unaudited image is possible via the run path.
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- `spike-rootless-tun-routing` — confirms the tun2socks sidecar approach before we pin to it (clear `needsAnswers` after it lands).

## Prompt

> Goal: pin the tun2socks redirector by immutable digest so runs are reproducible and no unaudited image is pulled at scan time (story 13). Read ADR-0001 (tun2socks sidecar, `xjasonlyu/tun2socks`, pinned by digest) and `CONTEXT.md` (redirector).
>
> FIRST, check against current reality: this task carries `needsAnswers: true` until `spike-rootless-tun-routing` confirms the tun2socks sidecar approach. Read its finding; if the spike forced an ADR-0001 revisit, do NOT pin to a dead approach — route to needs-attention.
>
> Write the guard test FIRST (testFirst is ON): assert the redirector reference the run path uses is an immutable `@sha256:` digest, not a mutable tag, and that nothing pulls an unpinned image. Then add the pinned reference + record the digest in-repo.
>
> "Done" means the redirector is digest-pinned, the digest is auditable in-repo, the guard test is green, and no run-path code can pull a mutable/unpinned image. RECORD the chosen digest + how it was obtained (so it is auditable) per the task-template guidance.
