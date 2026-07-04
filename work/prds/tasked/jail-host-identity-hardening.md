---
title: Jail host-identity hardening - stop a jailed tool fingerprinting the operator (hostname, username, host NIC), and state the scope explicitly
slug: jail-host-identity-hardening
promptGuidance.testFirst: true
---

> Launch snapshot - records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked - they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

## Problem Statement

netcage's guarantee is forced NETWORK egress: every TCP/DNS packet from the wrapped tool goes through the socks5h proxy, fail-closed, so the tool cannot leak the real IP or resolve DNS on the host. That guarantee holds.

But netcage exists to run UNTRUSTED / aggressive tools (recon, scan) without revealing who or where you are. A live session (captured in `work/notes/observations/jail-leaks-host-identity-metadata-not-network.md`) showed that a tool inside the jail can still fingerprint the OPERATOR'S MACHINE with zero network access, purely by reading local files and interfaces:

- **host machine name** (`nono`) from the container's `/etc/hosts` (`127.0.1.1 <hostname>`),
- **host username** (`wighawag`) from rootless Podman storage paths in `/proc/self/mountinfo` (`/home/<user>/.local/share/containers/storage/...`),
- **host NIC name** (`enxc8a362ba9779`) which, under systemd `enx<MAC>` naming, re-exposes the host NIC MAC,
- plus host hardware/kernel (`/proc/cpuinfo`, `uname`) and wrapper env (`ANON_PI_STAGE`, `SEARXNG_HOME`).

For netcage's threat model a precise host fingerprint (real username, hostname, NIC MAC) is arguably as deanonymizing as an IP leak, even though it sits outside the "forced egress" framing. Today netcage does nothing about it: the tool container is a plain `podman run --network container:<sidecar>` with no `--hostname`, no `/etc/hosts` sanitization, and the default username-bearing graphroot.

The `verify` leak-test proves network confinement but never probes host-identity exposure, so the scope of "what netcage hides" has never been stated. Users may reasonably assume a jail hides more than it does.

## Solution

Close the cheap, clearly-in-scope host-identity leaks that netcage OWNS, tell users how to close the one that depends on their own choice (`-v` mount paths), and STATE THE SCOPE explicitly (in an ADR + the `verify` seam) so the residual (shared-kernel hardware/kernel fingerprint) is documented, not surprising.

From the user's perspective, after this: a tool jailed by netcage cannot read the host's machine name or the operator's username from inside the container, and the in-netns interface no longer carries the host NIC's name/MAC. netcage's docs tell me what is and is not hidden, and how to keep my username out of `-v` mount paths if I care.

Concretely (detail lives in the observation + moves to tasks/ADRs at tasking time):

- **`/etc/hosts` + hostname:** mount a sanitized `/etc/hosts` (localhost only) into the tool container and set a fixed `--hostname`, so the host machine name no longer leaks. Mirrors the resolv.conf mount netcage already does.
- **Username via graphroot:** point Podman's graphroot (`--root`) at a username-free path under `/var/tmp`, so `/proc/self/mountinfo` no longer embeds `/home/<user>`. Same storage semantics as today (persistent, self-healing, holds image cache + kept containers), only the path changes. Leave `--runroot` at its default. User `-v` volume source paths are the user's own choice: document "mount from outside `$HOME` to keep your username out of that path."
- **NIC name/MAC:** pass pasta `-I,<stable-name>` (e.g. `netcage0`) so the in-netns interface is not named after the host NIC. PROVEN in the observation: the name leak disappears and egress is unaffected.
- **Scope statement:** an ADR that says netcage guarantees NETWORK egress; host-identity masking is closed where cheap+owned (above) and the shared-kernel residual (hardware, kernel version) is an accepted non-goal (a container is not a VM). Note the wrapper-env leak (`ANON_PI_STAGE` etc.) is the WRAPPER image's concern (anon-pi), not netcage's.

## User Stories

1. As an operator jailing an untrusted tool, I want the container's `/etc/hosts` to NOT contain my host machine name, so a tool reading it cannot learn my machine's name.
2. As an operator, I want the jailed tool's hostname to be a fixed neutral value, so `/etc/hostname` and the container's own name do not reveal or mirror my host.
3. As an operator, I want Podman's storage paths (visible in the container's `/proc/self/mountinfo`) to NOT contain my username, so a tool cannot recover my host account name.
4. As an operator, I want that storage relocation to behave exactly like today's home-folder storage (persistent across runs + reboots, holds my kept containers and image cache, self-heals if wiped), so the anonymization does not cost me the kept-run behaviour.
4a. As an operator, I want ALL netcage subcommands (run, start, and the pass-through verbs ps/logs/etc.) to use the SAME relocated store, so `netcage ps`/`logs`/`start` still find the containers a `netcage run` created (a split store would make them invisible).
5. As an operator, I want clear docs that if I mount a project with `-v` from under my home directory, that source path still reveals my username, and that mounting from outside `$HOME` avoids it, so I can make an informed choice.
6. As an operator, I want the in-netns network interface to NOT be named after my host NIC (which, as `enx<MAC>`, re-exposes my NIC MAC), so a tool reading `/sys/class/net` cannot recover my host MAC from the interface name.
7. As an operator, I want the interface rename to not affect egress (traffic still forced through the proxy, fail-closed), so the anonymization is free of connectivity cost.
8. As an operator, I want documentation of what netcage does and does NOT hide (network egress: guaranteed; hostname/username/NIC-name: hidden; host hardware + kernel version: NOT hidden because the kernel is shared), so I am not surprised by the residual fingerprint.
9. As an operator, I want a documented way to clear netcage's relocated storage that actually works (`podman ... system reset --force`, since a plain `rm -rf` fails on the id-mapped overlay tree), so I can reset without hitting permission errors.
10. As a maintainer, I want the scope decision recorded as an ADR so future changes do not silently erode or over-claim the host-identity boundary.

### Autonomy notes (the two gate axes)

- **`humanOnly`:** not set on this prd. The tasking is straightforward and the design is already resolved in the observation; a human MAY drive it but an agent tasking it would not be guessing. (Individual tasks set their own build-nature gate; none of these look like secrets/release/security-boundary work - they are jail-wiring + docs + an ADR.)
- **`needsAnswers`:** not set. The design forks were all resolved in the maintainer session recorded in the observation (rootful rejected; masking + `setup` verb dropped; `/var/tmp` chosen; pasta `-I` proven). One small open choice remains but is NOT blocking (see Open questions in Further Notes - it is a default-value pick with a safe default, not an unresolved premise).

> Tasked: implementation + testing detail moved into `work/tasks/` (`hide-host-identity-in-jail-wiring`, `relocate-graphroot-to-var-tmp-single-store`, `docs-what-is-hidden-and-storage-hygiene`) and the durable rationale into `docs/adr/0013-host-identity-hardening-scope.md`. Tested provenance is in `work/notes/observations/jail-leaks-host-identity-metadata-not-network.md`.

## Out of Scope

- **Host hardware / kernel fingerprint** (`/proc/cpuinfo`, `/proc/meminfo`, `uname`, kernel version): NOT hidden. The kernel is shared (containers, not VMs); `/proc/cpuinfo` reports physical CPUs regardless of cgroup limits, and faking it breaks tools. A real fix needs a different isolation model (gVisor/Kata). Accepted residual, documented in the scope ADR.
- **Wrapper/tool-image env** (`ANON_PI_STAGE`, `SEARXNG_HOME`, and any operator-identifying ENV baked into the tool image): NOT netcage's to strip. It comes from the wrapper image (anon-pi) / the tool image's own Dockerfile. A cross-repo note points this at anon-pi (don't bake operator-identifying env into the jailed tool's environment). netcage's own `netcage-run-<id>-*` names + `netcage.managed` labels are deliberate and low-sensitivity (ADR-0009); not hidden.
- **mountinfo masking / a `setup` provisioning verb:** considered and DROPPED. The `/var/tmp` graphroot needs no root and no provisioning helper, and docs handle the `-v` case, so masking (which can break tools that read mountinfo) and a `setup` verb are unnecessary. `setup-default` (the ADR-0012 config writer) is unrelated and unaffected.
- **Rootful Podman:** rejected. Rootless is load-bearing (ADR-0001, ADR-0002, both foundational spikes); rootful would only incidentally neutralise the username path while detonating the reachback model and worsening the escape threat. The `/var/tmp` graphroot achieves the username fix staying rootless.
- **LAN-topology residual** on the pasta interface (the copied `192.168.1.0/24` addresses/routes): a smaller, separate follow-up from NIC-name identity; noted in the observation, not tackled here.

## Further Notes

- Full tested provenance (live probes on this host, throwaway `--root`, zero residue) is in `work/notes/observations/jail-leaks-host-identity-metadata-not-network.md`. Read it before tasking - it records every dead-end already ruled out (rootful, masking, the `setup` verb, ephemeral-storage-auto-delete) so they are not re-litigated.
- The remaining small choices (exact `/var/tmp` store subpath; fixed hostname constant vs run-id) are left to the building tasks with safe defaults; ADR-0013 owns the scope rationale.
- All changes preserve the forced-egress guarantee; the `verify` leak-test staying green is the floor for every task here.
