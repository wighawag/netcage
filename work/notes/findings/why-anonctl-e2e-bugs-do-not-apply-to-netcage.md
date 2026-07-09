---
kind: finding
title: Why anonctl's first-e2e-run bugs do NOT apply to netcage (a third axis where the netns model is structurally tighter than per-UID)
slug: why-anonctl-e2e-bugs-do-not-apply-to-netcage
source: |
  Cross-repo analysis, 2026-07-09, after the sibling anonctl project ran its FIRST
  real end-to-end validation of its compiled binary on a real host (anonctl finding
  work/notes/findings/e2e-binary-validation.md). That run surfaced two SERIOUS bugs
  and several minor ones. This note records, checked against netcage's actual code
  and ADRs (internal/verify/verify.go, internal/*/integration_test.go,
  docs/adr/0008 the baked-firewall ADR, ADR-0003, ADR-0011 start-revives-jail),
  which of those findings apply to netcage. Conclusion: NONE require a netcage fix,
  for a structural reason worth recording. This is a REFERENCE/analysis note; the
  canonical bug details live in the anonctl repo.
---

## Why this note exists

anonctl and netcage solve the same primitive (force all of some scope's egress through a socks5h anonymizer, fail-closed) at different scopes: anonctl per Unix UID on a shared host, netcage per container netns. anonctl's first real-binary end-to-end run found bugs that, on inspection, are all consequences of the PER-UID-ON-A-SHARED-HOST model. netcage's per-netns-with-a-baked-firewall model does not have those failure modes. Recording WHY, so (a) nobody wastes time "porting the anonctl fixes" to netcage, and (b) the recurring structural advantage is on the record.

## The four anonctl findings, checked against netcage

### 1. Reboot fail-open (anonctl's most serious bug) -> does NOT apply

anonctl persisted its forcing ruleset via a drop-in on the HOST's `nftables.service`, which Debian ships DISABLED, so after a real reboot the forcing rules were absent and the anon UID egressed with the host's real IP in the clear. The fix inverted it to a standing per-UID default-deny loaded by anonctl's own early unit.

netcage has NO persistent host firewall to lose. The jail firewall is baked into the redirector sidecar's create-time `EXTRA_COMMANDS` (ADR-0008) and lives entirely inside the container netns. It re-applies AUTOMATICALLY whenever the sidecar (re)starts, including podman auto-revival, and `netcage start` re-applies the baked firewall and then RE-VERIFIES it (ADR-0011) before re-entering. The lifecycle is ephemeral-or-explicitly-revived: a `--rm` run vanishes; a kept container is "left behind fail-closed by the baked firewall"; a reboot kills the containers, and reviving one re-bakes + re-verifies. There is no "persisted host state silently absent after reboot -> leak" window, because fail-closed is a container-CREATE-TIME invariant, not a persisted-host-state race. netcage is structurally immune, and the `verify`-on-`start` netcage already ships is exactly the check anonctl had to add.

### 2. verify probes misusing the transparent relay (anonctl's second serious bug) -> does NOT apply

anonctl's `verify` false-failed 5/9 assertions on a HEALTHY account because its probes dialed the shim's transparent `SO_ORIGINAL_DST` relay as if it were a SOCKS server, and misread a completed loopback TCP handshake with the relay as "reached the target". The fix re-pointed them to egress AS the anon UID and assert on OFF-BOX reachability (an nft escaped-leak counter).

netcage's `verify` is architecturally different and already correct: it runs a real tool INSIDE the jail (`ExitIPProbe` runs the config's `ToolArgv` through `jail.Run`) and observes the real exit IP through the confined netns. It never dials its own relay/forwarder as a proxy, and its probes egress from inside the confinement, the netns equivalent of anonctl's fixed "egress as the anon UID". So netcage already does the RIGHT thing anonctl had to be fixed into. No bug.

### 3. Leaked global test seam -> does NOT apply

anonctl's unit `TestMain` set a package-level function seam (`WriteLoginEnv = no-op`) and never restored it, so under `-tags integration` the stub leaked into the integration test and the real writer never ran. netcage's three `TestMain`s (internal/verify, internal/manage, internal/jail) only set PROCESS-SCOPED env vars (`NETCAGE_DNS_BIN`, `NETCAGE_GRAPHROOT`) and build a helper; they do NOT clobber a package-level function seam without restoring it. The one package-level seam (`verify.DefaultRunner`) is not mutated in `TestMain`. Checked, clean.

### 4. Minor gaps (teardown residue, cosmetic message) -> anonctl-specific

These are about anonctl's `/etc/anonctl` + systemd-unit footprint on a shared host. netcage owns podman containers + a baked-in sidecar firewall, a different footprint; its teardown story is the `--rm`/kept-container lifecycle (ADR-0009), already covered by its own tasks. Nothing to port.

## The pattern: a THIRD axis where the netns model is structurally tighter than per-UID

This is now the third distinct place where confining by NETWORK NAMESPACE beats confining by socket-owning UID on a shared host:

1. **The UID-transition escape (Tails row 7):** anonctl matches `meta skuid`, so a setuid/sudo/daemon socket owned by a DIFFERENT uid escapes forcing in the clear. A netns has no per-uid escape: everything in the jail is confined by namespace regardless of uid. (Recorded in `learning-from-anonctl-tails-leak-catalogue.md`.)
2. **Reboot / persisted-host-state fail-open (this note, finding 1):** anonctl's forcing is loose host state that must be re-loaded fail-closed at every boot; netcage's is a container-create-time baked invariant with no persisted-host-state race.
3. **verify integrity (this note, finding 2):** probing forced egress from INSIDE a netns (run a tool in the jail) is unambiguous; probing per-UID forcing on a shared host had to thread the transparent-relay + nat-redirect semantics correctly, which anonctl got wrong on the first try.

Each is the same root cause: a per-UID forcer runs on a machine full of OTHER uids and loose OS state it does not fully own, so it must defend a larger, racier surface; a netns jail confines a self-contained world. This is NOT an argument that netcage is strictly better (they have different use cases: netcage jails a container/tool, anonctl anonymizes a whole login account you use natively). It is an argument that the netns model's guarantee is structurally SIMPLER to make airtight on these three axes, worth stating honestly in netcage's docs (alongside ADR-0013's honest scope) when the two tools are compared.

## Disposition

No netcage code change. This is a documentation/analysis finding. If netcage's docs ever add a "how netcage compares to anonctl / per-UID forcing" section, these three axes are the honest, concrete content for it. The one thing worth a glance in future work: netcage's OWN `verify` growth (the Tails-catalogue backlog tasks) should keep probing FROM INSIDE the jail (its correct current pattern), never regress to dialing its own forwarder/proxy, which is exactly the anonctl mistake this note records.
