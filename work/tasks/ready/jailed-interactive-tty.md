---
title: Interactive TTY/stdin run mode through the jail (shell into a jailed repo)
slug: jailed-interactive-tty
prd: jailed-interactive-repo-run
blockedBy: [distinguish-podman-failure-from-tool-exit, stream-tool-output-live]
covers: [1, 2, 11, 12]
---

## What to build

Give the jail's tool-run step an INTERACTIVE mode: run the tool container with a TTY and stdin attached (`podman run -it`) so a human or an agent can shell into the jail and set up / run a repo's tool by hand, with egress forced through the proxy exactly as a non-interactive run is today.

End-to-end thin path:

- When the parsed command is interactive (the `-i`/`-t` flags from `podman-shaped-cli-flag-parsing`), the tool-run step runs the tool container with `-it` and wires the process's `os.Stdin` + a PTY through, as a DISTINCT run mode behind the EXISTING `Runner` seam. This is RAW passthrough: no capture tee, no trimming, keystrokes and the tool's TTY output (prompts, progress bars, pagers, Ctrl-C) behave as in a normal `podman run -it`.
- The NON-interactive path is unchanged: it keeps the streaming-tee-plus-capture behaviour that `stream-tool-output-live` established, and the verify/leak-test probes keep their CAPTURE path (`Result.ToolStdout`). Interactive mode must NOT route the probes through the raw path (they need capture); interactive is opt-in and only for `tooljail run`.
- Everything else about the jail is IDENTICAL to a normal run: the same sidecar + shared netns + nft ruleset (UDP dropped, reachback narrowed) + DNS forwarder + fail-closed default + teardown. Interactivity changes only stdin/stdout/TTY wiring, never the network jail.

The design must extend the ONE `Runner` shape (a `RunSpec`-carried interactive/TTY option, or a sibling raw-passthrough mode) rather than forking a third conflicting runner redesign. It builds directly on the stdout/stderr-separated, live-sink seam the two blocking tasks established.

## Acceptance criteria

- [ ] Tests written FIRST: the `Runner`/run-mode seam is unit-testable WITHOUT podman (a fake runner asserts that interactive mode wires stdin and bypasses the capture tee, while the non-interactive path still captures into `Result.ToolStdout`).
- [ ] A podman-gated integration test (t.Skip without podman, mirroring the existing gated tests) proves an interactive-flagged run stands up the IDENTICAL jail topology as a plain run: same nft ruleset, forced egress active (exit IP is the proxy's), UDP dropped, fail-closed preserved. `-it` must not weaken the jail.
- [ ] An interactive/declarative run leaves NO residue (no `tooljail-run-<id>-*` container, no stray `tooljail-dns`/`nsenter`), asserted as the teardown-invariant tests do; podman-gated cases isolate to throwaway run-attributable resources.
- [ ] The existing forced-egress + leak-test probes (which parse `Result.ToolStdout`) keep working unchanged (the capture path is not removed for the non-interactive/verify path).
- [ ] Tests cover the new behaviour; the pure-seam cases need no podman, the topology/residue cases are podman-gated.

## Blocked by

- `distinguish-podman-failure-from-tool-exit`, `stream-tool-output-live`: this extends the stdout/stderr-separated, live-sink `Runner` seam those two tasks own (and touches the SAME tool-run step / Runner), so it is serialised after them to avoid a conflicting redesign and file conflicts. They must reach `tasks/done/` first.

## Prompt

> Goal: add an interactive TTY/stdin run mode to the jail so `tooljail run -it <image> bash` drops the user into a jailed shell, egress forced through the proxy, same jail as a normal run. Read `CONTEXT.md` (jail, forced egress, fail-closed), the `internal/jail` package (the `Runner` interface + `RunSpec` with its live Stdout/Stderr sinks and separated capture, `ExecRunner`, the tool-run step in `Run` that builds the tool `RunSpec`), `main.go`'s `runRun`, the prd `jailed-interactive-repo-run`, and the done records of `distinguish-podman-failure-from-tool-exit` + `stream-tool-output-live` (they own the seam you extend).
>
> FIRST, check against current reality: the two blocking tasks changed `Runner.Run` to return separated stdout/stderr and gave `RunSpec` optional live Stdout/Stderr sinks (a tee) plus a capture return; `main.go` sets those sinks to os.Stdout/os.Stderr for the run path while verify/probes leave them nil (capture-only). Confirm that seam shape landed as described before building on it. If it landed differently, reconcile (route to needs-attention with the discrepancy) rather than building on a stale premise. ADRs 0001/0002/0003 (tun2socks sidecar, pasta reachback, hard-block UDP) still hold; do not relitigate them.
>
> Write the seam test FIRST (testFirst is ON): a fake runner proves interactive mode wires stdin + bypasses the capture tee, while non-interactive still captures. Then wire the tool-run step to run `podman run -it` with `os.Stdin` + a PTY in interactive mode, behind the existing `Runner` shape (extend `RunSpec`/the run mode, do NOT fork a third runner). Add the podman-gated test that an interactive run stands up the identical nft/forced-egress/UDP-drop/fail-closed topology and leaves no residue.
>
> "Done" means an interactive jailed shell works (stdin/TTY/Ctrl-C behave like a normal `podman run -it`), the leak guarantee is proven UNCHANGED for the interactive path (same jail topology, verify probes still capture), and no residue remains. Keep the verify gate green; the podman-gated tests must genuinely pass (not skip) where podman is present. RECORD non-obvious in-scope decisions (how interactivity is carried on the seam; how stdin/PTY is wired; the raw-vs-capture split) per the task-template guidance (a `## Decisions` note, or an ADR if a choice meets the ADR gate).
