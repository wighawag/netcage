---
title: Stream the wrapped tool's stdout/stderr live instead of buffering to the end
slug: stream-tool-output-live
blockedBy: [jail-run-forced-egress, run-cli-wiring, distinguish-podman-failure-from-tool-exit]
covers: []
---

> Chore (no `prd`/`covers`): a usability refinement of the tool-run step, not the delivery of a prd
> user story. SERIALISED after `distinguish-podman-failure-from-tool-exit`: both change the SAME
> `internal/jail` Runner + tool-run step, and both need the wrapped tool's stdout separated from
> podman's own stderr. That task owns the stdout/stderr split; this one builds the live-streaming
> tee/capture ON TOP of the seam it establishes, so there is one Runner redesign, not two conflicting
> ones.

## What to build

Make `tooljail run` stream the wrapped tool's output as it happens, instead of capturing it all and
printing it only after the tool exits.

Today the jail runs the tool via the `Runner` interface, whose `ExecRunner.Run` calls
`CombinedOutput()` — it buffers the tool's entire stdout+stderr in memory and returns it as a
string, which `main.go`'s `runRun` prints at the end. For a scan tool that emits a single final
report this is fine, but for a long or interactive run (progress bars, per-target findings, a tool
that prompts) the user sees NOTHING until it finishes, and unbounded buffering of a chatty tool's
output is a memory footgun. A jailed tool should feel like running the tool directly: its stdout and
stderr appear live on tooljail's stdout/stderr.

The tension to resolve cleanly: the leak-test assertions and several jail tests consume the tool's
output as a returned string (e.g. the exit-IP probe parses the echoed IP from `Result.ToolStdout`).
So streaming must not break the "capture the output for assertions" path. The likely shape is a
`Runner` that can BOTH stream to the real stdout/stderr AND capture (a tee), or a run mode where the
production `run` streams while the test/verify probes capture — decided at build time, kept behind
the existing `Runner` seam so unit tests stay podman-free.

End-to-end thin path:

- The wrapped tool's stdout/stderr are written to tooljail's stdout/stderr AS THEY ARRIVE for
  `tooljail run` (no wait-until-exit, no unbounded in-memory buffer for the streamed path).
- The capture path the probes/verify rely on (`Result.ToolStdout` for assertions) keeps working —
  via a tee, or a separate capturing runner for the test/probe path.
- stdout vs stderr separation is preserved (do not merge the tool's stderr into the data a caller
  parses as stdout), which also complements the podman-failure-vs-tool-exit task.

## Acceptance criteria

- [ ] Tests written FIRST: a wrapped tool that emits output over time has that output observed
      INCREMENTALLY (e.g. a marker line is seen before the tool exits), not only after exit.
- [ ] The capture path still yields the tool's output for assertions (the exit-IP / DNS / fail-closed
      probes and `TestJail_ForcedEgress_ExitIPIsProxys` keep working against `Result.ToolStdout`).
- [ ] `tooljail run` shows the tool's stdout on stdout and stderr on stderr, live, so a jailed tool
      feels like running it directly; no unbounded buffering on the streamed path.
- [ ] The `Runner` seam stays unit-testable without podman (a fake runner can simulate streamed
      chunks); podman-dependent tests are podman-gated and leave no residue.
- [ ] Any non-obvious decision (tee vs separate runner; how stdout/stderr are split; whether verify
      keeps a pure-capture runner) is recorded per the task-template guidance.

## Blocked by

- `jail-run-forced-egress`, `run-cli-wiring` — both landed; this changes how the tool-run step's
  output is delivered, which `run` prints and the probes/verify consume.
- `distinguish-podman-failure-from-tool-exit` — it owns the `Runner` stdout/stderr-separation
  redesign this task's live tee/capture builds on; serialised so the two do not fork two conflicting
  `Runner` redesigns of the same seam.

## Prompt

> Goal: stream the wrapped tool's stdout/stderr live from `tooljail run` instead of buffering to the
> end. Read `internal/jail/jail.go` (the `Runner` interface + `ExecRunner`, which uses
> `CombinedOutput()`), `internal/jail/run.go` (the tool-run step returns `Result.ToolStdout`),
> `main.go`'s `runRun` (prints the captured output at the end), and how `internal/verify` +
> `internal/jail` integration tests parse `Result.ToolStdout` for their assertions.
>
> FIRST, check against current reality: the exit-IP / DNS / fail-closed probes assert on the RETURNED
> tool output, so streaming must not remove the capture path they depend on. Confirm which tests read
> `Result.ToolStdout` before changing the runner.
>
> Write the test FIRST: a tool that emits a marker and then keeps running has the marker OBSERVED
> before it exits (proves streaming, not buffer-then-print). Then implement: give the run path a
> Runner that streams to os.Stdout/os.Stderr while still capturing (a tee) for the probes, or split
> the production-stream vs test-capture runners. Keep stdout and stderr separate; keep the `Runner`
> seam unit-testable without podman; keep the leak-test and forced-egress probes green.
>
> "Done" means `tooljail run` shows tool output live (stdout on stdout, stderr on stderr) with no
> unbounded buffering, the capture-for-assertions path still works, and the streaming/capture design
> decision is recorded. RECORD non-obvious in-scope decisions per the task-template guidance.
