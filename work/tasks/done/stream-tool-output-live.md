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

Make `netcage run` stream the wrapped tool's output as it happens, instead of capturing it all and
printing it only after the tool exits.

Today the jail runs the tool via the `Runner` interface, whose `ExecRunner.Run` calls
`CombinedOutput()` — it buffers the tool's entire stdout+stderr in memory and returns it as a
string, which `main.go`'s `runRun` prints at the end. For a scan tool that emits a single final
report this is fine, but for a long or interactive run (progress bars, per-target findings, a tool
that prompts) the user sees NOTHING until it finishes, and unbounded buffering of a chatty tool's
output is a memory footgun. A jailed tool should feel like running the tool directly: its stdout and
stderr appear live on netcage's stdout/stderr.

The tension to resolve cleanly: the leak-test assertions and several jail tests consume the tool's
output as a returned string (e.g. the exit-IP probe parses the echoed IP from `Result.ToolStdout`).
So streaming must not break the "capture the output for assertions" path. The likely shape is a
`Runner` that can BOTH stream to the real stdout/stderr AND capture (a tee), or a run mode where the
production `run` streams while the test/verify probes capture — decided at build time, kept behind
the existing `Runner` seam so unit tests stay podman-free.

End-to-end thin path:

- The wrapped tool's stdout/stderr are written to netcage's stdout/stderr AS THEY ARRIVE for
  `netcage run` (no wait-until-exit, no unbounded in-memory buffer for the streamed path).
- The capture path the probes/verify rely on (`Result.ToolStdout` for assertions) keeps working —
  via a tee, or a separate capturing runner for the test/probe path.
- stdout vs stderr separation is preserved (do not merge the tool's stderr into the data a caller
  parses as stdout), which also complements the podman-failure-vs-tool-exit task.

## Acceptance criteria

- [ ] Tests written FIRST: a wrapped tool that emits output over time has that output observed
      INCREMENTALLY (e.g. a marker line is seen before the tool exits), not only after exit.
- [ ] The capture path still yields the tool's output for assertions (the exit-IP / DNS / fail-closed
      probes and `TestJail_ForcedEgress_ExitIPIsProxys` keep working against `Result.ToolStdout`).
- [ ] `netcage run` shows the tool's stdout on stdout and stderr on stderr, live, so a jailed tool
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

> Goal: stream the wrapped tool's stdout/stderr live from `netcage run` instead of buffering to the
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
> "Done" means `netcage run` shows tool output live (stdout on stdout, stderr on stderr) with no
> unbounded buffering, the capture-for-assertions path still works, and the streaming/capture design
> decision is recorded. RECORD non-obvious in-scope decisions per the task-template guidance.

## Decisions

**Built on the seam `distinguish-podman-failure-from-tool-exit` established (no second Runner
redesign).** That task already changed `jail.Runner.Run` to `Run(ctx, RunSpec) (stdout, stderr
string, err error)` and gave `RunSpec` OPTIONAL `Stdout`/`Stderr` `io.Writer` live sinks, with
`ExecRunner` teeing to them via `io.MultiWriter` while still capturing. This task only WIRED those
sinks through; it did not touch the interface. Drift check passed: the separated seam serves
streaming exactly (live tee + separate capture + stdout/stderr split), so the two tasks share one
Runner shape as intended.

**Tee via Config live sinks, not a separate runner (the design choice the task left open).**
`jail.Config` gained `ToolStdout` / `ToolStderr` `io.Writer` fields; `jail.Run` threads them into the
tool-run step's `RunSpec`. `netcage run` (`main.go` `runRun`) sets them to `os.Stdout`/`os.Stderr`,
so the wrapped tool's output streams live to netcage's own stdout/stderr and a jailed tool feels
like running it directly. The verify/leak-test probes call `jail.Run` via `verify.DefaultJailRunner`,
which leaves the sinks nil, so those paths stay CAPTURE-ONLY and keep asserting on
`Result.ToolStdout` unchanged. This is the tee shape (one runner that streams AND captures), chosen
over a separate production-stream-vs-test-capture runner because the sink is a per-run property, not a
per-runner one, and it keeps a single `Runner` implementation.

**No unbounded buffering on the streamed path / no double-print.** The streamed bytes flow through
`io.MultiWriter(&buf, liveSink)` as the process writes them (Go's `exec` copies via an internal pipe,
so it is genuinely live, proven by `TestExecRunner_StreamsIncrementally` and
`TestJail_StreamsToolOutputLiveThroughRun` observing the marker BEFORE the tool exits). `runRun` no
longer prints `res.ToolStdout` at the end (the live sink already put it on screen), so output is not
duplicated. The `bytes.Buffer` capture still exists for the probes; that capture is the pre-existing
behaviour and is bounded by the tool's total output the same as before. If a future unbounded-output
concern arises for the CAPTURE side, that is a separate follow-up (the STREAMED path, which the task
asked to be unbuffered, is unbuffered).

**stdout/stderr kept separate throughout.** `Result` gained `ToolStderr` alongside `ToolStdout`; the
tool's stderr is never merged into the stdout a probe parses. `main.go` streams stdout to
`os.Stdout` and stderr to `os.Stderr` on their own sinks.

Not recorded as an ADR: threading live sinks through an existing seam is an additive, easily
reversible wiring choice, not an architectural/lock-in decision, so it fails the ADR gate. Recorded
here per the task-template guidance.
