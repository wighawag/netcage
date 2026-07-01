---
title: Distinguish a podman/runtime failure from the wrapped tool's own exit code
slug: distinguish-podman-failure-from-tool-exit
blockedBy: [jail-run-forced-egress, run-cli-wiring]
covers: []
---

> Chore (no `prd`/`covers`): a review-born refinement of the tool-run step, not the delivery of a
> prd user story. It also OWNS the `internal/jail` Runner redesign that separates the wrapped tool's
> stdout from podman's own stderr; `stream-tool-output-live` is serialised AFTER this task
> (`blockedBy` it) and builds its tee/streaming on the separated seam this task establishes, so the
> two do not fork two conflicting Runner redesigns.

## What to build

Make `tooljail run` stop mis-reporting a podman/runtime failure as the wrapped tool's exit code.

Today `internal/jail.Run`'s tool step does `errors.As(runErr, &ee)` on the podman command's error
and, for ANY `*exec.ExitError`, treats the exit code as the TOOL's result (`res.ToolExit = ...;
return res, nil`). But podman itself exits with `125` (podman/config error, e.g. image pull
failure), `126` (OCI runtime could not exec), and `127` (command not found in the image) BEFORE the
tool ever runs. Those are indistinguishable, under the current logic, from a tool that genuinely
exited 125/126/127 — so a broken image or a typo in the tool argv is silently reported as "the tool
ran and exited 125", which is wrong and hides a setup failure behind a plausible-looking tool exit.

The fix is to tell "the wrapped tool ran and exited non-zero" apart from "podman/the runtime never
got the tool running", and surface the latter as a jail/setup ERROR (non-zero tooljail exit with a
clear message), not as `ToolExit`. The signal is available: podman distinguishes these (the 125/126/
127 convention, plus its stderr), and separating the tool's stdout from podman's own stderr makes
the tool's real output unambiguous.

End-to-end thin path:

- In the tool-run step, detect the podman-level failure cases (125 config/pull, 126 runtime-exec,
  127 not-found) and return them as a jail error (`fmt.Errorf`/a sentinel), distinct from a tool
  non-zero exit which still flows to `Result.ToolExit`.
- A wrapped tool that legitimately exits 125/126/127 for its OWN reasons must STILL propagate that
  as `ToolExit` once podman confirms the container actually started the tool. (If the only available
  signal is the exit code, document the residual ambiguity and prefer the reading that does not hide
  a setup failure; capturing podman's stderr separately from the tool's stdout removes most of the
  ambiguity.)
- `tooljail run` then exits with the tool's code for a real tool exit, and a clear non-zero setup
  error (with podman's diagnostic) for a runtime/pull failure.

## Acceptance criteria

- [ ] Tests written FIRST: a run whose IMAGE is unpullable/invalid returns a jail SETUP error (not a
      `ToolExit` of 125), and `tooljail run` exits non-zero with a clear message naming the
      image/runtime failure.
- [ ] A run whose tool COMMAND is not found in the image (podman 127) is reported as a setup/exec
      failure, not silently as "tool exited 127".
- [ ] A wrapped tool that itself exits non-zero (including 125/126/127 for its own reasons, once the
      container started it) STILL propagates that code as `Result.ToolExit` / tooljail's exit code
      (the existing `TestJail_PropagatesToolExitCode` contract must not regress).
- [ ] The decision (how podman-failure vs tool-exit is told apart, and any residual ambiguity) is
      recorded per the task-template guidance (a `## Decisions` note or an ADR if it meets the gate).
- [ ] Tests cover the new behaviour; the podman-dependent cases are podman-gated (t.Skip without
      podman) and leave no residue; pure-logic cases (classifying an exit code / error) need no
      podman.

## Blocked by

- `jail-run-forced-egress`, `run-cli-wiring` — both landed; this refines the tool-run step of
  `jail.Run` and the exit-code propagation `run` relies on.

## Prompt

> Goal: stop `tooljail run` from reporting a podman/runtime failure as the wrapped tool's exit code.
> Read `internal/jail/run.go` (the tool-run step: `errors.As(runErr, &ee)` -> `res.ToolExit`),
> `internal/jail/jail.go` (the `Runner` interface + `ExecRunner`, which currently returns combined
> stdout+stderr), and the done records of `jail-run-forced-egress` + `run-cli-wiring`. Podman exits
> 125 (config/pull error), 126 (runtime could not exec), 127 (command not found) BEFORE the tool
> runs; those must be jail SETUP errors, not `ToolExit`.
>
> FIRST, check against current reality: confirm the tool-run step still classifies every ExitError
> as the tool's result, and that `TestJail_PropagatesToolExitCode` pins the propagation contract you
> must not break.
>
> Write the test FIRST: an unpullable `--image` yields a jail setup error and a clear non-zero
> `tooljail run` exit, NOT a `ToolExit` of 125. Then wire the classification. Consider separating
> podman's own stderr from the tool's stdout in the `Runner` (or a variant) so the tool's real output
> and a real tool exit are unambiguous; keep `TestJail_PropagatesToolExitCode` green.
>
> "Done" means a broken image / missing tool command is surfaced as a setup failure with podman's
> diagnostic, a genuine tool non-zero exit still propagates, and the classification decision (plus any
> residual exit-code ambiguity) is recorded. RECORD non-obvious in-scope decisions per the
> task-template guidance.

## Decisions

**Runner seam redesign (owned by this task).** `jail.Runner.Run` changed from
`Run(ctx, name, args...) (stdout string, err error)` (which used `CombinedOutput()`, MERGING stdout
and stderr) to `Run(ctx, RunSpec) (stdout, stderr string, err error)`. `RunSpec` carries the command
plus OPTIONAL `Stdout`/`Stderr` `io.Writer` live sinks (a tee). `ExecRunner` now uses separate
`bytes.Buffer`s (via `io.MultiWriter` when a live sink is set), so stdout and stderr are captured
separately and never merged. This is the single Runner shape the serialised `stream-tool-output-live`
task reuses (it only wires the live sinks; it does not re-fork the interface). The internal podman
call sites (sidecar start, inspect, teardown, reachback) use a terse `runPodman` capture-only helper;
only the tool-run step needs the separated stderr and (later) the live sinks.

**How a podman/runtime SETUP failure is told apart from a tool's own exit.** Podman writes ITS own
setup diagnostic to STDERR prefixed with `Error:` (unpullable image, unknown flag), and the OCI
runtime's exec/not-found failures surface there too (`OCI runtime`, `crun:`, `executable file ... not
found`, `reading manifest`/`manifest unknown`). Because the tool-run step now captures podman's
stderr SEPARATELY from the tool's stdout, a setup diagnostic on podman's stderr is an unambiguous
podman-level failure. `classifyPodmanSetupFailure(code, podmanStderr)` returns a jail setup error
(wrapping the new sentinel `jail.ErrJailSetup`, carrying podman's diagnostic line) ONLY when the exit
code is 125/126/127 AND podman's stderr matches one of those setup markers; otherwise the exit code
flows to `Result.ToolExit` as before. `tooljail run` already exits non-zero (1) with the stderr
message on any jail error, so a broken image / missing command now exits 1 with podman's diagnostic
rather than a bogus `exit 125`.

**Residual exit-code ambiguity, and how it is resolved.** A wrapped tool could itself legitimately
exit 125/126/127. The exit code alone cannot disambiguate, so the classifier requires BOTH the
code AND a podman/runtime setup diagnostic on podman's own stderr. A bare 125/126/127 with no such
diagnostic (e.g. a shell that exits 127 because ITS OWN inner subcommand was not found, printing
`sh: ...: not found` rather than podman's `Error:`) is treated as the tool's exit and propagates to
`ToolExit`. This deliberately biases toward NOT hiding a setup failure while keeping
`TestJail_PropagatesToolExitCode` (a genuine `exit 42`) green; the narrow theoretical case (a tool
that exits 125/126/127 AND prints a line that looks exactly like a podman/runtime setup diagnostic to
stderr) would be misclassified, which is an acceptable, documented trade-off given the separated-
stderr signal makes it very unlikely in practice.

Not recorded as an ADR: this is an internal classification heuristic on the tool-run step, cheaply
reversible and not an architectural/lock-in decision, so it fails the ADR gate (hard-to-reverse +
surprising + real trade-off with lasting cost). It lives here per the task-template guidance instead.
