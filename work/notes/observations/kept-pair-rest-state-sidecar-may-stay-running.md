# Kept pair at rest: sidecar may stay RUNNING while the tool is stopped

2026-07-03 (noticed during exec-fidelity task)

CONTEXT.md's glossary says a KEPT run "LEAVES the stopped tool container and its
stopped sidecar behind", but `jail.Teardown` does NOTHING for a kept run
(`if !cfg.Ephemeral { return nil }` in `internal/jail/run.go`). The tool container
stops because its process (`true`) exits, but nothing stops the tun2socks SIDECAR,
so at rest a kept pair can be `tool=stopped, sidecar=running` (observed live in a
podman integration run). The glossary wording "both stopped" appears to be
aspirational / drifted from the actual teardown behaviour. Not fixing here (out of
scope for the exec task); capturing the drift between the glossary and
`Teardown`'s kept-run no-op.
