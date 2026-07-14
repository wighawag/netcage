# CLI grammar switched to positional podman-native shape

2026-07-01: The `podman-shaped-cli-flag-parsing` task replaced `netcage run`'s
old grammar (`--image <img> ... -- <tool argv>`) with podman-native positional
grammar (`run [flags] <image> [<cmd>...]`, no `--image`, no `--` separator). The
`internal/cli` code, its tests, and the `main.go` usage banner are updated, but
the PARENT prd `work/specs/.../netcage.md` (story 1 shows `--image nuclei --
nuclei -u ...`) and any README still document the old shape. A later doc pass
should reconcile the parent prd/README prose to the new positional grammar. This
drift is expected and out of scope for the CLI task; recorded here so it is not
silently left.

## Resolved 2026-07-01

The doc pass is done. `work/specs/tasked/netcage.md` (the "One command shape"
block + story 1) now shows the positional grammar; `work/specs/tasked/jailed-interactive-repo-run.md`
story 10 dropped the `--image` override phrasing and its Problem Statement is
marked as a launch snapshot whose old grammar has since been replaced. There is
no README at the repo root. ADR-0004's `--image` mention is left intact (it is
decision-context explaining the grammar it operates under, not stale usage). The
drift signal is discharged; this note can be deleted by a human when convenient
(git history is the archive).
