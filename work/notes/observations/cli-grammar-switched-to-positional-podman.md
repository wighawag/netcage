# CLI grammar switched to positional podman-native shape

2026-07-01: The `podman-shaped-cli-flag-parsing` task replaced `tooljail run`'s
old grammar (`--image <img> ... -- <tool argv>`) with podman-native positional
grammar (`run [flags] <image> [<cmd>...]`, no `--image`, no `--` separator). The
`internal/cli` code, its tests, and the `main.go` usage banner are updated, but
the PARENT prd `work/prds/.../tooljail.md` (story 1 shows `--image nuclei --
nuclei -u ...`) and any README still document the old shape. A later doc pass
should reconcile the parent prd/README prose to the new positional grammar. This
drift is expected and out of scope for the CLI task; recorded here so it is not
silently left.
