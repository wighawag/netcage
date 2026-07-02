package cli_test

import (
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/devimage"
)

// These tests own the default-dev-image + repo-mount ergonomics behaviour:
// making `netcage run` useful out of the box when the user does not spell out an
// image or a workdir. They are pure-logic (no podman): they assert on the parsed
// + resolved Command the jail consumes.

// TestParse_NoImageInjectsPinnedDefault checks that with NO positional image at
// all, the resolved run uses the pinned default dev image with an EMPTY argv (the
// image's own default command runs). Under podman-native grammar the default
// image applies ONLY when no image positional is given (`run -it` with no
// positional), never as a guess about a bare command-shaped token.
func TestParse_NoImageInjectsPinnedDefault(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "-it", "--proxy", "socks5h://127.0.0.1:9050",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Image != devimage.ImageReference() {
		t.Fatalf("Image = %q, want the pinned default dev image %q", cmd.Image, devimage.ImageReference())
	}
	if len(cmd.ToolArgv) != 0 {
		t.Fatalf("ToolArgv = %v, want empty (no positional => default image's own command runs)", cmd.ToolArgv)
	}
}

// TestParse_FirstPositionalIsAlwaysTheImage checks the podman-native rule: the
// first positional is the image with NO guessing, so a bare-token image needs no
// `--` marker. `run alpine sh` => image `alpine`, command `sh`. This is the
// behaviour that replaced the old image-vs-command heuristic (which forced
// `run -- alpine sh`).
func TestParse_FirstPositionalIsAlwaysTheImage(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1", "-it", "alpine", "sh",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Image != "alpine" {
		t.Fatalf("Image = %q, want alpine (the first positional is ALWAYS the image, no marker needed)", cmd.Image)
	}
	if strings.Join(cmd.ToolArgv, " ") != "sh" {
		t.Fatalf("ToolArgv = %v, want [sh]", cmd.ToolArgv)
	}
}

// TestParse_DefaultImageIsDigestPinned mirrors the redirector-pin assertion at
// the CLI seam: the injected default image (used when no positional is given) is
// pinned by an @sha256: digest, never a mutable tag.
func TestParse_DefaultImageIsDigestPinned(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(cmd.Image, "@sha256:") {
		t.Fatalf("default image %q is not digest-pinned; the injected default must be immutable", cmd.Image)
	}
}

// TestParse_ExplicitImageOverridesDefault checks that an explicit image reference
// is used as-is and is NOT replaced by the default.
func TestParse_ExplicitImageOverridesDefault(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1", "docker.io/library/alpine:latest", "sh",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Image != "docker.io/library/alpine:latest" {
		t.Fatalf("Image = %q, want the explicit image (default must NOT override)", cmd.Image)
	}
	if strings.Join(cmd.ToolArgv, " ") != "sh" {
		t.Fatalf("ToolArgv = %v, want [sh]", cmd.ToolArgv)
	}
}

// TestParse_TaggedImageAndCommand checks a bare `repo:tag` image is the image and
// the rest is the command (nothing special about the tag now; the first
// positional is always the image).
func TestParse_TaggedImageAndCommand(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1", "python:3.12", "python", "--version",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Image != "python:3.12" {
		t.Fatalf("Image = %q, want python:3.12", cmd.Image)
	}
	wantArgv := []string{"python", "--version"}
	if strings.Join(cmd.ToolArgv, " ") != strings.Join(wantArgv, " ") {
		t.Fatalf("ToolArgv = %v, want %v", cmd.ToolArgv, wantArgv)
	}
}

// TestParse_RepoMountDefaultsWorkdirToWork checks the repo-mount ergonomic: with a
// mount targeting /work and NO -w, the resolved workdir is /work (a repo dropped
// in is worked in without hand-writing -w).
func TestParse_RepoMountDefaultsWorkdirToWork(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "-it", "-v", "/home/me/repo:/work", "--proxy", "socks5h://h:1", "bash",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Workdir != "/work" {
		t.Fatalf("Workdir = %q, want /work (a mount targeting /work with no -w defaults the workdir there)", cmd.Workdir)
	}
}

// TestParse_BareRepoMountDefaultsTargetAndWorkdir checks the "bare repo path"
// shorthand: a -v value with no :container part defaults its target to /work and
// the workdir to /work, so `-v <repo>` lands you in the repo.
func TestParse_BareRepoMountDefaultsTargetAndWorkdir(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "-it", "-v", "/home/me/repo", "--proxy", "socks5h://h:1", "bash",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.Join(cmd.Mounts, " ") != "/home/me/repo:/work" {
		t.Fatalf("Mounts = %v, want [/home/me/repo:/work] (a bare -v repo path defaults its target to /work)", cmd.Mounts)
	}
	if cmd.Workdir != "/work" {
		t.Fatalf("Workdir = %q, want /work (a bare repo mount defaults the workdir to /work)", cmd.Workdir)
	}
}

// TestParse_ExplicitWorkdirOverridesRepoMountDefault checks an explicit -w wins
// over the /work default even when a repo is mounted at /work.
func TestParse_ExplicitWorkdirOverridesRepoMountDefault(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "-v", "/home/me/repo:/work", "-w", "/work/subdir", "--proxy", "socks5h://h:1", "bash",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Workdir != "/work/subdir" {
		t.Fatalf("Workdir = %q, want /work/subdir (an explicit -w must override the /work default)", cmd.Workdir)
	}
}

// TestParse_NoMountNoWorkdirLeavesWorkdirUnset checks we do NOT invent a workdir
// when the user mounts nothing at /work: the ergonomic only fires for a repo
// mount, so a plain `run <image> <cmd>` keeps the image's own default workdir.
func TestParse_NoMountNoWorkdirLeavesWorkdirUnset(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "--proxy", "socks5h://h:1", "docker.io/library/alpine:latest", "sh",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Workdir != "" {
		t.Fatalf("Workdir = %q, want empty (no repo mount => no invented workdir)", cmd.Workdir)
	}
}

// TestParse_DefaultImageWithNoCommand checks that `run` with a repo mount and no
// positional at all injects the default image and leaves the command empty (the
// image's own default command / entrypoint runs, e.g. a shell for an interactive
// dev base).
func TestParse_DefaultImageWithNoCommand(t *testing.T) {
	cmd, err := cli.ParseWithEnv([]string{
		"run", "-it", "-v", "/home/me/repo:/work", "--proxy", "socks5h://h:1",
	}, noEnv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Image != devimage.ImageReference() {
		t.Fatalf("Image = %q, want the pinned default dev image", cmd.Image)
	}
	if len(cmd.ToolArgv) != 0 {
		t.Fatalf("ToolArgv = %v, want empty (no command => the image's default command runs)", cmd.ToolArgv)
	}
}
