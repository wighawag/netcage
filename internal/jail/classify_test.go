package jail

import (
	"errors"
	"strings"
	"testing"
)

// TestClassifyPodmanSetupFailure_UnpullableImageIsSetupNotToolExit: podman exits
// 125 with a pull/manifest diagnostic on ITS stderr when the image cannot be
// pulled. That is a jail SETUP failure, not the tool exiting 125 for its own
// reasons.
func TestClassifyPodmanSetupFailure_UnpullableImageIsSetupNotToolExit(t *testing.T) {
	stderr := "Trying to pull docker.io/library/nope:nope...\n" +
		"Error: initializing source docker://nope:nope: reading manifest nope in docker.io/library/nope: requested access to the resource is denied"
	err := classifyPodmanSetupFailure(125, stderr)
	if err == nil {
		t.Fatal("an unpullable image (podman 125 + pull diagnostic) must be a jail setup error, not a tool exit")
	}
	if !errors.Is(err, ErrJailSetup) {
		t.Fatalf("setup failure must wrap ErrJailSetup; got %v", err)
	}
	if !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("setup error must carry podman's diagnostic; got %v", err)
	}
}

// TestClassifyPodmanSetupFailure_CommandNotFoundIsSetup: podman/crun exit 127
// with "executable file ... not found" is a setup/exec failure, not "the tool
// exited 127".
func TestClassifyPodmanSetupFailure_CommandNotFoundIsSetup(t *testing.T) {
	stderr := "Error: crun: executable file `nope` not found in $PATH: No such file or directory: OCI runtime attempted to invoke a command that was not found"
	err := classifyPodmanSetupFailure(127, stderr)
	if err == nil {
		t.Fatal("a command-not-found (podman 127 + OCI runtime diagnostic) must be a setup/exec failure")
	}
	if !errors.Is(err, ErrJailSetup) {
		t.Fatalf("setup failure must wrap ErrJailSetup; got %v", err)
	}
}

// TestClassifyPodmanSetupFailure_RuntimeExecFailureIsSetup: podman 126 (OCI
// runtime could not exec) with a runtime diagnostic is a setup failure.
func TestClassifyPodmanSetupFailure_RuntimeExecFailureIsSetup(t *testing.T) {
	stderr := "Error: OCI runtime error: crun: cannot exec: Permission denied"
	err := classifyPodmanSetupFailure(126, stderr)
	if err == nil {
		t.Fatal("a runtime exec failure (podman 126 + OCI runtime diagnostic) must be a setup failure")
	}
}

// TestClassifyPodmanSetupFailure_ToolExit42IsNotSetup: a genuine tool exit (42)
// is never a setup failure, whatever its stderr. This backs the
// TestJail_PropagatesToolExitCode contract at the pure-logic boundary.
func TestClassifyPodmanSetupFailure_ToolExit42IsNotSetup(t *testing.T) {
	if err := classifyPodmanSetupFailure(42, ""); err != nil {
		t.Fatalf("a tool exiting 42 must not be a setup failure; got %v", err)
	}
	if err := classifyPodmanSetupFailure(42, "Error: something the tool printed"); err != nil {
		t.Fatalf("only 125/126/127 can be a podman setup failure; 42 must pass through as a tool exit; got %v", err)
	}
}

// TestClassifyPodmanSetupFailure_ToolExits127ForItsOwnReasons: a wrapped tool
// that RAN and exited 127 for its OWN reasons (no podman/runtime setup
// diagnostic on stderr) must NOT be reclassified as a setup failure. This is the
// residual-ambiguity resolution: without a podman setup diagnostic, the exit is
// the tool's. Guards TestJail_PropagatesToolExitCode against over-eager
// reclassification.
func TestClassifyPodmanSetupFailure_ToolExits127ForItsOwnReasons(t *testing.T) {
	// A shell that exits 127 because ITS OWN subcommand was not found prints its
	// own message (no podman "Error:" / "OCI runtime" prefix on podman's stderr).
	toolStderr := "sh: some-inner-command: not found"
	if err := classifyPodmanSetupFailure(127, toolStderr); err != nil {
		t.Fatalf("a tool that ran and exited 127 for its own reasons (no podman setup diagnostic) must propagate as ToolExit, not a setup error; got %v", err)
	}
}

func TestPodmanSetupDiagnostic_DetectsPodmanFaults(t *testing.T) {
	faults := map[string]string{
		"podman error prefix":   "Error: unknown flag: --nope",
		"oci runtime not found": "Error: OCI runtime attempted to invoke a command that was not found",
		"crun executable":       "Error: crun: executable file `x` not found in $PATH",
		"pull manifest":         "Error: reading manifest nope in docker.io/library/x: manifest unknown",
	}
	for name, s := range faults {
		if podmanSetupDiagnostic(s) == "" {
			t.Errorf("%s: expected a non-empty setup diagnostic for %q", name, s)
		}
	}
}

func TestPodmanSetupDiagnostic_IgnoresPlainToolOutput(t *testing.T) {
	for _, s := range []string{"", "some normal tool warning on stderr", "failed to connect to host"} {
		if d := podmanSetupDiagnostic(s); d != "" {
			t.Errorf("plain tool stderr %q must not read as a podman setup diagnostic; got %q", s, d)
		}
	}
}
