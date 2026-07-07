package jail

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// pullRunner records the podman args it is given and can return a canned
// stderr/error, so PullImage's arg shape and error wrapping are unit-testable at
// the Runner seam WITHOUT a real podman.
type pullRunner struct {
	calls  [][]string
	stderr string
	err    error
}

func (r *pullRunner) Run(_ context.Context, spec RunSpec) (string, string, error) {
	r.calls = append(r.calls, spec.Args)
	return "", r.stderr, r.err
}

// TestPullImage_IssuesPlainPodmanPull: PullImage runs exactly `podman pull <ref>`
// through the Runner (the graphroot --root is injected downstream by ExecRunner,
// NOT here), so the probe image lands in netcage's store off the HOST network,
// never through the jail/proxy.
func TestPullImage_IssuesPlainPodmanPull(t *testing.T) {
	r := &pullRunner{}
	ref := "docker.io/library/debian@sha256:deadbeef"
	if err := PullImage(context.Background(), r, ref); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("PullImage must make exactly one podman call; got %d: %v", len(r.calls), r.calls)
	}
	got := strings.Join(r.calls[0], " ")
	if got != "pull "+ref {
		t.Fatalf("PullImage args = %q, want %q", got, "pull "+ref)
	}
}

// TestPullImage_WrapsErrorWithStderr: a pull failure carries podman's own stderr
// diagnostic and names the ref, so a caller (verify's DNS check) can report it as
// a setup/network problem rather than a DNS-over-TCP verdict.
func TestPullImage_WrapsErrorWithStderr(t *testing.T) {
	r := &pullRunner{stderr: "Error: reading manifest", err: errors.New("exit status 125")}
	err := PullImage(context.Background(), r, "docker.io/library/debian@sha256:beef")
	if err == nil {
		t.Fatal("a pull failure must return an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "docker.io/library/debian@sha256:beef") {
		t.Fatalf("pull error must name the ref; got %q", msg)
	}
	if !strings.Contains(msg, "reading manifest") {
		t.Fatalf("pull error must carry podman's stderr diagnostic; got %q", msg)
	}
}
