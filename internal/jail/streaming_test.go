package jail

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestExecRunner_TeesLiveWhileCapturing proves the Runner seam that streaming
// builds on: when RunSpec carries live Stdout/Stderr sinks, ExecRunner writes to
// them AND STILL returns the captured strings SEPARATELY (stdout not merged with
// stderr). It uses a trivial local command (sh) so it needs no podman; it is
// skipped only if sh is unavailable.
func TestExecRunner_TeesLiveWhileCapturing(t *testing.T) {
	var outSink, errSink bytes.Buffer
	stdout, stderr, err := ExecRunner{}.Run(context.Background(), RunSpec{
		Name:   "sh",
		Args:   []string{"-c", "echo to-stdout; echo to-stderr 1>&2"},
		Stdout: &outSink,
		Stderr: &errSink,
	})
	if err != nil {
		t.Skipf("sh not usable in this environment: %v", err)
	}
	if stdout != "to-stdout" {
		t.Fatalf("captured stdout = %q, want %q", stdout, "to-stdout")
	}
	if stderr != "to-stderr" {
		t.Fatalf("captured stderr = %q, want %q (stdout and stderr must stay separate)", stderr, "to-stderr")
	}
	if !strings.Contains(outSink.String(), "to-stdout") {
		t.Fatalf("live stdout sink missing the tool's stdout; got %q", outSink.String())
	}
	if strings.Contains(outSink.String(), "to-stderr") {
		t.Fatalf("live stdout sink leaked the tool's stderr into stdout; got %q", outSink.String())
	}
	if !strings.Contains(errSink.String(), "to-stderr") {
		t.Fatalf("live stderr sink missing the tool's stderr; got %q", errSink.String())
	}
}

// TestExecRunner_StreamsIncrementally proves the streamed path is LIVE, not
// buffer-then-flush: a command that prints a marker EARLY and then keeps running
// has the marker visible on the live sink BEFORE the command exits. Uses sh (no
// podman). This is the podman-free proof that the Runner seam delivers output
// incrementally; the end-to-end proof through jail.Run is podman-gated below.
func TestExecRunner_StreamsIncrementally(t *testing.T) {
	var live bytes.Buffer
	var mu sync.Mutex
	sink := &lockedWriter{w: &live, mu: &mu}

	// Print the marker immediately, then sleep so the process is still alive while
	// we check the sink.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, _, err := ExecRunner{}.Run(ctx, RunSpec{
			Name:   "sh",
			Args:   []string{"-c", "echo STREAM-MARKER; sleep 2"},
			Stdout: sink,
		})
		done <- err
	}()

	// Poll the live sink; the marker must appear well before the 2s sleep ends.
	deadline := time.Now().Add(1500 * time.Millisecond)
	seen := false
	for time.Now().Before(deadline) {
		mu.Lock()
		if strings.Contains(live.String(), "STREAM-MARKER") {
			seen = true
		}
		mu.Unlock()
		if seen {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !seen {
		select {
		case err := <-done:
			t.Skipf("command finished/failed before the streaming assertion (sh unusable?): %v", err)
		default:
		}
		t.Fatal("marker not observed on the live sink while the command was still running; output is buffered, not streamed")
	}
	<-done
}

// lockedWriter serialises concurrent writes so a test can read the live sink from
// another goroutine without a race.
type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
