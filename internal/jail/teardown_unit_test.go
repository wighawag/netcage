package jail

import (
	"context"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

// recordRunner records every podman invocation Teardown makes, so the
// remove-both-vs-leave-both split is unit-testable at the Runner seam WITHOUT a
// real podman (mirrors how the jail wiring is tested podman-free elsewhere).
type recordRunner struct{ calls [][]string }

func (r *recordRunner) Run(_ context.Context, spec RunSpec) (string, string, error) {
	r.calls = append(r.calls, spec.Args)
	return "", "", nil
}

func teardownCfg(ephemeral bool) Config {
	return Config{
		Proxy:     cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
		Image:     "docker.io/library/alpine:latest",
		ToolArgv:  []string{"true"},
		RunID:     "td01",
		Ephemeral: ephemeral,
	}
}

// TestTeardown_RemovesBothOnEphemeralLeavesBothOnKept pins the jail-lifecycle
// split at the Runner seam: an EPHEMERAL run (Ephemeral=true: the netcage `--rm`
// flag and every internal one-shot) removes BOTH the tool and the sidecar (no
// residue, as today). A KEPT run (Ephemeral=false: a plain `netcage run`) removes
// NEITHER, leaving the stopped tool + sidecar behind (the podman-fidelity
// feature; the pair is fail-closed via the baked EXTRA_COMMANDS firewall).
//
// "Remove the sidecar but keep the tool" is NOT reachable (the `--network
// container:` edge blocks removing the sidecar while the tool exists, and
// `--depend` cascades to the tool - see the finding), so the only two coherent
// end-states are both-gone (ephemeral) and both-kept (kept).
func TestTeardown_RemovesBothOnEphemeralLeavesBothOnKept(t *testing.T) {
	t.Run("ephemeral removes both tool and sidecar", func(t *testing.T) {
		c := teardownCfg(true)
		r := &recordRunner{}
		if err := Teardown(context.Background(), r, c); err != nil {
			t.Fatalf("Teardown (ephemeral): %v", err)
		}
		joined := joinAll(r.calls)
		for _, want := range []string{c.toolName(), c.sidecarName()} {
			if !strings.Contains(joined, "rm -f -i "+want) {
				t.Fatalf("ephemeral teardown must rm -f both containers; missing %q\ncalls: %s", want, joined)
			}
		}
	})

	t.Run("kept removes neither (leaves both behind)", func(t *testing.T) {
		c := teardownCfg(false)
		r := &recordRunner{}
		if err := Teardown(context.Background(), r, c); err != nil {
			t.Fatalf("Teardown (kept): %v", err)
		}
		if len(r.calls) != 0 {
			t.Fatalf("kept teardown must NOT remove the tool or sidecar (leave both behind); got podman calls: %s", joinAll(r.calls))
		}
	})
}

func joinAll(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}
