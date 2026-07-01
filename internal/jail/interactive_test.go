package jail

import (
	"strings"
	"testing"

	"github.com/wighawag/tooljail/internal/cli"
)

// TestInteractive_SameSidecarAndNftAsPlainRun pins the topology-IDENTITY
// invariant at the pure-wiring boundary (no podman): the sidecar args and the nft
// ruleset for an interactive-flagged config are BYTE-IDENTICAL to a plain run's
// (interactivity must change ONLY the tool's -it/stdio, never the network jail).
// The podman-gated integration test proves it stands up for real; this locks that
// the ONLY difference in the whole jail wiring is the tool container's -it.
func TestInteractive_SameSidecarAndNftAsPlainRun(t *testing.T) {
	base := Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"bash"},
		RunID:               "topo",
	}
	iact := base
	iact.Interactive = true

	if got, want := strings.Join(iact.SidecarRunArgs(), " "), strings.Join(base.SidecarRunArgs(), " "); got != want {
		t.Fatalf("interactive sidecar args differ from plain run's; the forced-egress topology must be identical\ninteractive: %s\nplain:       %s", got, want)
	}
	if got, want := iact.nftRuleset("9050"), base.nftRuleset("9050"); got != want {
		t.Fatalf("interactive nft ruleset differs from plain run's; UDP-drop / reachback-narrowing must be identical\ninteractive:\n%s\nplain:\n%s", got, want)
	}
}

// TestToolRunArgs_InteractiveAddsIT proves that an interactive run adds podman's
// -it to the tool container args (a TTY + stdin attached), while a non-interactive
// run does NOT, so `-it` is opt-in and only for the interactive path.
func TestToolRunArgs_InteractiveAddsIT(t *testing.T) {
	c := cfg()
	c.Interactive = true
	found := false
	for _, a := range c.ToolRunArgs() {
		if a == "-it" {
			found = true
		}
	}
	if !found {
		t.Fatalf("interactive tool args must include -it (TTY + stdin); got: %s", strings.Join(c.ToolRunArgs(), " "))
	}

	c2 := cfg()
	c2.Interactive = false
	for _, a := range c2.ToolRunArgs() {
		if a == "-it" {
			t.Fatalf("non-interactive tool args must NOT include -it; got: %s", strings.Join(c2.ToolRunArgs(), " "))
		}
	}
}

// TestToolRunSpec_InteractiveWiresStdinBypassesCaptureTee proves the run-mode
// seam WITHOUT podman: the tool-run RunSpec the jail builds carries Interactive +
// a Stdin and does NOT attach the capture-tee live sinks in interactive mode (raw
// passthrough, no capture), whereas the non-interactive spec leaves Stdin nil and
// keeps the live-sink capture/tee path. This is the boundary a fake runner would
// observe; asserting the spec directly keeps it podman-free (jail.Run's real
// nft/nsenter steps need a host, the spec construction does not).
func TestToolRunSpec_InteractiveWiresStdinBypassesCaptureTee(t *testing.T) {
	stdin := strings.NewReader("keystrokes")
	var sink strings.Builder

	t.Run("interactive: stdin wired, capture tee bypassed", func(t *testing.T) {
		c := cfg()
		c.Interactive = true
		c.ToolStdin = stdin
		// Even if live sinks are set, interactive must ignore them (podman owns the
		// container PTY; tooljail does raw stdio passthrough, no capture tee).
		c.ToolStdout = &sink
		c.ToolStderr = &sink
		spec := c.toolRunSpec()
		if !spec.Interactive {
			t.Fatal("interactive run must set RunSpec.Interactive on the tool-run step")
		}
		if spec.Stdin == nil {
			t.Fatal("interactive run must wire a Stdin into the tool-run RunSpec")
		}
		if spec.Stdout != nil || spec.Stderr != nil {
			t.Fatal("interactive run must NOT attach the capture-tee live sinks (raw passthrough, no capture)")
		}
	})

	t.Run("non-interactive: keeps the capture/tee sinks, no stdin", func(t *testing.T) {
		c := cfg()
		c.Interactive = false
		c.ToolStdin = stdin // must be ignored when not interactive
		c.ToolStdout = &sink
		c.ToolStderr = &sink
		spec := c.toolRunSpec()
		if spec.Interactive {
			t.Fatal("non-interactive run must NOT set RunSpec.Interactive")
		}
		if spec.Stdin != nil {
			t.Fatal("non-interactive run must not wire stdin (capture-only / tee path)")
		}
		if spec.Stdout == nil || spec.Stderr == nil {
			t.Fatal("non-interactive run must keep the live-sink capture/tee wiring")
		}
	})
}

// TestExecRunner_InteractiveRawPassthroughNoCapture proves the ExecRunner side of
// the seam without podman: in interactive mode the runner does RAW passthrough,
// so it does NOT capture the command's stdout into the returned string (the raw
// stdio is connected straight through; capture is deliberately bypassed). A tiny
// `sh` command stands in for the tool; skipped if sh is unusable.
func TestExecRunner_InteractiveRawPassthroughNoCapture(t *testing.T) {
	var out strings.Builder
	stdout, _, err := ExecRunner{}.Run(t.Context(), RunSpec{
		Name:        "sh",
		Args:        []string{"-c", "echo raw-output"},
		Interactive: true,
		// A live sink present here must be IGNORED in interactive raw mode, and
		// nothing captured into the returned stdout string.
		Stdout: &out,
	})
	if err != nil {
		t.Skipf("sh not usable in this environment: %v", err)
	}
	if stdout != "" {
		t.Fatalf("interactive raw mode must not capture stdout into the returned string; got %q", stdout)
	}
}
