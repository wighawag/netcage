// Package forward implements netcage's host-access verb (ADR-0014): `netcage
// forward <container> <port>` stands up ONE host `<bind>:<port>` -> in-jail
// `<port>` INBOUND forward on demand, holds it for the verb's lifetime, and tears
// it down when the verb ends. It is the netcage analogue of `kubectl
// port-forward` / `ssh -L`: an explicit, out-of-band, auditable action, NOT a
// property of the run.
//
// The MECHANISM is the recipe the socat-forward spike proved
// (work/notes/findings/spike-socat-forward-host-to-jail-loopback.md, "Shape B"):
// a HOST-side `socat` listener binding <bind> whose EXEC connect side reaches the
// in-jail server via `podman --root <graphroot> exec -i <tool> <connector>
// 127.0.0.1 <port>`. The listener runs on the HOST (it binds the HOST's
// loopback, not the container's), and only the connect side enters the shared
// netns via podman exec (ADR-0006 faithful: podman is the only host dependency,
// never host nsenter).
//
// Load-bearing guardrails (all from ADR-0014 / ADR-0013 / ADR-0003):
//
//   - Loopback by DEFAULT. The bare verb binds 127.0.0.1, so nothing off-box can
//     reach the jailed tool's server. `--bind 0.0.0.0` is a SEPARATE, louder,
//     explicitly-flagged opt-in: it prints a WARNING naming what it exposes (the
//     anonymity opt-in, ADR-0013), never the default.
//   - Egress firewall UNTOUCHED. The forward adds NO OUTPUT rule (the spike
//     confirmed the iptables OUTPUT/INPUT chains are byte-identical with a forward
//     active): it is a pure userspace host relay, so forced egress and fail-closed
//     are exactly as before. This package must NEVER emit an iptables/nft rule.
//   - TCP only, exactly the one named port (UDP stays hard-dropped, ADR-0003).
//   - netcage-managed containers only: the verb is label-scoped
//     (netcage.managed, ADR-0009) so it only forwards into a netcage-owned netns,
//     never an arbitrary container, and refuses a stopped jail loudly.
//   - Lifetime-bounded, no persistence. The forward is a plain host process
//     (socat) that lives ONLY for the verb's lifetime; Ctrl-C (ctx cancel) kills
//     it and a reboot ends it, and nothing revives it. There is no netns/nft/pasta
//     state to unwind (the spike: "kill socat -> gone").
//
// The argv builder (ListenArgs) is exposed and the orchestration goes through a
// jail.Runner, so the wiring is unit-testable without executing podman or binding
// a real host socket, mirroring internal/manage.
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/wighawag/netcage/internal/jail"
)

// Config is a resolved forward: the user-named container to forward into, the
// single TCP port to expose, and the resolved host bind address (127.0.0.1 by
// default, or the guardrailed 0.0.0.0). ToolContainer is the resolved
// run-attributable TOOL container name the connect side execs into (filled in by
// Run after the label guard); ListenArgs consumes it. Container is what the user
// typed (used for the guard + messages).
type Config struct {
	Container string // the user-supplied container name (guarded by label)
	Port      int    // the single TCP port to expose (validated 1..65535 at parse)
	Bind      string // resolved host bind: 127.0.0.1 (default) or 0.0.0.0

	// ToolContainer is the resolved netcage-managed TOOL container name the socat
	// connect side execs into. Run resolves it from the label guard; ListenArgs (a
	// pure builder) takes it directly so it is unit-testable without a Runner.
	ToolContainer string
}

// IO carries the sinks the verb writes its start line / warning to, and streams
// the relay's stderr to. In production these are os.Stdout/os.Stderr; a unit test
// injects buffers to assert the printed lines without touching real I/O.
type IO struct {
	Stdout io.Writer
	Stderr io.Writer
}

// loopbackBind is the DEFAULT bind: the host loopback, so nothing off-box can
// reach the forwarded in-jail server unless the operator opts in with --bind
// 0.0.0.0. Pinned here so a drift shows as a test failure.
const loopbackBind = "127.0.0.1"

// allInterfacesBind is the guardrailed LAN opt-in bind (warned before use).
const allInterfacesBind = "0.0.0.0"

// ListenArgs builds the HOST-side socat listener argv the forward stands up (the
// spike's Shape B). The listener binds the HOST's <bind>:<port> (TCP) and its
// EXEC connect side reaches the in-jail server via `podman --root <graphroot>
// exec -i <tool> <connector> 127.0.0.1 <port>`, so the forward is a pure
// userspace host relay that adds NO firewall rule (the egress-untouched
// invariant) and is TCP-only (ADR-0003).
//
// The connector is `sh -c` trying busybox `nc` then `socat` inside the TOOL
// container (the spike proved the tool image's busybox `nc` works; falling to
// socat covers a tool image that ships socat but not nc), so the connect side
// works across the common tool images without netcage assuming a specific
// connector. The graphroot is embedded explicitly because socat spawns podman as
// a CHILD, outside the ExecRunner --root injection seam.
func ListenArgs(cfg Config) []string {
	bind := cfg.Bind
	if bind == "" {
		bind = loopbackBind
	}
	port := strconv.Itoa(cfg.Port)
	// The connect command runs INSIDE the tool container's netns (shared with the
	// sidecar), so 127.0.0.1:<port> is the in-jail server. `exec 2>/dev/null` keeps
	// the connector's own noise off the relay's stderr; the trailing exec chain
	// tries nc then socat so a tool image with either works.
	connect := fmt.Sprintf("podman --root %s exec -i %s sh -c "+
		"'exec nc 127.0.0.1 %s 2>/dev/null || exec socat STDIO TCP:127.0.0.1:%s'",
		jail.GraphRoot(), cfg.ToolContainer, port, port)
	listen := fmt.Sprintf("TCP-LISTEN:%s,bind=%s,fork,reuseaddr", port, bind)
	return []string{"socat", listen, "EXEC:" + connect}
}

// Run stands up the forward for the verb's lifetime and blocks until ctx is
// cancelled (Ctrl-C) or the relay ends. It:
//
//  1. GUARDS that the named container is netcage-managed (the netcage.managed
//     label, ADR-0009), refusing a non-netcage container loudly and standing up
//     NOTHING (no host socket touched).
//  2. Resolves the run's TOOL container (a forward reaches the in-jail server,
//     which lives in the tool's shared netns) and REFUSES a stopped jail loudly
//     (the server cannot be reached, so failing loud beats appearing to work).
//  3. WARNS, before forwarding, when the bind is 0.0.0.0 - naming the container,
//     the port, and that any LAN host can reach the jailed tool's server (the
//     guardrailed anonymity opt-in, ADR-0013). The loopback default warns not at
//     all (nothing off-box is exposed).
//  4. Prints the start line and runs the socat relay through the Runner, blocking
//     until it returns. When it returns there is nothing to unwind: no firewall
//     rule was added and no persistent state written (the spike's "kill socat ->
//     gone"), so teardown is implicit.
func Run(ctx context.Context, r jail.Runner, cfg Config, out IO) error {
	runID, err := resolveManagedTool(ctx, r, cfg.Container)
	if err != nil {
		return err
	}
	toolName := toolNameFor(runID)
	if err := requireToolRunning(ctx, r, toolName); err != nil {
		return err
	}
	cfg.ToolContainer = toolName

	bind := cfg.Bind
	if bind == "" {
		bind = loopbackBind
	}
	if bind == allInterfacesBind {
		// The guardrailed anonymity opt-in (ADR-0013 / ADR-0014): name exactly what
		// this exposes, BEFORE the forward is stood up, so a LAN exposure of the
		// untrusted tool's server is never an accident.
		fmt.Fprintf(writerOrDiscard(out.Stderr),
			"WARNING: exposing %s:%d on ALL interfaces (0.0.0.0); any host on your LAN can reach the jailed tool's server. Ctrl-C to stop.\n",
			cfg.Container, cfg.Port)
	}
	fmt.Fprintf(writerOrDiscard(out.Stdout),
		"forwarding http://%s:%d -> %s:%d (Ctrl-C to stop)\n",
		bind, cfg.Port, cfg.Container, cfg.Port)

	// The relay is a plain host userspace process: it blocks here for the verb's
	// lifetime. ctx cancellation (Ctrl-C / SIGTERM, wired in main) kills socat, and
	// because no firewall rule was added and no state persisted, there is nothing to
	// tear down - the forward is gone with the process (ADR-0014 "does not outlive
	// the verb", spike "kill socat -> gone"). A context.Canceled here is the clean
	// Ctrl-C path, not a failure.
	spec := jail.RunSpec{Name: "socat", Args: ListenArgs(cfg)[1:], Stderr: out.Stderr}
	_, serr, rerr := r.Run(ctx, spec)
	if rerr != nil {
		if ctx.Err() != nil {
			// Ctrl-C / SIGTERM tore the relay down: the intended lifetime bound, clean.
			return nil
		}
		if strings.TrimSpace(serr) != "" {
			return fmt.Errorf("forward relay failed: %w: %s", rerr, serr)
		}
		return fmt.Errorf("forward relay failed: %w", rerr)
	}
	return nil
}

// writerOrDiscard returns w, or io.Discard when w is nil, so Run never panics on
// a nil sink (a test may leave one unset).
func writerOrDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// ErrNotManaged is returned when a named container is not a netcage-managed one
// (missing the netcage.managed label), so the forward REFUSES to touch it. It
// mirrors manage.ErrNotManaged / jail's start resolver: a forward may only reach
// a netcage-owned netns.
var ErrNotManaged = errors.New("not a netcage-managed container")

// resolveManagedTool resolves a user-supplied container NAME to the run id of a
// netcage-MANAGED container, REFUSING a non-netcage or unknown container before
// any forward work (label-scoping, ADR-0009). It reads the create-time labels
// (netcage.managed / role / run-id) via one inspect through the Runner seam,
// mirroring manage.guardManaged / jail.resolveManagedTool. Either the tool or the
// sidecar name resolves to the same run (both carry the run-id label); the
// forward always reaches the TOOL's netns, so it resolves to the run id and
// rebuilds the tool name.
func resolveManagedTool(ctx context.Context, r jail.Runner, name string) (string, error) {
	format := fmt.Sprintf("{{ index .Config.Labels %q }}\t{{ index .Config.Labels %q }}\t{{ index .Config.Labels %q }}",
		jail.LabelManaged, jail.LabelRole, jail.LabelRunID)
	out, _, err := r.Run(ctx, jail.RunSpec{Name: "podman", Args: []string{"inspect", "--format", format, name}})
	if err != nil {
		return "", fmt.Errorf("%q is not a netcage-managed container (inspect failed): %w", name, err)
	}
	fields := strings.SplitN(strings.TrimSpace(out), "\t", 3)
	if len(fields) < 3 || fields[0] != "true" {
		return "", fmt.Errorf("%q is %w (missing the %s label); refusing to forward into it", name, ErrNotManaged, jail.LabelManaged)
	}
	runID := fields[2]
	if runID == "" {
		return "", fmt.Errorf("%q is netcage-managed but carries no run id label (%s); cannot resolve its tool container", name, jail.LabelRunID)
	}
	return runID, nil
}

// requireToolRunning REFUSES the forward unless the run's TOOL container is
// running: a forward reaches the in-jail server, so a stopped jail cannot serve
// it. Failing loud (pointing at `netcage start`) beats a forward that appears to
// work but reaches nothing. One `.State.Running` inspect through the Runner seam
// (the pair is already confirmed netcage-managed by the guard).
func requireToolRunning(ctx context.Context, r jail.Runner, toolName string) error {
	out, _, err := r.Run(ctx, jail.RunSpec{Name: "podman", Args: []string{"inspect", "--format", "{{ .State.Running }}", toolName}})
	if err != nil {
		return fmt.Errorf("cannot forward into %q: it is unavailable (inspect failed): %w; run `netcage start` first", toolName, err)
	}
	if strings.TrimSpace(out) != "true" {
		return fmt.Errorf("cannot forward into %q: its forced-egress jail is not running (the tool is stopped); run `netcage start %s` first to revive the jail, then relaunch the server", toolName, toolName)
	}
	return nil
}

// toolNameFor rebuilds the run-attributable TOOL container name from a run id,
// matching jail's naming convention (netcage-run-<id>-tool). The forward reaches
// the TOOL's netns (shared with the sidecar), so it always resolves to the tool,
// even when the user named the sidecar.
func toolNameFor(runID string) string {
	return "netcage-run-" + runID + "-tool"
}
