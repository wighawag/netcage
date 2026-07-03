// Package manage implements netcage's pass-through management verbs
// (ps/logs/inspect/exec/stop/rm/images) as THIN wrappers over podman, SCOPED to
// netcage's own containers via the netcage.managed label (ADR-0009). A user
// manages netcage's containers with podman vocabulary without ever seeing (or
// acting on) unrelated ones.
//
// These verbs are inspection/lifecycle ONLY: they never stand up or tear down a
// jail (that is `run` / `netcage start`) and they never touch a running jail's
// forced-egress state. In particular:
//
//   - none require or bypass the proxy (they do not egress), so netcage's
//     proxy preflight is deliberately OFF them (see main.go's dispatch);
//   - `exec` runs INSIDE the container's EXISTING jailed netns (a plain `podman
//     exec`), never a fresh un-jailed one, so it cannot hand out a working
//     un-jailed network;
//   - `rm` removes the WHOLE kept pair (the sidecar with --depend, which
//     cascades to its `--network container:` dependent tool), leaving no
//     orphaned sidecar (see
//     work/notes/findings/podman-network-container-dependency-lifecycle.md).
//
// The verb argv builders are exposed (and the orchestration goes through a
// jail.Runner) so the wiring is unit-testable without executing podman, mirroring
// jail.Config's SidecarRunArgs/ToolRunArgs.
package manage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wighawag/netcage/internal/jail"
)

// managedFilter is the podman `ps` filter that scopes the listing to netcage's
// own containers: the netcage.managed label the sidecar/tool create args stamp
// (ADR-0009). A label, not the netcage-run-<id>-* name convention, is the robust
// discriminator, so it survives renames and is unambiguous at rest. Only `ps`
// takes `--filter`; the named verbs (logs/inspect/exec/stop) are guarded by the
// pre-verb guardManaged label check instead (they reject `--filter`).
func managedFilter() []string {
	return []string{"--filter", "label=" + jail.LabelManaged + "=true"}
}

// PsArgs builds `podman ps -a --filter label=netcage.managed=true`: list
// netcage's containers, INCLUDING stopped ones (-a), because a kept pair is
// stopped at rest and the whole point of `ps` here is to see it. Only
// netcage-managed containers appear; unrelated podman containers are filtered
// out.
func PsArgs() []string {
	args := []string{"ps", "-a"}
	return append(args, managedFilter()...)
}

// ImagesArgs builds `podman images`: the images netcage uses. A thin
// pass-through (podman images are not per-run-labelled, so there is no
// container-label filter to apply here).
func ImagesArgs() []string {
	return []string{"images"}
}

// LogsArgs builds `podman logs <name>`: the tool container's logs. It is a PLAIN
// pass-through - podman's logs/inspect/exec/stop verbs do NOT accept a `--filter`
// (only `ps` does), so scoping to netcage-managed containers is enforced by the
// guardManaged label check that Run runs BEFORE the verb, never by a filter on
// the verb argv itself.
func LogsArgs(name string) []string {
	return namedVerbArgs("logs", name)
}

// InspectArgs builds `podman inspect <name>` for a netcage-managed container (a
// plain pass-through; scoping is the pre-verb guardManaged check, not a filter).
func InspectArgs(name string) []string {
	return namedVerbArgs("inspect", name)
}

// StopArgs builds `podman stop <name>` for a netcage-managed container: a plain
// lifecycle pass-through (stopping a jailed container does not alter its
// firewall, which is baked into the sidecar and re-applies on restart). Scoping
// is the pre-verb guardManaged check, not a filter.
func StopArgs(name string) []string {
	return namedVerbArgs("stop", name)
}

// ExecArgs builds `podman exec <name> <cmd...>`: run a command INSIDE the
// EXISTING container, which already shares the sidecar's jailed netns. It is a
// plain `podman exec` (never `podman run --network ...`), so it enters the
// container's existing netns and CANNOT hand out a fresh, un-jailed network (the
// forced-egress invariant). Scoping is the pre-verb guardManaged check, not a
// filter. The user command is passed through verbatim.
func ExecArgs(name string, cmd []string) []string {
	args := namedVerbArgs("exec", name)
	return append(args, cmd...)
}

// RmPairArgs builds `podman rm -f --depend <sidecar>`: remove the sidecar, which
// CASCADES to its `--network container:` dependent tool (the only way to drop the
// sidecar; podman refuses to remove it while the tool exists). So removing the
// pair by its SIDECAR name cleans both with no orphaned residue. The caller
// resolves the sidecar name from whatever container the user named (see Run's rm
// path).
func RmPairArgs(sidecarName string) []string {
	return []string{"rm", "-f", "--depend", sidecarName}
}

// namedVerbArgs is the shared shape for a container-scoped verb: the podman verb
// then the named subject. It is a PLAIN pass-through with NO `--filter` - podman
// only supports `--filter` on `ps` (logs/inspect/exec/stop reject it), so scoping
// to netcage-managed containers is done by the guardManaged label check Run
// performs BEFORE the verb, not by a filter baked into the verb argv.
func namedVerbArgs(verb, name string) []string {
	args := []string{verb}
	return append(args, name)
}

// ErrNotManaged is returned when a named container is not a netcage-managed one
// (missing the netcage.managed label), so a management verb REFUSES to touch it.
var ErrNotManaged = errors.New("not a netcage-managed container")

// managed is the resolved netcage identity of a named container: its role and
// run id, read from the create-time labels. Absent labels => not managed.
type managed struct {
	role  string
	runID string
}

// IO carries the sinks a management verb streams its podman output to (the
// user's own stdout/stderr in production). Both may be nil in a unit test whose
// recording runner only asserts the built argv.
type IO struct {
	Stdout io.Writer
	Stderr io.Writer
}

// Run dispatches a management verb through the runner, applying the label guard
// and (for rm) the pair-resolution the verb needs. Verb output is streamed live
// to out.Stdout/out.Stderr so `logs`/`inspect`/`ps` feel like the podman verbs
// they wrap.
//
//   - ps / images: label-scoped listings, no named subject.
//   - logs / inspect / stop / exec: operate on a NAMED container, but only after
//     GUARDING that it is netcage-managed (the label). A non-netcage container is
//     REFUSED with ErrNotManaged before any podman verb runs against it.
//   - rm: guard the named container, then remove the WHOLE pair by its SIDECAR
//     name (rm -f --depend cascades to the tool), so no orphaned sidecar is left
//     even when the user names the tool.
func Run(ctx context.Context, r jail.Runner, verb string, args []string, out IO) error {
	switch verb {
	case "ps":
		return stream(ctx, r, PsArgs(), out)
	case "images":
		return stream(ctx, r, ImagesArgs(), out)
	case "logs", "inspect", "stop":
		name, _, err := requireName(verb, args)
		if err != nil {
			return err
		}
		if _, err := guardManaged(ctx, r, name); err != nil {
			return err
		}
		return stream(ctx, r, namedVerbArgs(verb, name), out)
	case "exec":
		name, rest, err := requireName(verb, args)
		if err != nil {
			return err
		}
		if _, err := guardManaged(ctx, r, name); err != nil {
			return err
		}
		return stream(ctx, r, ExecArgs(name, rest), out)
	case "rm":
		name, _, err := requireName(verb, args)
		if err != nil {
			return err
		}
		m, err := guardManaged(ctx, r, name)
		if err != nil {
			return err
		}
		// Remove the whole pair by its SIDECAR name: rm -f --depend cascades to the
		// `--network container:` dependent tool, so no orphaned sidecar is left.
		return stream(ctx, r, RmPairArgs(sidecarNameFor(m.runID)), out)
	default:
		return fmt.Errorf("unknown management verb %q", verb)
	}
}

// requireName pulls the (required) subject container name off the front of args
// and returns the remainder (the exec command, empty for the others).
func requireName(verb string, args []string) (name string, rest []string, err error) {
	if len(args) == 0 {
		return "", nil, fmt.Errorf("%s requires a netcage container name", verb)
	}
	return args[0], args[1:], nil
}

// guardManaged inspects the named container's netcage labels and REFUSES
// (ErrNotManaged) anything that is not netcage-managed, so a management verb can
// never touch an unrelated podman container. It is the single choke point the
// named verbs (logs/inspect/exec/stop/rm) pass through before acting.
func guardManaged(ctx context.Context, r jail.Runner, name string) (managed, error) {
	// One inspect call fetches all three labels tab-separated: <managed>\t<role>\t<run-id>.
	format := fmt.Sprintf("{{ index .Config.Labels %q }}\t{{ index .Config.Labels %q }}\t{{ index .Config.Labels %q }}",
		jail.LabelManaged, jail.LabelRole, jail.LabelRunID)
	out, _, err := r.Run(ctx, jail.RunSpec{Name: "podman", Args: []string{"inspect", "--format", format, name}})
	if err != nil {
		return managed{}, fmt.Errorf("%q is not a netcage-managed container (inspect failed): %w", name, err)
	}
	fields := strings.SplitN(strings.TrimSpace(out), "\t", 3)
	if len(fields) < 3 || fields[0] != "true" {
		return managed{}, fmt.Errorf("%q is %w (missing the %s label); refusing to manage it", name, ErrNotManaged, jail.LabelManaged)
	}
	return managed{role: fields[1], runID: fields[2]}, nil
}

// sidecarNameFor rebuilds the run-attributable sidecar name from a run id,
// matching jail's naming convention (netcage-run-<id>-sidecar). rm targets the
// sidecar because removing it (with --depend) cascades to the tool.
func sidecarNameFor(runID string) string {
	return "netcage-run-" + runID + "-sidecar"
}

// stream runs a podman argv through the runner, teeing its stdout/stderr live to
// the user's sinks, and surfacing any failure with the captured stderr so the
// user sees podman's own message.
func stream(ctx context.Context, r jail.Runner, args []string, out IO) error {
	_, serr, err := r.Run(ctx, jail.RunSpec{Name: "podman", Args: args, Stdout: out.Stdout, Stderr: out.Stderr})
	if err != nil {
		if strings.TrimSpace(serr) != "" {
			return fmt.Errorf("podman %s: %w: %s", args[0], err, serr)
		}
		return fmt.Errorf("podman %s: %w", args[0], err)
	}
	return nil
}
