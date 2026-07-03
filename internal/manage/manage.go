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

// ExecFlags is the CURATED, network/isolation-IRRELEVANT subset of podman's
// `exec` flags netcage honours (ADR-0010 checklist): they only affect the
// exec'd process's tty/stdin/cwd/env/uid, NEVER the container's network, netns,
// caps, ports, or DNS, so they are safe to pass through a jailed exec. Every
// other flag is REFUSED (fail-closed on the unknown, like `run`), so a future
// network/priv exec flag can never silently breach the jail. It is exposed (with
// ExecArgs + ParseExecArgs) so the flag parse + argv wiring is unit-testable
// without executing podman, like the other verb argv builders.
type ExecFlags struct {
	Interactive bool     // -i / --interactive
	TTY         bool     // -t / --tty
	Workdir     string   // -w / --workdir <dir>
	User        string   // -u / --user <user>
	Env         []string // -e / --env KEY=VAL (repeatable)
}

// execAcceptedFlags is the human-readable accepted-flag list an unknown-flag
// refusal names, so the message tells the user exactly what `netcage exec` takes
// (mirrors `run`'s fail-closed-on-the-unknown message).
const execAcceptedFlags = "-i/--interactive, -t/--tty, -w/--workdir <dir>, -e/--env KEY=VAL, -u/--user <user>"

// ParseExecArgs separates the CURATED exec flags from the subject container name
// and the command, so a podman user can write `netcage exec -it -w /root -e K=V
// <c> bash` (flags BEFORE the name, like podman). It scans leading flags until
// the first non-flag token, which is the container NAME; everything after the
// name is the command, passed through verbatim (its own flags are NOT parsed).
// An UNKNOWN flag before the name is REFUSED (fail-closed), naming the accepted
// flags. `-it`/`-ti` bundles and `--flag=value` forms are accepted.
func ParseExecArgs(args []string) (flags ExecFlags, name string, cmd []string, err error) {
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			// Explicit end-of-flags: the next token is the name.
			i++
			break
		}
		if len(a) == 0 || a[0] != '-' || a == "-" {
			// First non-flag token: the container name. Flag scanning stops here so the
			// command's OWN flags are never mis-parsed as exec flags.
			break
		}
		// A value may be attached as --flag=value; split it off so the flag case can
		// consume it without peeking at the next arg.
		flag, inlineVal, hasInline := a, "", false
		if eq := strings.IndexByte(a, '='); eq >= 0 && strings.HasPrefix(a, "--") {
			flag, inlineVal, hasInline = a[:eq], a[eq+1:], true
		}
		// takeValue returns the flag's value: the inline `--flag=value`, else the next
		// arg. A value-taking flag at the end of args with no value is an error.
		takeValue := func(name string) (string, error) {
			if hasInline {
				return inlineVal, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("exec flag %s needs a value", name)
			}
			i++
			return args[i], nil
		}
		switch flag {
		case "-i", "--interactive":
			flags.Interactive = true
		case "-t", "--tty":
			flags.TTY = true
		case "-it", "-ti":
			flags.Interactive, flags.TTY = true, true
		case "-w", "--workdir":
			if flags.Workdir, err = takeValue(flag); err != nil {
				return ExecFlags{}, "", nil, err
			}
		case "-u", "--user":
			if flags.User, err = takeValue(flag); err != nil {
				return ExecFlags{}, "", nil, err
			}
		case "-e", "--env":
			v, verr := takeValue(flag)
			if verr != nil {
				return ExecFlags{}, "", nil, verr
			}
			flags.Env = append(flags.Env, v)
		default:
			return ExecFlags{}, "", nil, fmt.Errorf("unknown exec flag %q (netcage exec accepts %s); refusing it, like a jail-breaching flag", a, execAcceptedFlags)
		}
	}
	if i >= len(args) {
		return ExecFlags{}, "", nil, fmt.Errorf("exec requires a netcage container name")
	}
	name = args[i]
	cmd = args[i+1:]
	if len(cmd) == 0 {
		return ExecFlags{}, "", nil, fmt.Errorf("exec requires a command to run in %q", name)
	}
	return flags, name, cmd, nil
}

// ExecArgs builds `podman exec [flags] <name> <cmd...>`: run a command INSIDE the
// EXISTING container, which already shares the sidecar's jailed netns. It is a
// plain `podman exec` (never `podman run --network ...`), so it enters the
// container's existing netns and CANNOT hand out a fresh, un-jailed network (the
// forced-egress invariant). The curated flags (all ADR-0010 network-irrelevant)
// are emitted BEFORE the name, in a canonical order, then the name, then the
// user's command verbatim. Scoping is the pre-verb guardManaged check, not a
// filter.
func ExecArgs(flags ExecFlags, name string, cmd []string) []string {
	args := []string{"exec"}
	// -i / -t as podman's own bundled forms (podman accepts -i, -t, -it).
	if flags.Interactive {
		args = append(args, "-i")
	}
	if flags.TTY {
		args = append(args, "-t")
	}
	if flags.Workdir != "" {
		args = append(args, "-w", flags.Workdir)
	}
	if flags.User != "" {
		args = append(args, "-u", flags.User)
	}
	for _, e := range flags.Env {
		args = append(args, "-e", e)
	}
	args = append(args, name)
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
// recording runner only asserts the built argv. Stdin is the reader wired to an
// INTERACTIVE `exec -it` (os.Stdin in production); it is used ONLY on the
// interactive-exec raw-passthrough path and ignored otherwise.
type IO struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
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
		return runExec(ctx, r, args, out)
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
		if err := stream(ctx, r, RmPairArgs(sidecarNameFor(m.runID)), out); err != nil {
			return err
		}
		// Sweep the run-attributable resolv.conf too: a KEPT pair leaves it durable on
		// the host (so `netcage start` can re-mount it), so removing the pair must also
		// remove that file or it orphans under $TMPDIR. Idempotent (no-op if absent).
		jail.RemoveResolvConf(m.runID)
		return nil
	default:
		return fmt.Errorf("unknown management verb %q", verb)
	}
}

// runExec is the jail-safe, podman-faithful `netcage exec`: it parses the curated
// exec flags (BEFORE the name), GUARDS that the named container is
// netcage-managed, ensures the JAIL IS HEALTHY (the sidecar AND tool are running)
// BEFORE exec'ing, and then runs the command INSIDE the existing jailed netns. When
// `-it` is given it wires a REAL interactive terminal (raw stdio passthrough via
// RunSpec.Interactive/Stdin, the same path `run -it`/`start -ai` use) instead of
// the capture-only stream; a non-interactive exec keeps the capture/tee
// behaviour.
//
// The jail-health guarantee is REFUSE-IF-DOWN (see the exec done record): a plain
// `podman exec` into a container whose forced-egress jail is not fully up would
// run before the jail is healthy. Rather than silently exec into a container
// whose jail is down, exec REFUSES unless BOTH the sidecar (which owns the netns
// + firewall + DNS) AND the tool are running, telling the user to `netcage start
// <c>` first (which revives + verifies the jail). A deliberately-down jail
// therefore never yields a working un-jailed exec. (Reviving here would need to
// reconstruct the full proxy config from the sidecar's baked env, which `start`
// does not expose reusably; refuse is the self-contained, jail-safe choice.)
func runExec(ctx context.Context, r jail.Runner, args []string, out IO) error {
	flags, name, cmd, err := ParseExecArgs(args)
	if err != nil {
		return err
	}
	m, err := guardManaged(ctx, r, name)
	if err != nil {
		return err
	}
	// Jail-health guarantee: refuse unless the forced-egress jail is fully up (the
	// sidecar that owns the netns + firewall + DNS, and the tool exec targets), so
	// exec never runs before the jail is healthy. This enters the EXISTING jailed
	// netns; it never stands up a fresh one.
	if err := requireJailHealthy(ctx, r, m.runID, name); err != nil {
		return err
	}
	execArgs := ExecArgs(flags, name, cmd)
	spec := jail.RunSpec{Name: "podman", Args: execArgs}
	if flags.Interactive && flags.TTY {
		// Interactive `-it`: RAW stdio passthrough (a real PTY + stdin), the same seam
		// `run -it`/`start -ai` use. podman owns the container PTY; netcage does not
		// capture. Leave the capture-tee sinks nil (the raw path ignores them).
		spec.Interactive = true
		spec.Stdin = out.Stdin
		if _, _, err := r.Run(ctx, spec); err != nil {
			return fmt.Errorf("podman exec: %w", err)
		}
		return nil
	}
	// Non-interactive exec keeps the capture/tee behaviour, unchanged.
	return stream(ctx, r, execArgs, out)
}

// requireJailHealthy is the exec jail-health guard: it REFUSES exec unless the
// container's forced-egress jail is fully UP, so a plain `podman exec` never runs
// before the jail is healthy. It checks BOTH:
//
//   - the SIDECAR (which holds the netns + firewall + DNS forwarder): if it is
//     stopped, the jail is down;
//   - the TOOL itself (exec's target): a kept pair AT REST leaves the tool
//     stopped (its process exited), and podman would otherwise refuse exec with a
//     cryptic "container state improper"; this turns that into a clear "run
//     `netcage start` first".
//
// Either being down is refused with a message pointing at `netcage start <tool>`
// (which revives + firewall-VERIFIES the jail), so a deliberately-down jail can
// never yield a working un-jailed exec. Two small `.State.Running` inspects; the
// pre-verb guardManaged label check has already confirmed the pair is
// netcage-managed.
func requireJailHealthy(ctx context.Context, r jail.Runner, runID, toolName string) error {
	sidecar := sidecarNameFor(runID)
	for _, c := range []struct{ name, role string }{
		{sidecar, "jail sidecar (netns + firewall + DNS)"},
		{toolName, "tool container"},
	} {
		out, _, err := r.Run(ctx, jail.RunSpec{Name: "podman", Args: []string{"inspect", "--format", "{{ .State.Running }}", c.name}})
		if err != nil {
			return fmt.Errorf("cannot exec into %q: its %s %q is unavailable (inspect failed): %w; run `netcage start %s` first", toolName, c.role, c.name, err, toolName)
		}
		if strings.TrimSpace(out) != "true" {
			return fmt.Errorf("cannot exec into %q: its forced-egress jail is not running (%s %q is stopped); run `netcage start %s` first to revive + verify the jail", toolName, c.role, c.name, toolName)
		}
	}
	return nil
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
