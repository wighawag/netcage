// Package manage implements netcage's pass-through management verbs
// (ps/logs/inspect/exec/stop/rm/images/commit + the image-store WRITE verbs
// build/pull/load) as THIN wrappers over podman. The container-scoped verbs are
// SCOPED to netcage's own containers via the netcage.managed label (ADR-0009), so
// a user manages netcage's containers with podman vocabulary without ever seeing
// (or acting on) unrelated ones. The image verbs (images + build/pull/load) are
// UNGUARDED pass-throughs against netcage's image store: they act on IMAGES, not
// run-labelled containers, so the label guard does not apply (ADR-0013).
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
//     work/notes/findings/podman-network-container-dependency-lifecycle.md);
//   - `commit` is a PURE filesystem->image snapshot of the TOOL container: it
//     never starts the container or touches the netns/firewall/DNS, so it is the
//     one management verb that is inherently jail-neutral (no revive/verify).
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

// PsArgs builds `podman ps -a --filter label=netcage.managed=true [userArgs...]`:
// list netcage's containers, INCLUDING stopped ones (-a), because a kept pair is
// stopped at rest and the whole point of `ps` here is to see it. Only
// netcage-managed containers appear; unrelated podman containers are filtered
// out.
//
// The caller's OWN podman `ps` output/query flags (--format <go-template>,
// --format json, -q/--quiet, additional --filter, ...) are FORWARDED VERBATIM
// after the managed-scope filter, so `netcage ps --format '{{.ID}}\t{{.Labels}}'`
// / `-q` / `--filter label=<k>=<v>` behave EXACTLY as `podman ps` does
// (podman-faithful machine-readable output, ADR-0016). This is safe because `ps`
// is a READ-ONLY listing verb: its flags only shape the OUTPUT (they cannot
// egress, alter a netns/firewall, or touch a container's lifecycle), and the
// netcage.managed filter is always PREPENDED, so a user --filter composes ON TOP
// of the implicit netcage scope (podman ANDs repeated --filter), never replacing
// it. The managed-scope filter therefore stays enforced no matter what the caller
// passes.
func PsArgs(userArgs []string) []string {
	args := []string{"ps", "-a"}
	args = append(args, managedFilter()...)
	return append(args, userArgs...)
}

// ImagesArgs builds `podman images`: the images netcage uses. A thin
// pass-through (podman images are not per-run-labelled, so there is no
// container-label filter to apply here).
func ImagesArgs() []string {
	return []string{"images"}
}

// BuildArgs builds `podman build <args...>`: build a Dockerfile into netcage's
// image store. It is a THIN pass-through - the user's args flow through VERBATIM
// (like exec's command tail, NOT a single-label-scoped name), and it does NOT
// hand-add `--root`: the graphroot is injected at the shared ExecRunner.Run seam
// (ADR-0013's single-seam rule), so a per-builder `--root` would be redundant and
// risk splitting the store. `netcage build` == `podman build`, scoped to the
// store. (The one refused arg, a user `--root`, is rejected in Run BEFORE the
// argv is built, so it never reaches here.)
func BuildArgs(args []string) []string {
	return passThroughVerbArgs("build", args)
}

// PullArgs builds `podman pull <args...>`: pull a registry ref into netcage's
// store. A thin verbatim pass-through, like BuildArgs (see it for the
// no-hand-added-`--root` rationale).
func PullArgs(args []string) []string {
	return passThroughVerbArgs("pull", args)
}

// LoadArgs builds `podman load <args...>`: load a `podman save` tar into
// netcage's store. A thin verbatim pass-through, like BuildArgs.
func LoadArgs(args []string) []string {
	return passThroughVerbArgs("load", args)
}

// passThroughVerbArgs is the shared shape for the image-store WRITE verbs
// (build/pull/load): the podman verb then the user's args VERBATIM. No
// `--filter`, no label scoping, and no hand-added `--root` (the graphroot rides
// in at the shared exec seam). It is the write sibling of ImagesArgs/PsArgs.
func passThroughVerbArgs(verb string, args []string) []string {
	out := make([]string, 0, len(args)+1)
	out = append(out, verb)
	return append(out, args...)
}

// refuseUserRoot is the ONE fail-closed guard on the otherwise-verbatim write
// verbs: a user-supplied `--root` (in either `--root x` or `--root=x` form,
// anywhere in the args) is REFUSED. netcage OWNS the store location - the
// graphroot is injected at the shared ExecRunner.Run seam so every verb shares
// ONE store (ADR-0013); honouring a user `--root` would re-split the store this
// fix exists to unify, making a `netcage build`'s image invisible to `netcage
// run` (consistent with how `run` owns `--network`/`--name`). Everything ELSE on
// podman's flag surface is forwarded verbatim: there is no jail to breach, so
// `run`'s allow-list does not apply (even a build-time `--network` is safe - it
// produces an IMAGE, still forced-egress-jailed at a later `netcage run`).
func refuseUserRoot(verb string, args []string) error {
	for _, a := range args {
		if a == "--root" || strings.HasPrefix(a, "--root=") {
			return fmt.Errorf("netcage owns the image store location, so `netcage %s` refuses a user-supplied --root: it is injected automatically (the single %s store); honouring your --root would split the store and hide the result from `netcage run`", verb, "/var/tmp/netcage-storage")
		}
	}
	return nil
}

// LogsArgs builds `podman logs <name>`: the tool container's logs. It is a PLAIN
// pass-through - podman's logs/inspect/exec/stop verbs do NOT accept a `--filter`
// (only `ps` does), so scoping to netcage-managed containers is enforced by the
// guardManaged label check that Run runs BEFORE the verb, never by a filter on
// the verb argv itself.
func LogsArgs(name string) []string {
	return namedVerbArgs("logs", name)
}

// InspectArgs builds `podman inspect [flags...] <name>` for a netcage-managed
// container: the caller's OWN inspect flags (chiefly --format <go-template>, so
// `netcage inspect <id> --format '{{index .Config.Labels "anon-pi.key"}}'`
// returns just that label, exactly as `podman inspect`) are FORWARDED VERBATIM
// BEFORE the name (podman's flags-before-positional order), then the name.
// Full-JSON default (no --format) is preserved. Scoping is the pre-verb
// guardManaged label check (a REFUSED non-netcage container never reaches this
// argv), not a filter. This is safe because inspect is a READ-ONLY query verb:
// --format only shapes the OUTPUT and cannot egress or touch a container's
// lifecycle (ADR-0016). flags carries the already-separated inspect flags (parsed
// off the front of the verb args); name is the guarded subject container.
func InspectArgs(flags []string, name string) []string {
	args := []string{"inspect"}
	args = append(args, flags...)
	return append(args, name)
}

// ParseInspectArgs separates the caller's read-only inspect FLAGS from the single
// subject container NAME, so a podman user can write the flag on EITHER side of
// the name (`netcage inspect <c> --format '...'` OR `netcage inspect --format
// '...' <c>`), matching podman's tolerant flag placement. It scans every token:
// the FIRST non-flag token is the container name; every other token is a flag
// (and a value-taking flag in its `--flag value` separate form consumes the next
// token as its value, so that value is not mistaken for the name). Recognising a
// small set of value-taking inspect flags (--format/-f, --type/-t, --size is a
// boolean) is enough to keep the name resolution correct; unrecognised flags are
// still forwarded (inspect is a read-only query verb, so there is no jail to
// breach, unlike run/exec's curated allow-list), just treated as boolean for the
// purpose of finding the name. Exactly one positional (the name) is required.
//
// This is a READ-ONLY query verb: forwarding arbitrary inspect flags is safe
// because they only shape the OUTPUT (they cannot egress, alter a netns/firewall,
// or touch a container's lifecycle), and the pre-verb guardManaged label check
// still REFUSES a non-netcage container before podman inspect ever runs
// (ADR-0016).
func ParseInspectArgs(args []string) (flags []string, name string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			// Explicit end-of-flags: the next token is the name, the rest (if any) are
			// extra positionals (refused - inspect here takes exactly one container).
			rest := args[i+1:]
			if len(rest) == 0 {
				return nil, "", fmt.Errorf("inspect requires a netcage container name")
			}
			if name != "" || len(rest) > 1 {
				return nil, "", fmt.Errorf("inspect takes exactly one netcage container name; got extra positionals")
			}
			name = rest[0]
			break
		}
		if len(a) == 0 || a[0] != '-' || a == "-" {
			// A positional: the container name. Only one is allowed.
			if name != "" {
				return nil, "", fmt.Errorf("inspect takes exactly one netcage container name; got a second positional %q", a)
			}
			name = a
			continue
		}
		// A flag: forward it. If it is a value-taking inspect flag in its separate
		// `--flag value` form (no inline `=`), also consume the next token as its value
		// so a `--format {{...}}` value is never mistaken for the container name.
		flags = append(flags, a)
		if isInspectValueFlag(a) && !strings.Contains(a, "=") {
			if i+1 >= len(args) {
				return nil, "", fmt.Errorf("inspect flag %s needs a value", a)
			}
			i++
			flags = append(flags, args[i])
		}
	}
	if name == "" {
		return nil, "", fmt.Errorf("inspect requires a netcage container name")
	}
	return flags, name, nil
}

// isInspectValueFlag reports whether a is one of the value-taking podman inspect
// flags in its `--flag`/`-f` separate form (so ParseInspectArgs consumes the next
// token as its value rather than treating it as the container name). The set is
// small and read-only: --format/-f (the go-template), --type/-t (container|image).
// A `--flag=value` inline form carries its own value, so it is NOT listed here
// (the `strings.Contains(a, "=")` guard at the call site skips it).
func isInspectValueFlag(a string) bool {
	switch a {
	case "--format", "-f", "--type", "-t":
		return true
	}
	return false
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

// CommitFlags is the CURATED, network/isolation-IRRELEVANT subset of podman's
// `commit` flags netcage honours. Unlike run's ADR-0010 checklist (which governs
// flags on the JAILED CONTAINER's netns/caps/ports/DNS/lifecycle), commit writes
// an IMAGE, not the running container: it never starts the container, never
// touches the netns/firewall/DNS, and cannot open a leak by construction. These
// flags only affect the produced image's manifest/metadata/config (-m/-a/-c/-f)
// or a momentary pause during the snapshot (--pause), or output verbosity (-q).
// `-c`/`--change` bakes IMAGE config (CMD/ENTRYPOINT/ENV/EXPOSE/...) that takes
// effect only on a FUTURE `netcage run`, which STILL passes through netcage's own
// run allow-list, so the run-time jail is unchanged by what commit bakes. Every
// other flag is REFUSED (fail-closed on the unknown, like `run`/`exec`). Exposed
// (with CommitArgs + ParseCommitArgs) so the flag parse + argv wiring is
// unit-testable without executing podman, like the other verb argv builders.
type CommitFlags struct {
	Message  string   // -m / --message <text>
	Author   string   // -a / --author <name>
	Change   []string // -c / --change <instruction> (repeatable)
	Format   string   // -f / --format <oci|docker>
	Pause    bool     // --pause[=bool] (podman default is true)
	PauseSet bool     // whether --pause was given explicitly (so the argv emits it)
	Quiet    bool     // -q / --quiet
}

// commitAcceptedFlags is the human-readable accepted-flag list an unknown-flag
// refusal names, so the message tells the user exactly what `netcage commit`
// takes (mirrors `run`/`exec`'s fail-closed-on-the-unknown message).
const commitAcceptedFlags = "-m/--message <text>, -a/--author <name>, -c/--change <instr>, -f/--format <oci|docker>, --pause[=bool], -q/--quiet"

// ParseCommitArgs separates the CURATED commit flags from the two required
// positionals - the netcage container NAME then the new IMAGE-REF - so a podman
// user can write `netcage commit -m "msg" -a me <c> my-image:tag`. Flags may be
// interleaved with the positionals (podman accepts flags before OR between them);
// the FIRST non-flag token is the container name and the SECOND is the image-ref.
// An UNKNOWN flag is REFUSED (fail-closed), naming the accepted flags. `--pause`
// is a boolean with podman's `--pause[=bool]` inline-negation form; the metadata
// flags take a value (inline `--flag=value` or the next arg).
func ParseCommitArgs(args []string) (flags CommitFlags, name string, imageRef string, err error) {
	var positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			// Explicit end-of-flags: the rest are positionals.
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if len(a) == 0 || a[0] != '-' || a == "-" {
			positionals = append(positionals, a)
			continue
		}
		// Split an inline --flag=value so the flag case can consume it directly.
		flag, inlineVal, hasInline := a, "", false
		if eq := strings.IndexByte(a, '='); eq >= 0 && strings.HasPrefix(a, "--") {
			flag, inlineVal, hasInline = a[:eq], a[eq+1:], true
		}
		takeValue := func(fn string) (string, error) {
			if hasInline {
				return inlineVal, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("commit flag %s needs a value", fn)
			}
			i++
			return args[i], nil
		}
		switch flag {
		case "-m", "--message":
			if flags.Message, err = takeValue(flag); err != nil {
				return CommitFlags{}, "", "", err
			}
		case "-a", "--author":
			if flags.Author, err = takeValue(flag); err != nil {
				return CommitFlags{}, "", "", err
			}
		case "-c", "--change":
			v, verr := takeValue(flag)
			if verr != nil {
				return CommitFlags{}, "", "", verr
			}
			flags.Change = append(flags.Change, v)
		case "-f", "--format":
			if flags.Format, err = takeValue(flag); err != nil {
				return CommitFlags{}, "", "", err
			}
		case "--pause":
			// Boolean with podman's `--pause[=bool]`: bare means true, `--pause=false`
			// turns off the default snapshot pause. PauseSet records that it was given so
			// CommitArgs only emits it when the user chose it (podman defaults to pause).
			flags.PauseSet = true
			if hasInline {
				flags.Pause = inlineVal == "true" || inlineVal == "1"
			} else {
				flags.Pause = true
			}
		case "-q", "--quiet":
			flags.Quiet = true
		default:
			return CommitFlags{}, "", "", fmt.Errorf("unknown commit flag %q (netcage commit accepts %s); refusing it, like a jail-breaching flag", a, commitAcceptedFlags)
		}
	}
	if len(positionals) < 1 {
		return CommitFlags{}, "", "", fmt.Errorf("commit requires a netcage container name")
	}
	if len(positionals) < 2 {
		return CommitFlags{}, "", "", fmt.Errorf("commit requires an image-ref to write (the new image name), e.g. `netcage commit %s my-image:tag`", positionals[0])
	}
	if len(positionals) > 2 {
		return CommitFlags{}, "", "", fmt.Errorf("commit takes exactly a container name and an image-ref; got extra positionals %v", positionals[2:])
	}
	return flags, positionals[0], positionals[1], nil
}

// CommitArgs builds `podman commit [curated flags] <tool> <image-ref>`: snapshot
// the TOOL container's FILESYSTEM into a new image. The curated metadata flags
// (all image-side, never touching the container's network/netns) are emitted
// BEFORE the container name, in a canonical order, then the tool, then the
// image-ref. There is NO --network and NO container start here BY DESIGN: commit
// is a pure filesystem->image snapshot, the one management verb that is inherently
// jail-neutral - so it deliberately needs no sidecar-revive / firewall-verify (see
// Run's commit case). A later reader must NOT add a firewall check here: there is
// no jail to restore because nothing runs.
func CommitArgs(flags CommitFlags, toolName, imageRef string) []string {
	args := []string{"commit"}
	if flags.Message != "" {
		args = append(args, "-m", flags.Message)
	}
	if flags.Author != "" {
		args = append(args, "-a", flags.Author)
	}
	for _, c := range flags.Change {
		args = append(args, "-c", c)
	}
	if flags.Format != "" {
		args = append(args, "-f", flags.Format)
	}
	if flags.PauseSet {
		// Only emit --pause when the user chose it (podman defaults to pausing); use
		// the inline `--pause=false` form so an explicit OFF is preserved.
		if flags.Pause {
			args = append(args, "--pause")
		} else {
			args = append(args, "--pause=false")
		}
	}
	if flags.Quiet {
		args = append(args, "-q")
	}
	args = append(args, toolName, imageRef)
	return args
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
//   - ps: a label-scoped container listing, no named subject. The caller's own
//     read-only podman ps output/query flags (--format/--format json/-q/--filter)
//     are FORWARDED after the managed-scope filter, so machine-readable listing is
//     podman-faithful; the netcage.managed filter is always prepended (a user
//     --filter composes on top, never replaces it), so the label scope stays
//     enforced (ADR-0016).
//   - inspect: operates on a NAMED container after the label guard, and FORWARDS
//     the caller's read-only inspect flags (chiefly --format <go-template>) so a
//     single label can be read machine-readably (ADR-0016).
//   - images / build / pull / load: UNGUARDED image-store pass-throughs (no label
//     check - they act on images, not run-labelled containers). build/pull/load
//     forward their args to podman VERBATIM against the store (the graphroot
//     --root is inherited from the exec seam, ADR-0013), refusing ONLY a
//     user-supplied --root (it would re-split the single store).
//   - logs / stop / exec: operate on a NAMED container, but only after GUARDING
//     that it is netcage-managed (the label). A non-netcage container is REFUSED
//     with ErrNotManaged before any podman verb runs against it.
//   - rm: guard the named container, then remove the WHOLE pair by its SIDECAR
//     name (rm -f --depend cascades to the tool), so no orphaned sidecar is left
//     even when the user names the tool.
//   - commit: guard the named container, REFUSE a sidecar (commit takes the
//     tool), resolve the run's TOOL, and `podman commit` its filesystem to a new
//     image. Snapshot-only: it never starts or networks the container.
func Run(ctx context.Context, r jail.Runner, verb string, args []string, out IO) error {
	switch verb {
	case "ps":
		// ps forwards the caller's read-only podman ps output/query flags
		// (--format/--format json/-q/--filter/...) VERBATIM after the managed-scope
		// filter, so machine-readable listing is podman-faithful (ADR-0016). The
		// netcage.managed filter is always prepended, so a user --filter composes ON TOP
		// of it (never replaces it) and the label scope stays enforced.
		return stream(ctx, r, PsArgs(args), out)
	case "images":
		return stream(ctx, r, ImagesArgs(), out)
	case "build", "pull", "load":
		// The image-store WRITE verbs (ADR-0013): the write siblings of `images`. They
		// act on IMAGES, not run-labelled containers, so they are UNGUARDED (no
		// guardManaged) and forward their args to podman VERBATIM. The graphroot `--root`
		// is inherited from the shared ExecRunner.Run seam, never hand-added here. The ONE
		// refusal is a user-supplied `--root` (it would re-split the single store); every
		// other podman flag passes through (no jail to breach, so no run allow-list).
		if err := refuseUserRoot(verb, args); err != nil {
			return err
		}
		return stream(ctx, r, passThroughVerbArgs(verb, args), out)
	case "inspect":
		// inspect is podman-faithful for machine-readable output: the caller's own
		// read-only inspect flags (chiefly --format <go-template>) are forwarded so
		// `netcage inspect <id> --format '{{index .Config.Labels "anon-pi.key"}}'`
		// returns just that label (ADR-0016). The flags are separated from the subject
		// name, the name is guarded netcage-managed, then podman inspect runs with the
		// flags BEFORE the name.
		flags, name, err := ParseInspectArgs(args)
		if err != nil {
			return err
		}
		if _, err := guardManaged(ctx, r, name); err != nil {
			return err
		}
		return stream(ctx, r, InspectArgs(flags, name), out)
	case "logs", "stop":
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
	case "commit":
		return runCommit(ctx, r, args, out)
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
		// Sweep the run-attributable bind-mount sources too: a KEPT pair leaves the
		// resolv.conf + sanitized /etc/hosts durable on the host (so `netcage start` can
		// re-mount them), so removing the pair must also remove those files or they
		// orphan under $TMPDIR. Idempotent (no-op if absent).
		jail.RemoveResolvConf(m.runID)
		jail.RemoveHosts(m.runID)
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

// runCommit is the jail-NEUTRAL, podman-faithful `netcage commit`: it parses the
// curated commit flags + the two required positionals (the container NAME then
// the new IMAGE-REF), GUARDS that the named container is netcage-managed, REFUSES
// a sidecar (commit takes the TOOL, like `netcage start`), resolves the run's
// TOOL container, and runs `podman commit [flags] <tool> <image-ref>` against it.
//
// Forced-egress invariant (why there is NO firewall/jail-health check here):
// commit is a PURE filesystem->image snapshot. It does NOT start the container,
// touch the netns/firewall/DNS, or give any container a working un-jailed network
// - it cannot open a leak by construction. So, unlike `run`/`start`/`exec`, it
// needs NO sidecar-revive / firewall-verify: there is no jail to restore because
// nothing runs. It is the one management verb that is inherently jail-neutral.
// Do NOT add a firewall check here "for consistency" - it would be meaningless.
// It also works on a STOPPED kept container (the exploratory-machine path: run
// kept -> play -> quit -> commit); podman commit handles a stopped container
// as-is, so commit deliberately does not require the tool to be running.
func runCommit(ctx context.Context, r jail.Runner, args []string, out IO) error {
	flags, name, imageRef, err := ParseCommitArgs(args)
	if err != nil {
		return err
	}
	m, err := guardManaged(ctx, r, name)
	if err != nil {
		return err
	}
	// Commit the TOOL, never the sidecar: the tool holds the played-with filesystem;
	// the sidecar is just jail plumbing (tun2socks + firewall + DNS). If the user
	// named the sidecar, REFUSE and point at the tool (mirrors `netcage start`).
	if m.role == jail.RoleSidecar {
		return fmt.Errorf("%q is a netcage sidecar (jail plumbing), not a tool container; `netcage commit` snapshots the TOOL container (its played-with filesystem) - name the tool %q instead", name, toolNameFor(m.runID))
	}
	return stream(ctx, r, CommitArgs(flags, toolNameFor(m.runID), imageRef), out)
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

// toolNameFor rebuilds the run-attributable TOOL container name from a run id,
// matching jail's naming convention (netcage-run-<id>-tool). commit resolves the
// run's tool from the run id (regardless of whether the user named the tool or
// something else managed by the run) so it always snapshots the played-with tool
// filesystem, never the sidecar.
func toolNameFor(runID string) string {
	return "netcage-run-" + runID + "-tool"
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
