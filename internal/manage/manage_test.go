package manage_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/manage"
)

// The label filter EVERY container-scoped verb must carry so it only ever sees
// netcage's own containers (a label, not the netcage-run-<id>-* name
// convention). Pinned here so a drift in the key shows up as a test failure.
const managedFilter = "--filter label=" + jail.LabelManaged + "=true"

// TestPsArgs_ListsOnlyManagedContainers pins that `netcage ps` is a thin podman
// `ps` scoped by the netcage.managed label filter, so it lists netcage's
// containers (and only those), including stopped ones (-a, since a kept pair is
// stopped at rest).
func TestPsArgs_ListsOnlyManagedContainers(t *testing.T) {
	got := strings.Join(manage.PsArgs(), " ")
	for _, want := range []string{"ps", "-a", managedFilter} {
		if !strings.Contains(got, want) {
			t.Fatalf("ps args missing %q\ngot: %s", want, got)
		}
	}
}

// TestImagesArgs_ShowsNetcageImages pins that `netcage images` is a thin podman
// `images` pass-through (the images netcage uses).
func TestImagesArgs_IsPodmanImages(t *testing.T) {
	got := strings.Join(manage.ImagesArgs(), " ")
	if !strings.Contains(got, "images") {
		t.Fatalf("images args must invoke podman images; got: %s", got)
	}
}

// TestNamedVerbArgs_ArePlainPassThroughs pins the container-scoped verbs
// (logs/inspect/stop) as PLAIN podman pass-throughs: just the verb and the named
// subject, with NO `--filter` (podman only accepts `--filter` on `ps`;
// logs/inspect/exec/stop reject it). Scoping to netcage-managed containers is
// enforced by the pre-verb guardManaged label check in Run, NOT by a filter on
// the verb argv - so these must NOT carry it.
func TestNamedVerbArgs_ArePlainPassThroughs(t *testing.T) {
	cases := []struct {
		verb string
		got  []string
	}{
		{"logs", manage.LogsArgs("netcage-run-abc-tool")},
		{"inspect", manage.InspectArgs("netcage-run-abc-tool")},
		{"stop", manage.StopArgs("netcage-run-abc-tool")},
	}
	for _, tc := range cases {
		joined := strings.Join(tc.got, " ")
		if tc.got[0] != tc.verb {
			t.Fatalf("%s args must start with the podman verb %q; got: %s", tc.verb, tc.verb, joined)
		}
		if strings.Contains(joined, "--filter") {
			t.Fatalf("%s must be a PLAIN pass-through with NO --filter (podman rejects it on this verb); scoping is the guardManaged check. got: %s", tc.verb, joined)
		}
		if !strings.Contains(joined, "netcage-run-abc-tool") {
			t.Fatalf("%s args must name the subject container; got: %s", tc.verb, joined)
		}
	}
}

// TestExecArgs_RunsInsideExistingJailedNetns pins the forced-egress invariant for
// exec: it is a plain `podman exec` into the EXISTING container (which already
// shares the sidecar's jailed netns) and passes the user's command through. It
// carries NO --filter (podman rejects it on exec; scoping is the guardManaged
// check) and must NEVER add --network or any flag that would give a fresh,
// un-jailed netns.
func TestExecArgs_RunsInsideExistingJailedNetns(t *testing.T) {
	got := manage.ExecArgs(manage.ExecFlags{}, "netcage-run-abc-tool", []string{"sh", "-c", "id"})
	joined := strings.Join(got, " ")
	if got[0] != "exec" {
		t.Fatalf("exec args must start with the podman verb exec; got: %s", joined)
	}
	if strings.Contains(joined, "--filter") {
		t.Fatalf("exec must be a PLAIN pass-through with NO --filter (podman rejects it on exec); scoping is the guardManaged check. got: %s", joined)
	}
	if !strings.Contains(joined, "netcage-run-abc-tool sh -c id") {
		t.Fatalf("exec args must name the container then pass the command through; got: %s", joined)
	}
	// Forced-egress invariant: exec must not introduce any network wiring (a fresh
	// netns would be un-jailed). It only enters the container's existing netns.
	if strings.Contains(joined, "--network") {
		t.Fatalf("exec must NOT set --network (it runs inside the container's existing jailed netns); got: %s", joined)
	}
}

// TestRmDependArgs_RemovesTheSidecarWhichCascadesToTheTool pins how `rm` cleans
// the WHOLE pair: `podman rm -f --depend <sidecar>` removes the sidecar and
// cascades to its `--network container:` dependent tool (the only way to drop
// the sidecar; removing the tool alone would orphan the sidecar). See
// work/notes/findings/podman-network-container-dependency-lifecycle.md.
func TestRmDependArgs_RemovesTheSidecarWhichCascadesToTheTool(t *testing.T) {
	got := strings.Join(manage.RmPairArgs("netcage-run-abc-sidecar"), " ")
	for _, want := range []string{"rm", "-f", "--depend", "netcage-run-abc-sidecar"} {
		if !strings.Contains(got, want) {
			t.Fatalf("rm-pair args missing %q\ngot: %s", want, got)
		}
	}
}

// recordRunner records every podman invocation the orchestration makes and
// answers label/role/run-id inspect queries from a scripted table, so the
// guard-by-label and resolve-the-pair logic is unit-testable WITHOUT a real
// podman (mirrors jail's teardown_unit_test recordRunner).
type recordRunner struct {
	calls   [][]string
	labels  map[string]map[string]string // container name -> label key -> value
	running map[string]bool              // container name -> .State.Running (for the exec jail-health guard)
	specs   []jail.RunSpec               // every RunSpec, so a test can assert Interactive/Stdin wiring
}

// lastExecSpec returns the RunSpec of the last `podman exec ...` call recorded,
// so a test can assert the interactive raw-stdio wiring the exec verb builds.
func (r *recordRunner) lastExecSpec(t *testing.T) jail.RunSpec {
	t.Helper()
	for i := len(r.specs) - 1; i >= 0; i-- {
		if len(r.specs[i].Args) > 0 && r.specs[i].Args[0] == "exec" {
			return r.specs[i]
		}
	}
	t.Fatalf("no `podman exec` call was recorded; calls:\n%s", joinAll(r.calls))
	return jail.RunSpec{}
}

func (r *recordRunner) Run(_ context.Context, spec jail.RunSpec) (string, string, error) {
	r.calls = append(r.calls, spec.Args)
	r.specs = append(r.specs, spec)
	// Answer the inspect queries. Two shapes: the label GUARD (`inspect --format
	// {{...Labels...}} <name>`) and the exec jail-health STATE probe (`inspect
	// --format {{ .State.Running }} <sidecar>`). Distinguish by the format template.
	if len(spec.Args) >= 3 && spec.Args[0] == "inspect" && spec.Args[1] == "--format" {
		format := spec.Args[2]
		name := spec.Args[len(spec.Args)-1]
		if strings.Contains(format, ".State.Running") {
			if r.running == nil {
				return "false", "", nil
			}
			if r.running[name] {
				return "true", "", nil
			}
			return "false", "", nil
		}
		lbls, ok := r.labels[name]
		if !ok {
			return "", "no such container", errNotFound
		}
		// Return managed|role|run-id joined, matching the format the resolver asks for.
		return lbls[jail.LabelManaged] + "\t" + lbls[jail.LabelRole] + "\t" + lbls[jail.LabelRunID], "", nil
	}
	return "", "", nil
}

var errNotFound = &inspectErr{}

type inspectErr struct{}

func (*inspectErr) Error() string { return "no such container" }

func joinAll(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// TestRun_RefusesNonNetcageContainer proves the guard: a named container that
// does NOT carry the netcage.managed label is REFUSED (clear error), and no
// mutating podman verb runs against it. This covers logs/inspect/exec/stop/rm.
func TestRun_RefusesNonNetcageContainer(t *testing.T) {
	for _, verb := range []string{"logs", "inspect", "exec", "stop", "rm"} {
		t.Run(verb, func(t *testing.T) {
			r := &recordRunner{labels: map[string]map[string]string{
				"some-random-container": {}, // exists but NOT netcage-managed
			}}
			args := []string{"some-random-container"}
			if verb == "exec" {
				args = []string{"some-random-container", "sh"}
			}
			err := manage.Run(context.Background(), r, verb, args, manage.IO{})
			if err == nil {
				t.Fatalf("%s of a non-netcage container must be REFUSED", verb)
			}
			if !strings.Contains(err.Error(), "not a netcage-managed container") {
				t.Fatalf("%s refusal must name the reason (not a netcage-managed container); got: %v", verb, err)
			}
			// The refusal must happen BEFORE any ACTION verb runs. The ONLY podman call
			// permitted on the refusal path is the guard's own label probe, which is a
			// distinctive `inspect --format ... <name>` (it carries --format; no action
			// verb does). So exactly one call, and it must be the guard inspect.
			if len(r.calls) != 1 {
				t.Fatalf("%s refusal must make exactly one podman call (the guard inspect); calls: %s", verb, joinAll(r.calls))
			}
			guard := strings.Join(r.calls[0], " ")
			if !strings.HasPrefix(guard, "inspect --format") {
				t.Fatalf("%s must only run the guard `inspect --format ...` probe on a refused container, never an action verb; got: %s", verb, guard)
			}
		})
	}
}

// TestRun_RmResolvesAndRemovesTheSidecarPair proves that `netcage rm <tool>`
// resolves the pair by run-id and removes the SIDECAR with --depend (cascading
// to the tool), so no orphaned sidecar is left even when the user names the
// tool.
func TestRun_RmResolvesAndRemovesTheSidecarPair(t *testing.T) {
	r := &recordRunner{labels: map[string]map[string]string{
		"netcage-run-abc-tool": {
			jail.LabelManaged: "true", jail.LabelRole: jail.RoleTool, jail.LabelRunID: "abc",
		},
	}}
	if err := manage.Run(context.Background(), r, "rm", []string{"netcage-run-abc-tool"}, manage.IO{}); err != nil {
		t.Fatalf("rm of a managed tool: %v", err)
	}
	joined := joinAll(r.calls)
	if !strings.Contains(joined, "rm -f --depend netcage-run-abc-sidecar") {
		t.Fatalf("rm of the tool must remove the SIDECAR with --depend (cascades to the tool); calls: %s", joined)
	}
}

// TestParseExecArgs_SeparatesCuratedFlagsFromNameAndCommand pins the podman-
// faithful parse: the curated exec flags (-i/-t/-w/-e/-u) are parsed BEFORE the
// container name (a podman user writes `netcage exec -it -w /root -e K=V <c>
// bash`), the first non-flag token is the NAME, and everything after it is the
// COMMAND passed through verbatim (its own flags are NOT re-parsed as exec
// flags).
func TestParseExecArgs_SeparatesCuratedFlagsFromNameAndCommand(t *testing.T) {
	flags, name, cmd, err := manage.ParseExecArgs([]string{
		"-it", "-w", "/root", "-e", "K=V", "-e", "J=W", "-u", "root",
		"netcage-run-abc-tool", "bash", "-lc", "id",
	})
	if err != nil {
		t.Fatalf("parse of a valid exec invocation: %v", err)
	}
	if !flags.Interactive || !flags.TTY {
		t.Fatalf("-it must set both Interactive and TTY; got %+v", flags)
	}
	if flags.Workdir != "/root" {
		t.Fatalf("-w must set Workdir=/root; got %q", flags.Workdir)
	}
	if flags.User != "root" {
		t.Fatalf("-u must set User=root; got %q", flags.User)
	}
	if strings.Join(flags.Env, ",") != "K=V,J=W" {
		t.Fatalf("-e must be repeatable and ordered; got %v", flags.Env)
	}
	if name != "netcage-run-abc-tool" {
		t.Fatalf("the first non-flag token must be the container name; got %q", name)
	}
	if strings.Join(cmd, " ") != "bash -lc id" {
		t.Fatalf("everything after the name is the command, verbatim; got %v", cmd)
	}
}

// TestParseExecArgs_RefusesUnknownFlagFailClosed pins the fail-closed-on-the-
// unknown behaviour (like `run`): an exec flag netcage has NOT vetted (e.g. a
// hypothetical jail-breaching one) is REFUSED, and the message names the accepted
// flags so the user knows the curated surface.
func TestParseExecArgs_RefusesUnknownFlagFailClosed(t *testing.T) {
	_, _, _, err := manage.ParseExecArgs([]string{"--privileged", "netcage-run-abc-tool", "sh"})
	if err == nil {
		t.Fatal("an unknown exec flag must be REFUSED (fail-closed on the unknown)")
	}
	if !strings.Contains(err.Error(), "--privileged") {
		t.Fatalf("the refusal must name the offending flag; got: %v", err)
	}
	for _, want := range []string{"-i", "-t", "-w", "-e", "-u"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must list the accepted flag %q; got: %v", want, err)
		}
	}
}

// TestExecArgs_EmitsCuratedFlagsBeforeNameThenCommand pins the argv the exec verb
// builds: `podman exec [flags] <name> <cmd...>`, flags BEFORE the name, command
// verbatim after it, and NO --network (it enters the container's EXISTING jailed
// netns).
func TestExecArgs_EmitsCuratedFlagsBeforeNameThenCommand(t *testing.T) {
	got := manage.ExecArgs(manage.ExecFlags{
		Interactive: true, TTY: true, Workdir: "/root", User: "root", Env: []string{"K=V", "J=W"},
	}, "netcage-run-abc-tool", []string{"bash", "-lc", "id"})
	joined := strings.Join(got, " ")
	if got[0] != "exec" {
		t.Fatalf("exec argv must start with the podman verb exec; got: %s", joined)
	}
	for _, want := range []string{"-i", "-t", "-w /root", "-u root", "-e K=V", "-e J=W"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("exec argv missing %q; got: %s", want, joined)
		}
	}
	// The name then the command, verbatim, at the end.
	if !strings.Contains(joined, "netcage-run-abc-tool bash -lc id") {
		t.Fatalf("exec argv must place the name then the command verbatim; got: %s", joined)
	}
	// Every flag must precede the name (podman requires flags before the container).
	nameIdx := indexOf(got, "netcage-run-abc-tool")
	for _, f := range []string{"-i", "-t", "-w", "-u", "-e"} {
		if idx := indexOf(got, f); idx == -1 || idx >= nameIdx {
			t.Fatalf("flag %q must appear BEFORE the container name; got: %s", f, joined)
		}
	}
	if strings.Contains(joined, "--network") {
		t.Fatalf("exec must NOT set --network (it enters the container's existing jailed netns); got: %s", joined)
	}
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// TestRun_ExecInteractiveWiresRawStdioPath proves the interactive seam WITHOUT
// podman: `netcage exec -it <c> <cmd>` (into a healthy jail) builds a RunSpec
// that carries Interactive + a wired Stdin (the real-PTY raw-passthrough path
// `run -it` uses), so the exec is a usable interactive shell, not capture-only.
// A NON-interactive exec leaves Interactive false and Stdin nil (capture/tee).
func TestRun_ExecInteractiveWiresRawStdioPath(t *testing.T) {
	newRunner := func() *recordRunner {
		return &recordRunner{
			labels: map[string]map[string]string{
				"netcage-run-abc-tool": {
					jail.LabelManaged: "true", jail.LabelRole: jail.RoleTool, jail.LabelRunID: "abc",
				},
			},
			// Healthy jail: BOTH the sidecar and the tool are running.
			running: map[string]bool{"netcage-run-abc-sidecar": true, "netcage-run-abc-tool": true},
		}
	}

	t.Run("interactive -it: Interactive + Stdin wired", func(t *testing.T) {
		r := newRunner()
		stdin := strings.NewReader("keystrokes")
		err := manage.Run(context.Background(), r, "exec",
			[]string{"-it", "netcage-run-abc-tool", "bash"}, manage.IO{Stdin: stdin})
		if err != nil {
			t.Fatalf("interactive exec into a healthy jail: %v", err)
		}
		spec := r.lastExecSpec(t)
		if !spec.Interactive {
			t.Fatal("exec -it must set RunSpec.Interactive (real PTY, raw passthrough)")
		}
		if spec.Stdin == nil {
			t.Fatal("exec -it must wire a Stdin into the RunSpec (stdin passthrough)")
		}
	})

	t.Run("non-interactive: capture path, no Interactive/Stdin", func(t *testing.T) {
		r := newRunner()
		err := manage.Run(context.Background(), r, "exec",
			[]string{"netcage-run-abc-tool", "echo", "hi"}, manage.IO{Stdin: strings.NewReader("ignored")})
		if err != nil {
			t.Fatalf("non-interactive exec into a healthy jail: %v", err)
		}
		spec := r.lastExecSpec(t)
		if spec.Interactive {
			t.Fatal("non-interactive exec must NOT set RunSpec.Interactive (capture/tee path)")
		}
		if spec.Stdin != nil {
			t.Fatal("non-interactive exec must NOT wire Stdin (capture/tee path)")
		}
	})
}

// TestRun_ExecRefusesWhenJailNotHealthy pins the jail-health guarantee: exec into
// a netcage-managed pair is REFUSED unless the forced-egress jail is fully UP -
// either the SIDECAR (netns + firewall + DNS) is stopped, OR the TOOL is stopped
// (a kept pair AT REST). Each is refused with a clear "run `netcage start` first"
// message, and NO `podman exec` is ever issued. A deliberately-down jail must
// never yield a working un-jailed exec.
func TestRun_ExecRefusesWhenJailNotHealthy(t *testing.T) {
	cases := []struct {
		name    string
		running map[string]bool
	}{
		{"sidecar down", map[string]bool{"netcage-run-abc-sidecar": false, "netcage-run-abc-tool": true}},
		{"tool down (kept pair at rest)", map[string]bool{"netcage-run-abc-sidecar": true, "netcage-run-abc-tool": false}},
		{"both down", map[string]bool{"netcage-run-abc-sidecar": false, "netcage-run-abc-tool": false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &recordRunner{
				labels: map[string]map[string]string{
					"netcage-run-abc-tool": {
						jail.LabelManaged: "true", jail.LabelRole: jail.RoleTool, jail.LabelRunID: "abc",
					},
				},
				running: tc.running,
			}
			err := manage.Run(context.Background(), r, "exec",
				[]string{"netcage-run-abc-tool", "sh"}, manage.IO{})
			if err == nil {
				t.Fatal("exec into a container whose jail is not fully up must be REFUSED")
			}
			if !strings.Contains(err.Error(), "netcage start") {
				t.Fatalf("the refusal must tell the user to run `netcage start` first; got: %v", err)
			}
			// No `podman exec` may be issued on the refusal path (only the guard + state
			// probes, both `inspect`). A deliberately-down jail yields NO un-jailed exec.
			for _, c := range r.calls {
				if len(c) > 0 && c[0] == "exec" {
					t.Fatalf("a down-jail refusal must NOT issue `podman exec`; calls:\n%s", joinAll(r.calls))
				}
			}
		})
	}
}

// TestParseCommitArgs_SeparatesCuratedFlagsFromNameAndImageRef pins the podman-
// faithful parse: the curated commit metadata flags are parsed in ANY order
// interleaved with the two required positionals (the netcage container NAME then
// the new IMAGE-REF), value-taking flags consume their value, and boolean flags
// (`--pause`/`-q`) stand alone. A podman user writes `netcage commit -m "msg" -a
// me <c> my-image:tag`.
func TestParseCommitArgs_SeparatesCuratedFlagsFromNameAndImageRef(t *testing.T) {
	flags, name, imageRef, err := manage.ParseCommitArgs([]string{
		"-m", "played with apt", "-a", "me", "-c", "CMD=/bin/bash", "-c", "ENV=X=1",
		"-f", "docker", "--pause", "-q",
		"netcage-run-abc-tool", "my-image:tag",
	})
	if err != nil {
		t.Fatalf("parse of a valid commit invocation: %v", err)
	}
	if flags.Message != "played with apt" {
		t.Fatalf("-m must set Message; got %q", flags.Message)
	}
	if flags.Author != "me" {
		t.Fatalf("-a must set Author; got %q", flags.Author)
	}
	if strings.Join(flags.Change, ",") != "CMD=/bin/bash,ENV=X=1" {
		t.Fatalf("-c must be repeatable and ordered; got %v", flags.Change)
	}
	if flags.Format != "docker" {
		t.Fatalf("-f must set Format; got %q", flags.Format)
	}
	if !flags.Pause {
		t.Fatalf("--pause must set Pause; got %+v", flags)
	}
	if !flags.Quiet {
		t.Fatalf("-q must set Quiet; got %+v", flags)
	}
	if name != "netcage-run-abc-tool" {
		t.Fatalf("the first non-flag token must be the container name; got %q", name)
	}
	if imageRef != "my-image:tag" {
		t.Fatalf("the second non-flag token must be the image-ref; got %q", imageRef)
	}
}

// TestParseCommitArgs_NegatablePause pins podman's `--pause=false` (and
// `--pause=true`) inline form: commit's default is to pause during the snapshot,
// so a user must be able to turn it OFF. --no-pause is NOT a podman commit
// spelling; only the boolean `--pause[=bool]` is.
func TestParseCommitArgs_NegatablePause(t *testing.T) {
	flags, _, _, err := manage.ParseCommitArgs([]string{"--pause=false", "netcage-run-abc-tool", "img:tag"})
	if err != nil {
		t.Fatalf("parse of --pause=false: %v", err)
	}
	if flags.Pause {
		t.Fatalf("--pause=false must clear Pause; got %+v", flags)
	}
	if !flags.PauseSet {
		t.Fatalf("--pause=false must record that pause was explicitly SET (so the argv emits it); got %+v", flags)
	}
}

// TestParseCommitArgs_RefusesUnknownFlagFailClosed pins the fail-closed-on-the-
// unknown behaviour (like `run`/`exec`): a commit flag netcage has NOT vetted is
// REFUSED, and the message names the accepted flags so the user knows the curated
// surface.
func TestParseCommitArgs_RefusesUnknownFlagFailClosed(t *testing.T) {
	_, _, _, err := manage.ParseCommitArgs([]string{"--squash", "netcage-run-abc-tool", "img:tag"})
	if err == nil {
		t.Fatal("an unknown commit flag must be REFUSED (fail-closed on the unknown)")
	}
	if !strings.Contains(err.Error(), "--squash") {
		t.Fatalf("the refusal must name the offending flag; got: %v", err)
	}
	for _, want := range []string{"-m", "-a", "-c", "-f", "--pause", "-q"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must list the accepted flag %q; got: %v", want, err)
		}
	}
}

// TestParseCommitArgs_RequiresContainerAndImageRef pins that both positionals are
// required: `netcage commit` with no args, or with only the container name (no
// image-ref), is refused with a clear message (the image-ref is the new image
// name to write).
func TestParseCommitArgs_RequiresContainerAndImageRef(t *testing.T) {
	if _, _, _, err := manage.ParseCommitArgs(nil); err == nil {
		t.Fatal("commit with no container name must be refused")
	}
	if _, _, _, err := manage.ParseCommitArgs([]string{"netcage-run-abc-tool"}); err == nil {
		t.Fatal("commit with a container but no image-ref must be refused")
	}
}

// TestCommitArgs_SnapshotsTheToolToTheImage pins the argv the commit verb builds:
// `podman commit [curated flags] <tool> <image-ref>`. The curated metadata flags
// precede the tool name (podman's order), then the tool, then the image-ref. It
// commits the TOOL container's FILESYSTEM to a new image; it must NEVER add any
// network wiring (commit is a pure filesystem->image snapshot, inherently
// jail-neutral).
func TestCommitArgs_SnapshotsTheToolToTheImage(t *testing.T) {
	got := manage.CommitArgs(manage.CommitFlags{
		Message: "played", Author: "me", Change: []string{"CMD=/bin/bash"},
		Format: "docker", Pause: true, PauseSet: true, Quiet: true,
	}, "netcage-run-abc-tool", "my-image:tag")
	joined := strings.Join(got, " ")
	if got[0] != "commit" {
		t.Fatalf("commit argv must start with the podman verb commit; got: %s", joined)
	}
	for _, want := range []string{"-m played", "-a me", "-c CMD=/bin/bash", "-f docker", "--pause", "-q"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commit argv missing %q; got: %s", want, joined)
		}
	}
	// The tool then the image-ref, in that order, at the end.
	if !strings.Contains(joined, "netcage-run-abc-tool my-image:tag") {
		t.Fatalf("commit argv must place the tool then the image-ref; got: %s", joined)
	}
	// Every flag must precede the container name (podman requires flags before it).
	nameIdx := indexOf(got, "netcage-run-abc-tool")
	for _, f := range []string{"-m", "-a", "-c", "-f", "--pause", "-q"} {
		if idx := indexOf(got, f); idx == -1 || idx >= nameIdx {
			t.Fatalf("flag %q must appear BEFORE the container name; got: %s", f, joined)
		}
	}
	// Forced-egress / jail-neutral invariant: commit must NEVER wire a network (it
	// is a filesystem->image snapshot, it never starts or networks the container).
	if strings.Contains(joined, "--network") {
		t.Fatalf("commit must NOT set --network (it is a pure filesystem->image snapshot); got: %s", joined)
	}
}

// TestCommitArgs_OmitsUnsetFlags pins that a bare `netcage commit <c> <ref>`
// (no metadata flags) builds a MINIMAL `podman commit <tool> <ref>` with no
// stray flags, so podman's own defaults apply (default --pause included).
func TestCommitArgs_OmitsUnsetFlags(t *testing.T) {
	got := strings.Join(manage.CommitArgs(manage.CommitFlags{}, "netcage-run-abc-tool", "img:tag"), " ")
	want := "commit netcage-run-abc-tool img:tag"
	if got != want {
		t.Fatalf("bare commit must be %q; got %q", want, got)
	}
}

// TestRun_CommitResolvesToolAndSnapshotsIt proves the happy path end to end (no
// podman): `netcage commit <tool> <image-ref>` GUARDS the named container is
// netcage-managed, resolves the run's TOOL container by run-id, and runs `podman
// commit <tool> <image-ref>` against it. Naming the tool commits THAT tool.
func TestRun_CommitResolvesToolAndSnapshotsIt(t *testing.T) {
	r := &recordRunner{labels: map[string]map[string]string{
		"netcage-run-abc-tool": {
			jail.LabelManaged: "true", jail.LabelRole: jail.RoleTool, jail.LabelRunID: "abc",
		},
	}}
	if err := manage.Run(context.Background(), r, "commit",
		[]string{"-m", "snap", "netcage-run-abc-tool", "my-image:tag"}, manage.IO{}); err != nil {
		t.Fatalf("commit of a managed tool: %v", err)
	}
	joined := joinAll(r.calls)
	if !strings.Contains(joined, "commit -m snap netcage-run-abc-tool my-image:tag") {
		t.Fatalf("commit must snapshot the resolved tool to the image-ref; calls:\n%s", joined)
	}
	// Jail-neutral: commit must NEVER start the container or wire a network.
	if strings.Contains(joined, "start ") || strings.Contains(joined, "--network") {
		t.Fatalf("commit must NOT start or network the container (it is snapshot-only); calls:\n%s", joined)
	}
}

// TestRun_CommitRefusesSidecar pins that naming the netcage SIDECAR (role=sidecar)
// is REFUSED with a message directing the user to the TOOL container (commit takes
// the tool, mirroring `netcage start`), and NO `podman commit` runs against it.
func TestRun_CommitRefusesSidecar(t *testing.T) {
	r := &recordRunner{labels: map[string]map[string]string{
		"netcage-run-abc-sidecar": {
			jail.LabelManaged: "true", jail.LabelRole: jail.RoleSidecar, jail.LabelRunID: "abc",
		},
	}}
	err := manage.Run(context.Background(), r, "commit",
		[]string{"netcage-run-abc-sidecar", "img:tag"}, manage.IO{})
	if err == nil {
		t.Fatal("commit of the netcage SIDECAR must be REFUSED (commit takes the tool)")
	}
	if !strings.Contains(err.Error(), "tool") {
		t.Fatalf("the sidecar refusal must direct the user to the TOOL container; got: %v", err)
	}
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "commit" {
			t.Fatalf("a sidecar refusal must NOT issue `podman commit`; calls:\n%s", joinAll(r.calls))
		}
	}
}

// TestRun_CommitRefusesNonNetcageContainer pins the label guard for commit: a
// container that does NOT carry the netcage.managed label is REFUSED before any
// `podman commit` runs against it.
func TestRun_CommitRefusesNonNetcageContainer(t *testing.T) {
	r := &recordRunner{labels: map[string]map[string]string{
		"some-random-container": {}, // exists but NOT netcage-managed
	}}
	err := manage.Run(context.Background(), r, "commit",
		[]string{"some-random-container", "img:tag"}, manage.IO{})
	if err == nil {
		t.Fatal("commit of a non-netcage container must be REFUSED")
	}
	if !strings.Contains(err.Error(), "not a netcage-managed container") {
		t.Fatalf("the refusal must name the reason; got: %v", err)
	}
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "commit" {
			t.Fatalf("a non-netcage refusal must NOT issue `podman commit`; calls:\n%s", joinAll(r.calls))
		}
	}
}

// TestRun_NamedVerbAcceptsManagedContainer proves the happy path: a managed
// container passes the guard and the verb's podman argv runs against it.
func TestRun_NamedVerbAcceptsManagedContainer(t *testing.T) {
	r := &recordRunner{labels: map[string]map[string]string{
		"netcage-run-abc-tool": {
			jail.LabelManaged: "true", jail.LabelRole: jail.RoleTool, jail.LabelRunID: "abc",
		},
	}}
	if err := manage.Run(context.Background(), r, "logs", []string{"netcage-run-abc-tool"}, manage.IO{}); err != nil {
		t.Fatalf("logs of a managed tool: %v", err)
	}
	if !strings.Contains(joinAll(r.calls), "logs") {
		t.Fatalf("logs of a managed container must run podman logs; calls: %s", joinAll(r.calls))
	}
}
