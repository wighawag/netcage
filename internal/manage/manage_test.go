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
	got := manage.ExecArgs("netcage-run-abc-tool", []string{"sh", "-c", "id"})
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
	calls  [][]string
	labels map[string]map[string]string // container name -> label key -> value
}

func (r *recordRunner) Run(_ context.Context, spec jail.RunSpec) (string, string, error) {
	r.calls = append(r.calls, spec.Args)
	// Answer the inspect query used to guard/resolve: `inspect --format <tmpl> <name>`.
	if len(spec.Args) >= 2 && spec.Args[0] == "inspect" {
		name := spec.Args[len(spec.Args)-1]
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
