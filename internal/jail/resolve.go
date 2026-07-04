package jail

import (
	"context"
	"fmt"
	"strings"
)

// ResolveManagedRun resolves a user-supplied container NAME to the run id of a
// netcage-MANAGED run, REFUSING (ErrNotManaged) a non-netcage or unknown
// container before any verb work (label-scoping, ADR-0009). It reads the
// create-time labels (netcage.managed / role / run-id) via ONE inspect through
// the Runner seam and is deliberately ROLE-AGNOSTIC: either the tool or the
// sidecar name resolves to the SAME run (both carry the run-id label), because a
// caller that wants a specific role rebuilds the name from the run id with
// ToolNameFor / SidecarNameFor.
//
// This is the SINGLE shared home for the label -> run-id resolution the
// host-access verbs (`forward`, `ports`) both need. Before it, that resolution
// was forked package-private in several places (`internal/forward`,
// `internal/jail` start, `internal/manage` guardManaged); the read-only verbs
// converge on this one exported function instead of copying it a fourth time.
// `netcage start`'s resolveManagedTool stays separate on purpose: it additionally
// REFUSES a non-tool role (start revives the tool + its sidecar), a stricter
// contract than the role-agnostic resolution here.
func ResolveManagedRun(ctx context.Context, r Runner, name string) (string, error) {
	format := fmt.Sprintf("{{ index .Config.Labels %q }}\t{{ index .Config.Labels %q }}\t{{ index .Config.Labels %q }}",
		LabelManaged, LabelRole, LabelRunID)
	out, serr, err := runPodman(ctx, r, "inspect", "--format", format, name)
	if err != nil {
		return "", fmt.Errorf("%q is not a netcage-managed container (inspect failed): %w%s", name, err, stderrSuffix(serr))
	}
	fields := strings.SplitN(strings.TrimSpace(out), "\t", 3)
	if len(fields) < 3 || fields[0] != "true" {
		return "", fmt.Errorf("%q is %w (missing the %s label); refusing to touch it", name, ErrNotManaged, LabelManaged)
	}
	runID := fields[2]
	if runID == "" {
		return "", fmt.Errorf("%q is netcage-managed but carries no run id label (%s); cannot resolve its containers", name, LabelRunID)
	}
	return runID, nil
}

// ToolNameFor / SidecarNameFor rebuild the run-attributable container names from a
// run id, matching netcage's naming convention (netcage-run-<id>-<role>). They are
// the exported form of the name builders forward/manage/start each carried
// privately, so a caller that resolved a run id (ResolveManagedRun) can address
// either container without re-implementing the convention.
func ToolNameFor(runID string) string    { return "netcage-run-" + runID + "-tool" }
func SidecarNameFor(runID string) string { return "netcage-run-" + runID + "-sidecar" }
