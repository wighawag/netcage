package jail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Start is the jail-aware `netcage start <name>` verb: it REVIVES a kept,
// netcage-managed tool container with its full forced-egress jail restored, so a
// named reusable jailed container is a durable environment (the primitive a
// downstream "machine" is built from). It is the ONLY supported reuse path (a raw
// `podman start` outside netcage stays fail-closed but leaves DNS dead, ADR-0008).
//
// Sequence (proven sufficient by spiking; see
// work/notes/findings/netcage-start-sidecar-revive-is-sufficient.md):
//
//  1. Resolve <name> to a netcage-MANAGED tool container (by the netcage.managed
//     label + role=tool) and read its run id, so a non-netcage or unknown
//     container is REFUSED before anything is touched.
//  2. RECONCILE the REQUESTED jail config (cfg.Proxy / cfg.AllowDirect) against
//     the container's BAKED config (read from the sidecar's create-time env). A
//     SAME config REVIVES; a DIFFERENT --proxy/--allow is REFUSED
//     (ErrJailConfigChanged), never silently revived stale, never rebuilt-and-
//     state-lost.
//  3. Revive the sidecar (`podman start <sidecar>`; the baked EXTRA_COMMANDS
//     firewall re-applies on start, ADR-0008), then VERIFY the firewall is fully
//     present (same iptables -S probe as the run path; the fail-loud layer applies
//     to start too), then re-exec the netcage-dns forwarder INTO the sidecar (a
//     SEPARATE process, not baked into EXTRA_COMMANDS, so a restart leaves it dead
//     until this step restores it), then start/attach the tool.
//  4. On exit the same teardown split applies (Ephemeral true -> remove both;
//     false -> leave both stopped, fail-closed via the baked firewall).
//
// The forced-egress invariant is paramount and restored BEFORE the tool runs: the
// tool is never started until the firewall is verified present and the DNS
// forwarder is up. A changed jail config is refused, never silently revived; a
// restarted container passes the same leak assertions as a fresh run.
//
// resolveName is the user-supplied container NAME (the tool's, typically); Start
// resolves it to the run-attributable pair via the labels.
func Start(ctx context.Context, r Runner, cfg Config, resolveName string) (Result, error) {
	// 1. Resolve the named container to a netcage-managed TOOL (by label) and read
	// its run id, so the sidecar/tool names are the run-attributable ones. A
	// non-netcage or unknown container is refused here, before any jail work.
	runID, err := resolveManagedTool(ctx, r, resolveName)
	if err != nil {
		return Result{}, err
	}
	cfg.RunID = runID

	// Resolve the netcage-dns helper before touching the jail (it is re-exec'd into
	// the revived sidecar); fail early rather than half-revive.
	dnsBin, err := dnsHelperPath()
	if err != nil {
		return Result{}, err
	}
	cfg.dnsHelperPath = dnsBin

	// 2. RECONCILE the requested jail config against the container's baked config.
	// A changed --proxy/--allow is REFUSED (state-preserving) rather than
	// silently reviving a stale jail or rebuilding and losing container state.
	baked, err := readBakedSidecarConfig(ctx, r, cfg.sidecarName())
	if err != nil {
		return Result{}, err
	}
	if err := reconcileJailConfig(cfg, baked); err != nil {
		return Result{}, err
	}

	// Teardown honours the SAME lifecycle split as run (ADR-0009): a kept start
	// leaves the pair stopped + fail-closed; an ephemeral one removes both. Deferred
	// on a fresh context so a cancelled ctx still cleans up.
	defer func() {
		tdCtx, tdCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tdCancel()
		if err := Teardown(tdCtx, r, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "netcage: teardown: %v\n", err)
		}
	}()

	// 3a. REVIVE the sidecar: a plain `podman start` of the EXISTING sidecar. The
	// pinned tun2socks entrypoint re-runs the baked EXTRA_COMMANDS firewall on every
	// start (ADR-0008), so the firewall self-heals on this revive.
	if _, serr, err := runPodman(ctx, r, cfg.SidecarStartArgs()...); err != nil {
		return Result{}, fmt.Errorf("revive tun2socks sidecar: %w%s", err, stderrSuffix(serr))
	}

	// 3b. VERIFY the firewall INSIDE the revived sidecar (the fail-loud layer,
	// ADR-0008): EXTRA_COMMANDS self-heals on restart but cannot abort the sidecar
	// on a half-apply, so netcage asserts the exact rule set is present and aborts
	// LOUDLY if partial. `netcage start` is a netcage-driven path, so it gets the
	// fail-loud layer too, not just `run`.
	if err := verifyFirewall(ctx, r, cfg); err != nil {
		return Result{}, fmt.Errorf("verify firewall after reviving sidecar: %w", err)
	}

	// 3c. Re-exec the DNS forwarder INTO the sidecar. It is a SEPARATE process (not
	// baked into EXTRA_COMMANDS), so a restart leaves it dead until this restores
	// it. Without this the revived jail is fail-closed but names do not resolve; WITH
	// it the durable environment resumes with full function.
	if err := startSidecarDNS(ctx, r, cfg); err != nil {
		return Result{}, fmt.Errorf("re-exec in-jail DNS forwarder: %w", err)
	}
	cfg.dnsServer = "127.0.0.1:53"

	// Re-materialise the tool's resolv.conf at the SAME stable path it bind-mounts
	// (baked at create as resolvConfPathFor(runID)). A kept run leaves this durable,
	// but a revive on another host, or after a temp-dir sweep, would otherwise fail
	// with crun "cannot stat" when podman re-mounts the now-missing source. Writing
	// it here (idempotent) makes `netcage start` self-sufficient. An ephemeral start
	// removes it again via Teardown (centralised there, and in `netcage rm`).
	resolvPath := resolvConfPathFor(cfg.RunID)
	if err := writeResolvConfAt(resolvPath); err != nil {
		return Result{}, fmt.Errorf("re-materialise tool resolv.conf for start: %w", err)
	}

	// Re-materialise the sanitized /etc/hosts at the SAME stable path the tool
	// bind-mounts (baked at create as hostsPathFor(runID)), for the same reason as
	// the resolv.conf above: a revive on another host or after a temp-dir sweep
	// would otherwise fail with crun "cannot stat" when podman re-mounts the missing
	// source. Idempotent; an ephemeral start removes it again via Teardown.
	if err := writeHostsAt(hostsPathFor(cfg.RunID)); err != nil {
		return Result{}, fmt.Errorf("re-materialise tool /etc/hosts for start: %w", err)
	}

	// 3d. reachback diagnostic for a host-loopback proxy (as the run path), so an
	// unreachable proxy port is a clear message, not an opaque tool failure.
	if cfg.ProxyOnHostLoopback {
		if err := checkReachback(ctx, r, cfg); err != nil {
			return Result{}, fmt.Errorf("%w: %v (is the proxy listening on the host's 127.0.0.1:%s? the jail reaches it via the pasta map %s)",
				ErrReachback, err, cfg.Proxy.Port, mappedHostLoopback)
		}
	}

	// 4. START/attach the EXISTING tool (never a fresh `run`, so its state is
	// intact). The jail is fully restored above, so the tool never runs before its
	// forced-egress jail is back.
	out, errOut, runErr := r.Run(ctx, cfg.toolStartSpec())
	res := Result{ToolStdout: out, ToolStderr: errOut}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			if setupErr := classifyPodmanSetupFailure(ee.ExitCode(), errOut); setupErr != nil {
				return res, setupErr
			}
			res.ToolExit = ee.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("start wrapped tool: %w%s", runErr, stderrSuffix(errOut))
	}
	return res, nil
}

// ErrJailConfigChanged is the REFUSAL when `netcage start` is invoked with a jail
// config (--proxy / --allow) that DIFFERS from the one the container was
// created with. The safe default is to refuse (state-preserving) rather than
// silently revive a stale jail or rebuild-and-lose the container's state (the
// finding's decided policy). A future explicit rebuild flag can be a follow-up.
var ErrJailConfigChanged = errors.New("this container was jailed with a different proxy/allowlist")

// ErrNotManaged is the REFUSAL when `netcage start` is pointed at a container
// that is not netcage-managed (missing the netcage.managed label): a non-netcage
// or unknown container. It mirrors the manage package's guard so start refuses an
// unmanaged container the same way the pass-through verbs do, without importing
// manage (which would be a cycle: manage imports jail).
var ErrNotManaged = errors.New("not a netcage-managed container")

// isJailConfigChanged reports whether err is (or wraps) the changed-config
// refusal, so tests and callers can distinguish it from other start failures.
func isJailConfigChanged(err error) bool { return errors.Is(err, ErrJailConfigChanged) }

// bakedSidecarConfig is the jail config a sidecar was CREATED with, read from its
// three create-time env values (podman inspect). Together they fully encode the
// --proxy + --allow config: PROXY is the socks5 upstream, ExcludedRoutes
// is TUN_EXCLUDED_ROUTES (the proxy reachback + each allowlisted direct), and
// ExtraCommands is the baked firewall script (the allowlist accepts + RFC1918
// drops). reconcileJailConfig compares these against what the REQUESTED config
// would bake, so a changed jail config is detected without re-deriving each flag.
type bakedSidecarConfig struct {
	Proxy          string // sidecar PROXY= (socks5://... upstream)
	ExcludedRoutes string // sidecar TUN_EXCLUDED_ROUTES= (proxy reachback + directs)
	ExtraCommands  string // sidecar EXTRA_COMMANDS= (the baked firewall script)
}

// reconcileJailConfig decides REVIVE vs REFUSE for `netcage start`: it compares
// what the REQUESTED config (cfg) would BAKE into a fresh sidecar against what the
// existing container was ACTUALLY created with (baked). If all three baked-env
// values match, the jail config is unchanged -> REVIVE (nil). If any differs, the
// requested --proxy/--allow is not the one the container carries -> REFUSE
// (ErrJailConfigChanged), so a stale jail is never silently revived and the
// container's state is never silently discarded.
//
// Comparing the DERIVED env values (not the raw flags) is the robust check: the
// sidecar bakes exactly these, so equal baked env == an identical jail, and it
// naturally covers proxy host/port/auth AND the full allowlist (accepts, excluded
// routes, RFC1918 drops) in one comparison, matching what the container will
// actually run on revive.
func reconcileJailConfig(cfg Config, baked bakedSidecarConfig) error {
	want := bakedSidecarConfig{
		Proxy:          cfg.sidecarProxyURL(),
		ExcludedRoutes: cfg.excludedRoutes(),
		ExtraCommands:  cfg.firewallScript(cfg.Proxy.Port),
	}
	if want == baked {
		return nil
	}
	var diffs []string
	if want.Proxy != baked.Proxy {
		diffs = append(diffs, "proxy")
	}
	if want.ExcludedRoutes != baked.ExcludedRoutes || want.ExtraCommands != baked.ExtraCommands {
		diffs = append(diffs, "allowlist/firewall")
	}
	return fmt.Errorf("%w (%s differs); remove it and run again, or start it with the same jail config",
		ErrJailConfigChanged, strings.Join(diffs, " + "))
}

// readBakedSidecarConfig reads the three create-time env values off the stopped
// sidecar via `podman inspect`, so reconcileJailConfig can compare the requested
// jail config against what the container was actually created with. The inspect
// goes through the Runner seam (pure podman client), so start can drive a remote
// podman too (ADR-0006).
//
// .Config.Env is fetched as JSON (a []string of "KEY=VALUE") and parsed, NOT via
// a newline-joined text template: the EXTRA_COMMANDS firewall value ITSELF
// contains newlines, so a `{{range}}...{{"\n"}}` template would split one env var
// across lines and truncate the baked firewall to its first line (silently making
// every reconcile falsely see a changed config). JSON keeps each element intact.
func readBakedSidecarConfig(ctx context.Context, r Runner, sidecarName string) (bakedSidecarConfig, error) {
	out, serr, err := runPodman(ctx, r, "inspect", "--format", "{{json .Config.Env}}", sidecarName)
	if err != nil {
		return bakedSidecarConfig{}, fmt.Errorf("inspect the container's baked jail config (sidecar %s): %w%s", sidecarName, err, stderrSuffix(serr))
	}
	var env []string
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		return bakedSidecarConfig{}, fmt.Errorf("parse the sidecar %s env (inspect json): %w", sidecarName, err)
	}
	var b bakedSidecarConfig
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PROXY="); ok {
			b.Proxy = v
		} else if v, ok := strings.CutPrefix(kv, "TUN_EXCLUDED_ROUTES="); ok {
			b.ExcludedRoutes = v
		} else if v, ok := strings.CutPrefix(kv, "EXTRA_COMMANDS="); ok {
			b.ExtraCommands = v
		}
	}
	return b, nil
}

// resolveManagedTool resolves a user-supplied container NAME to the run id of a
// netcage-MANAGED TOOL container, REFUSING (ErrNotManaged-style) a non-netcage or
// unknown container before any jail work. It reads the create-time labels
// (netcage.managed / role / run-id) via one inspect; the named container must be
// managed AND be the tool role (start revives the tool + its sidecar, so naming a
// bare sidecar is refused with a clear message).
func resolveManagedTool(ctx context.Context, r Runner, name string) (string, error) {
	format := fmt.Sprintf("{{ index .Config.Labels %q }}\t{{ index .Config.Labels %q }}\t{{ index .Config.Labels %q }}",
		LabelManaged, LabelRole, LabelRunID)
	out, serr, err := runPodman(ctx, r, "inspect", "--format", format, name)
	if err != nil {
		return "", fmt.Errorf("%q is not a netcage-managed container (inspect failed): %w%s", name, err, stderrSuffix(serr))
	}
	fields := strings.SplitN(strings.TrimSpace(out), "\t", 3)
	if len(fields) < 3 || fields[0] != "true" {
		return "", fmt.Errorf("%q is %w (missing the %s label); refusing to start it", name, ErrNotManaged, LabelManaged)
	}
	role, runID := fields[1], fields[2]
	if role != RoleTool {
		return "", fmt.Errorf("%q is a netcage %s, not a tool container; `netcage start` takes the TOOL container name (it revives the tool + its sidecar)", name, role)
	}
	if runID == "" {
		return "", fmt.Errorf("%q is netcage-managed but carries no run id label (%s); cannot resolve its sidecar", name, LabelRunID)
	}
	return runID, nil
}

// SidecarStartArgs returns the podman args to REVIVE the existing sidecar: a
// plain `podman start <sidecar>` of the container that already exists (created by
// the original run). It is NOT a fresh create: the sidecar's baked env (PROXY /
// TUN_EXCLUDED_ROUTES / EXTRA_COMMANDS firewall) is retained by the container, so
// podman re-applies the firewall on start (ADR-0008). Exposed for testing the
// wiring without executing podman.
func (c Config) SidecarStartArgs() []string {
	return []string{"start", c.sidecarName()}
}

// ToolStartArgs returns the podman args to re-enter the KEPT tool container:
// `podman start` of the EXISTING container (preserving its in-container state),
// NEVER a fresh `podman run` (which would lose state and re-create it). It
// ATTACHES so the tool's output flows through to netcage:
//
//   - non-interactive: `podman start -a <tool>` (attach stdout/stderr).
//   - interactive (`netcage start -it`): `podman start -ai <tool>` (attach a TTY +
//     stdin) so a human/agent resumes a shell in the durable jailed environment.
//
// The container already carries its --network container:<sidecar> linkage and its
// resolv.conf mount from create time, so reviving it re-enters the SAME jailed
// netns; start does not (and cannot) re-specify those on a plain `podman start`.
func (c Config) ToolStartArgs() []string {
	args := []string{"start"}
	if c.Interactive {
		// Attach stdin + a TTY to the revived tool (podman `start -ai`).
		args = append(args, "-a", "-i")
	} else {
		// Attach stdout/stderr so the tool's output flows through (podman `start -a`).
		args = append(args, "-a")
	}
	return append(args, c.toolName())
}

// toolStartSpec builds the RunSpec for re-entering the kept tool, choosing raw
// stdio passthrough for an interactive start (like toolRunSpec does for run) so a
// resumed shell behaves like a normal attached container; a non-interactive start
// captures/tees the tool's output for the caller.
func (c Config) toolStartSpec() RunSpec {
	spec := RunSpec{Name: "podman", Args: c.ToolStartArgs()}
	if c.Interactive {
		spec.Interactive = true
		spec.Stdin = c.ToolStdin
		return spec
	}
	spec.Stdout = c.ToolStdout
	spec.Stderr = c.ToolStderr
	return spec
}
