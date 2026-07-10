// Package jail stands up netcage's forced-egress jail: the wrapped tool runs
// with ALL its TCP egress forced through a tun2socks sidecar (the jail's only
// route out), all UDP hard-dropped, DNS resolved proxy-side via a
// DNS-to-SOCKS-TCP forwarder, and a fail-closed default (proxy down => no
// egress). The design (Option A, shared netns) and recipes come from the spikes:
//
//   - work/notes/findings/spike-rootless-tun-routing.md  (rootless TUN routing)
//   - work/notes/findings/spike-pasta-loopback-reachback.md (pasta + nft narrowing)
//   - work/notes/findings/spike-dns-to-socks-bridge.md   (DNS-to-SOCKS-TCP)
//
// ADRs: 0001 (tun2socks sidecar), 0002 (pasta reachback, sidecar-scoped),
// 0003 (hard-block all UDP; DNS is proxy-side over TCP).
//
// Topology (Option A): a tun2socks sidecar container creates a TUN and routes
// everything to it; the tool container joins the sidecar's netns via
// `--network container:<sidecar>` so its egress hits the TUN and is forced
// through the proxy. A firewall (iptables, baked into the sidecar's create-time
// `EXTRA_COMMANDS` env so it re-applies on every (re)start, ADR-0008 refining
// ADR-0006; netcage verifies it after start as the fail-loud layer) drops all UDP
// egress in the shared netns and narrows host-loopback reachback to exactly the
// proxy port. A DNS forwarder (the
// netcage-dns helper, mounted into the sidecar and exec'd there) resolves names
// via the proxy over TCP. Everything is labeled run-attributably and torn down
// on exit. Because every in-netns step goes through podman (never host nsenter),
// the host needs no nft/nsenter binaries and netcage can drive a remote podman
// (ADR-0006).
package jail

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/net/proxy"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/redirector"
)

// mappedHostLoopback is the dedicated link-local address pasta maps to host
// loopback (spike-pasta-loopback-reachback). Chosen so it is not a real LAN host
// and the firewall narrowing rule's destination is stable.
const mappedHostLoopback = "169.254.1.1"

// pastaIfName is the FIXED, neutral name pasta gives the in-netns interface (via
// its `-I,<name>` option, composed into the pasta network arg in SidecarRunArgs).
// It hides the NIC-name leak (Leak 5, ADR-0013): pasta's default is to reuse the
// host default-route NIC's NAME inside the netns, and under systemd predictable
// naming that name is often `enx<MAC>`, whose NAME re-exposes the host NIC MAC
// even though pasta already synthesizes a fake MAC. Renaming the interface to a
// fixed constant removes that leak. It is a CONSTANT (not run-scoped): the name
// carries no identity, so there is nothing to vary per run, and a stable name
// keeps the wiring test and any interface-name assertion deterministic. The route
// out is still the TUN, so the rename does not touch forced egress (ADR-0013,
// live-verified in the jail-leaks observation).
const pastaIfName = "netcage0"

// fixedHostname is the FIXED, neutral hostname netcage sets on the tool container
// (via --hostname) so /etc/hostname and the container's own name do not reveal or
// mirror the host machine name (Leak 1, ADR-0013). It is a CONSTANT (not the run
// id): the point is a NEUTRAL value that carries no host or run identity, and a
// run-id hostname would just introduce a different correlator. It is netcage's
// DEFAULT only: it is emitted BEFORE the vetted pass-through flags (ToolRunArgs),
// so a user who explicitly passes `--hostname` (an ADR-0010 allow-list flag) still
// wins under podman's last-flag-wins semantics.
const fixedHostname = "netcage"

// sidecarDNSHelperPath is where the netcage-dns helper is mounted inside the
// sidecar container (read-only) and exec'd from (ADR-0006: the forwarder runs
// INSIDE the sidecar via `podman exec -d`, so the host needs no nsenter). The
// helper must be a STATIC binary (the release builds are CGO_ENABLED=0): the
// sidecar image is musl-based, so a glibc-dynamic helper fails to exec there.
const sidecarDNSHelperPath = "/usr/local/bin/netcage-dns"

// Config is a resolved jail run.
type Config struct {
	Proxy    cli.ProxyConfig
	Image    string
	ToolArgv []string
	Mounts   []string // podman -v values, passed through
	Workdir  string   // podman -w/--workdir; empty leaves the image's own workdir
	RunID    string   // run-attributable id; containers named netcage-run-<RunID>-*

	// Env, User and Entrypoint are the podman -e/--env (repeatable), -u/--user, and
	// --entrypoint pass-throughs (from cli.Command). They are NONE of them
	// network/isolation-relevant (env vars, the in-container uid/gid, and the
	// command the container starts), so they are safe to pass to the tool container.
	// They were parsed by the CLI but historically NEVER wired here (silently
	// dropped); ToolRunArgs now emits them so `-e KEY=VALUE` sets the env, `-u` runs
	// as that user, and `--entrypoint` overrides the image entrypoint. Empty leaves
	// the image's own defaults intact (like plain `podman run`).
	Env        []string // podman -e/--env values, repeatable
	User       string   // podman -u/--user; empty leaves the image's own user
	Entrypoint string   // podman --entrypoint; empty leaves the image's own entrypoint

	// PassThroughFlags is the ORDERED, verbatim podman-run token stream for the
	// widened, vetted allow-list flags (ADR-0010), populated from
	// cli.Command.PassThroughFlags. ToolRunArgs emits it BEFORE the image so each
	// flag reaches the tool container's podman argv exactly as the user wrote it
	// (order + repetition preserved). Only flags that pass the vetting checklist
	// (they cannot alter network/netns, add caps/devices/privilege, publish/bind
	// ports, affect DNS/resolv, or collide with a netcage-owned name/lifecycle
	// field) are ever added by the CLI parser, so passing them through does not
	// weaken forced egress.
	PassThroughFlags []string

	// AllowDirect is the validated split-tunnel LAN allowlist: private-only
	// destinations (network + EXACT TCP port) the jailed tool may reach
	// DIRECTLY over the real NIC instead of through the proxy, while ALL other
	// egress stays forced through the proxy, fail-closed. EMPTY (the default) ==
	// today's byte-identical strict jail: no extra excluded routes, no accept
	// rules, no RFC1918 drops. A NON-EMPTY allowlist adds BOTH halves the spike
	// proved are jointly required (each alone is insufficient): each net is added
	// to the sidecar's TUN_EXCLUDED_ROUTES (SidecarRunArgs, the ENABLER) AND an
	// ACCEPT rule before RFC1918-range drops (firewallScript, the NARROWING).
	// TCP-only; UDP stays hard-dropped (ADR-0003) even
	// to an allowlisted host. See ADR-0005 + work/notes/findings/
	// spike-split-tunnel-lan-allowlist.md. Populated from cli.Command.AllowDirect.
	AllowDirect []cli.DirectAllow

	// Ephemeral selects the tool-container / jail LIFECYCLE (podman-fidelity split,
	// ADR-0009). It decouples the two concerns that used to be conflated (the tool
	// was hard-`--rm`'d AND force-removed at teardown):
	//
	//   - Ephemeral TRUE == remove-both on exit. The tool container runs with
	//     `--rm` (podman removes it) and Teardown removes BOTH the tool and the
	//     sidecar, so nothing is left behind. This is what the netcage-owned `--rm`
	//     user flag maps to, and what EVERY internal one-shot sets (verify probes,
	//     reachback/direct probes, declarative runs) so they stay residue-free.
	//   - Ephemeral FALSE (the default, a plain `netcage run` with no `--rm`) ==
	//     leave-both. The tool container omits `--rm` (podman leaves it stopped,
	//     inspectable/restartable like `podman run`) and Teardown removes NEITHER,
	//     leaving the stopped tool + its stopped sidecar behind. The pair is
	//     fail-closed at rest and on any restart via the sidecar's baked
	//     EXTRA_COMMANDS firewall (ADR-0008), so leaving it is safe.
	//
	// "Sidecar gone, tool kept" is NOT a reachable state: podman refuses to remove
	// a `--network container:` sidecar while its dependent tool exists, and
	// `rm --depend` cascades to the tool (see
	// work/notes/findings/podman-network-container-dependency-lifecycle.md). So the
	// only two coherent end-states are both-gone (ephemeral) and both-kept (kept).
	Ephemeral bool

	// ProxyOnHostLoopback indicates the proxy listens on the HOST's 127.0.0.1
	// (local Tor / ssh -D), so the sidecar reaches it via the pasta map. When
	// false the proxy is a normal routable host the sidecar dials directly.
	ProxyOnHostLoopback bool

	// ToolStdout and ToolStderr are OPTIONAL live sinks for the wrapped tool's
	// output. When set, the tool's stdout/stderr are streamed to them AS THEY
	// ARRIVE (a tee) in addition to being captured into Result.ToolStdout /
	// Result.ToolStderr. `netcage run` sets them to os.Stdout/os.Stderr so a
	// jailed tool feels like running it directly; the verify/leak-test probes leave
	// them nil (capture-only) since they only assert on the returned output. Kept
	// separate so the tool's stderr is never merged into the stdout a caller parses.
	//
	// In INTERACTIVE mode (Interactive true) these capture/tee sinks are IGNORED:
	// the tool runs with `podman run -it` and netcage does raw stdio passthrough
	// (podman owns the container PTY), so there is no capture and no tee.
	ToolStdout io.Writer
	ToolStderr io.Writer

	// Interactive runs the wrapped tool with a TTY and stdin attached (`podman run
	// -it`) so a human or agent can shell into the jail. It is opt-in and only for
	// `netcage run -it`; the verify/leak-test probes leave it false so they keep
	// the capture path. Interactive changes ONLY the stdin/stdout/TTY wiring, never
	// the network jail (same sidecar + netns + firewall + forced egress + fail-closed).
	Interactive bool

	// ToolStdin is the reader wired to the interactive tool's stdin (os.Stdin for
	// `netcage run -it`). It is used ONLY in Interactive mode (raw passthrough);
	// non-interactive runs leave it nil and never attach stdin.
	ToolStdin io.Reader

	// DNSUpstream optionally overrides the DNS resolver the in-netns forwarder
	// reaches THROUGH the proxy (DNS-over-TCP, addressed by hostname so the proxy
	// resolves it). Empty uses the forwarder's default public resolver. verify
	// sets this to a controllable resolver so the proxy-side-resolution assertion
	// is deterministic against the fixture.
	DNSUpstream string

	// dnsServer is set by Run once the in-netns forwarder is up (its presence
	// signals the resolv.conf wiring is active).
	dnsServer string
	// dnsHelperPath is the HOST path of the netcage-dns helper binary, set by Run
	// before the sidecar starts so SidecarRunArgs can mount it read-only at
	// sidecarDNSHelperPath (ADR-0006).
	dnsHelperPath string
	// resolvConfPath is a host path to a resolv.conf (nameserver 127.0.0.1)
	// mounted into the tool, set by Run.
	resolvConfPath string
	// hostsPath is a host path to a synthesized localhost-only /etc/hosts mounted
	// read-only into the tool (Leak 1 of the host-identity hardening, ADR-0013),
	// set by Run. Its presence signals the sanitized-hosts wiring is active; it
	// mirrors resolvConfPath (a per-run temp fixture, not a shared/global write).
	hostsPath string
}

// proxyAuth returns the SOCKS5 auth for the forwarder, or nil.
func (c Config) proxyAuth() *proxy.Auth {
	if c.Proxy.Username == "" {
		return nil
	}
	return &proxy.Auth{User: c.Proxy.Username, Password: c.Proxy.Password}
}

func splitHostPort(addr string) (host, port, err string) {
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		return "", "", e.Error()
	}
	return h, p, ""
}

// Runner abstracts command execution so the orchestration is unit-testable
// without a real podman (the integration test uses the real one).
//
// Run keeps the command's stdout SEPARATE from its stderr (it does NOT merge
// them the way CombinedOutput would). That separation is load-bearing:
//
//   - the tool-run step classifies a podman/runtime SETUP failure (podman's own
//     125/126/127 diagnostic, which podman writes to ITS stderr) apart from the
//     wrapped tool's own non-zero exit, so a broken image or missing tool
//     command is not mis-reported as "the tool exited 125"; and
//   - a caller parsing the tool's real output (the leak-test / verify probes read
//     Result.ToolStdout) sees only the tool's stdout, never podman's stderr noise.
//
// The optional Stdout/Stderr live sinks in RunSpec let a caller TEE the streams
// to os.Stdout/os.Stderr as they arrive while still capturing them for the
// return values; when nil, Run captures only. That is the seam the live-output
// streaming builds on, so there is a single Runner shape, not two.
type Runner interface {
	Run(ctx context.Context, spec RunSpec) (stdout, stderr string, err error)
}

// RunSpec is one command to run through a Runner. Stdout/Stderr are OPTIONAL live
// sinks: when set, the runner writes the command's stdout/stderr to them AS THEY
// ARRIVE (a tee) in addition to capturing them; when nil, the runner only
// captures. Keeping stdout and stderr as separate sinks preserves the split the
// tool-exit-vs-podman-failure classification and the capture-for-assertions path
// both depend on.
type RunSpec struct {
	Name   string
	Args   []string
	Stdout io.Writer
	Stderr io.Writer

	// Interactive requests RAW stdio passthrough: the command inherits Stdin and
	// writes its stdout/stderr straight through to the process's own stdout/stderr
	// (podman owns the container PTY under `podman run -it`). In this mode the
	// runner does NOT capture output (the returned stdout/stderr are empty) and the
	// Stdout/Stderr capture-tee sinks above are IGNORED. Used for the interactive
	// jailed shell only; every other Runner call leaves it false.
	Interactive bool

	// Stdin is the reader wired to the command's stdin in Interactive mode
	// (os.Stdin for the jailed shell). Ignored when Interactive is false.
	Stdin io.Reader
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Run executes the spec's command and returns its trimmed stdout and stderr
// SEPARATELY (never merged). If spec.Stdout/spec.Stderr are set, the command's
// streams are also written to them live (a tee) as they arrive; otherwise Run
// only captures. The returned err is the raw exec error (e.g. *exec.ExitError),
// so callers can inspect the exit code and classify it against the captured
// stderr.
func (ExecRunner) Run(ctx context.Context, spec RunSpec) (string, string, error) {
	// Inject the username-free graphroot (podman's global `--root`) at THIS single
	// exec seam, so EVERY podman invocation netcage issues - jail run/start/
	// teardown/verify/exec, the manage pass-through verbs, the interactive raw
	// passthrough, and the probe/verify runners - shares ONE store (ADR-0013).
	// Every inline ExecRunner{} construction site inherits it here with zero
	// per-site wiring, so it is impossible to miss an invocation (a split store
	// would make `netcage ps`/`start` unable to find a `netcage run`'s container).
	// Only podman commands are rewritten; any other command (the local `sh` the
	// streaming tests use) is left untouched.
	args := spec.Args
	if spec.Name == "podman" {
		args = podmanGlobalArgs(args)
	}
	cmd := exec.CommandContext(ctx, spec.Name, args...)

	// Interactive: RAW passthrough. The command inherits stdin and writes its
	// stdout/stderr straight through to the process's own stdout/stderr; podman
	// (`run -it`) owns the container PTY, so keystrokes, the tool's TTY output, and
	// Ctrl-C behave as in a normal `podman run -it`. Nothing is captured (the
	// returned strings are empty) and the capture-tee sinks are ignored.
	if spec.Interactive {
		if spec.Stdin != nil {
			cmd.Stdin = spec.Stdin
		} else {
			cmd.Stdin = os.Stdin
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		return "", "", err
	}

	var outBuf, errBuf bytes.Buffer
	if spec.Stdout != nil {
		cmd.Stdout = io.MultiWriter(&outBuf, spec.Stdout)
	} else {
		cmd.Stdout = &outBuf
	}
	if spec.Stderr != nil {
		cmd.Stderr = io.MultiWriter(&errBuf, spec.Stderr)
	} else {
		cmd.Stderr = &errBuf
	}
	err := cmd.Run()
	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), err
}

// runPodman is a convenience for the common capture-only podman invocation used
// by the orchestration steps (sidecar start, inspect, teardown, reachback). It
// keeps those call sites terse while the tool-run step, which needs the live
// sinks and the separated stderr, builds its own RunSpec.
func runPodman(ctx context.Context, r Runner, args ...string) (stdout, stderr string, err error) {
	return r.Run(ctx, RunSpec{Name: "podman", Args: args})
}

// PullImage pulls an image into netcage's graphroot on the HOST's normal network
// (a plain `podman pull`, NOT inside the jail netns), so it does NOT egress
// through the forced-egress proxy. It goes through the Runner seam, so the
// graphroot `--root` is injected and the pull lands in the SAME store the jail
// runs from. Callers use it to make a probe image PRESENT before a timed jail
// run, so the run never pays a large image pull through a slow proxy. A pull
// error carries podman's own stderr diagnostic.
//
// It is idempotent-ish: pulling an already-present digest is a cheap no-op for
// podman (it revalidates the manifest and returns success), so it is safe to
// call unconditionally before the probe.
func PullImage(ctx context.Context, r Runner, ref string) error {
	if _, serr, err := runPodman(ctx, r, "pull", ref); err != nil {
		return fmt.Errorf("pull image %s: %w%s", ref, err, stderrSuffix(serr))
	}
	return nil
}

// sidecarProxyURL converts the user-facing socks5h:// proxy into the socks5://
// form tun2socks expects. tun2socks rejects the socks5h scheme but resolves
// remotely by construction, so socks5:// IS socks5h semantics for the tunnel
// (see work/notes/findings/dns-through-socks-is-tcp-not-udp.md). For a
// host-loopback proxy the host is the pasta-mapped address.
func (c Config) sidecarProxyURL() string {
	host := c.Proxy.Host
	if c.ProxyOnHostLoopback {
		host = mappedHostLoopback
	}
	u := url.URL{Scheme: "socks5", Host: host + ":" + c.Proxy.Port}
	if c.Proxy.Username != "" {
		if c.Proxy.Password != "" {
			u.User = url.UserPassword(c.Proxy.Username, c.Proxy.Password)
		} else {
			u.User = url.User(c.Proxy.Username)
		}
	}
	return u.String()
}

// sidecarName / toolName are the run-attributable container names.
func (c Config) sidecarName() string { return "netcage-run-" + c.RunID + "-sidecar" }
func (c Config) toolName() string    { return "netcage-run-" + c.RunID + "-tool" }

// netcage.managed / .role / .run-id are the container LABELS netcage stamps on
// both the tool and the sidecar at CREATE time (introduced by the teardown-split
// task, the first to leave containers behind that must be identifiable at rest).
// They are the ROBUST discriminator the pass-through verbs (`ps`/`logs`/... and
// `netcage start`) scope on - a label, not the `netcage-run-<id>-*` name
// convention - so a left-behind pair is unambiguously netcage-managed even after
// the run process is gone.
//
// They are EXPORTED (LabelManaged / LabelRole / LabelRunID / RoleTool /
// RoleSidecar) so the pass-through verbs (internal/manage) filter on the SAME
// constants netcage stamps here, keeping a single source of truth for the
// discriminator (no re-meaning of the label key in a second place).
const (
	LabelManaged = "netcage.managed"
	LabelRole    = "netcage.role"
	LabelRunID   = "netcage.run-id"
	RoleTool     = "tool"
	RoleSidecar  = "sidecar"

	labelManaged = LabelManaged
	labelRole    = LabelRole
	labelRunID   = LabelRunID
	roleTool     = RoleTool
	roleSidecar  = RoleSidecar
)

// managedLabelArgs returns the podman `--label k=v` args stamping a container as
// netcage-managed with its role and run id, so a kept pair is identifiable at
// rest (consumed by the pass-through verbs). role is roleTool or roleSidecar.
func (c Config) managedLabelArgs(role string) []string {
	return []string{
		"--label", labelManaged + "=true",
		"--label", labelRole + "=" + role,
		"--label", labelRunID + "=" + c.RunID,
	}
}

// firewallScript is the in-netns firewall: drop all egress UDP except the local
// tool<->forwarder loopback hop, and narrow host-loopback reachback to exactly
// the proxy port. It is an iptables/ip6tables shell script BAKED into the
// sidecar's create-time EXTRA_COMMANDS env (ADR-0008, refining ADR-0006): the
// pinned tun2socks image runs EXTRA_COMMANDS on EVERY (re)start before it execs
// tun2socks, so the firewall self-heals whenever podman auto-revives the sidecar
// (e.g. as a `--network container:` dependency of a raw `podman start <tool>`).
// The image ships iptables (nf_tables-backed) and the sidecar has CAP_NET_ADMIN.
//
// EXTRA_COMMANDS CANNOT fail-close the sidecar (the entrypoint runs it in a
// child subshell and does not check its exit before `exec tun2socks`, so `set
// -e`/`kill 1` cannot abort it - spiked). The fail-LOUD guarantee therefore
// comes from netcage's OWN post-start VERIFICATION (verifyFirewall), NOT from
// this script aborting. `set -e` is kept so a broken rule at least stops the
// SUBSHELL early (leaving MORE dropped, not more open, given the DROP-first
// ordering below).
//
// DROP-first ordering (ADR-0008, spiked): the only unguarded path is a raw
// `podman start` OUTSIDE netcage (no netcage process to verify). There a
// mid-script rule FAILURE leaves a partial chain, and the ORDER decides whether
// that partial is more open or more closed. So the ENABLING accepts (loopback
// UDP, the proxy-port reachback ACCEPT, each split-tunnel direct ACCEPT) are
// emitted FIRST - they must precede the broad drops that would otherwise catch
// the sidecar's own dial to the proxy / an allowed direct - and then ALL the
// broad DROPs (egress UDP, the reachback drop, the RFC1918/link-local drops)
// follow in one contiguous block. A failure inside the DROP block thus leaves
// MORE dropped, not more open (append-style ordering LEAKED the LAN gateway on a
// partial apply; DROP-first DROPPED it).
func (c Config) firewallScript(proxyPort string) string {
	// The tool's DNS query AND the forwarder's reply are BOTH loopback UDP
	// (127.x<->127.x): the tool sends to 127.0.0.1:53 and the forwarder replies
	// FROM 127.0.0.1:53 to the tool's EPHEMERAL port. So allowing only dport 53
	// drops the reply (its dport is the ephemeral port) and DNS silently fails
	// closed. Allow ALL loopback UDP instead: it never egresses the netns, so it
	// is safe, while every OTHER (egress) UDP is still hard-dropped (ADR-0003).
	// The v6 rules mirror what the previous nft `inet` table covered (its
	// `meta l4proto udp drop` dropped BOTH families).
	var b strings.Builder
	b.WriteString("set -e\n")

	// --- ENABLING ACCEPTs first (must precede the broad drops below) ---
	b.WriteString("iptables -A OUTPUT -p udp -d 127.0.0.0/8 -j ACCEPT\n") // tool<->forwarder loopback DNS (query + reply)
	b.WriteString("ip6tables -A OUTPUT -p udp -d ::1/128 -j ACCEPT\n")    // v6-loopback parity
	if c.ProxyOnHostLoopback {
		// The sidecar's own dial to the pasta-mapped proxy MUST be accepted before
		// the reachback drop and the link-local (169.254.0.0/16) drop that follow.
		b.WriteString(fmt.Sprintf("iptables -A OUTPUT -p tcp -d %s --dport %s -j ACCEPT\n", mappedHostLoopback, proxyPort))
	}
	c.writeSplitTunnelAccepts(&b) // each allowlisted direct, before the RFC1918 drops

	// --- BROAD DROPs after, in one contiguous block (DROP-first residual bound) ---
	b.WriteString("iptables -A OUTPUT -p udp -j DROP\n")  // every other (egress) IPv4 UDP dropped
	b.WriteString("ip6tables -A OUTPUT -p udp -j DROP\n") // every other (egress) IPv6 UDP dropped
	if c.mapExists() {
		// The map DROP closer keeps every NON-named host-loopback port closed. It is
		// present whenever the map exists (a host-loopback proxy OR a host-loopback
		// --allow, ADR-0019), so the named-port accepts above (the proxy-port reachback
		// and each host-model accept) are the ONLY holes in the map; everything else on
		// mappedHostLoopback is dropped. It sits in the broad-DROP block AFTER those
		// accepts (DROP-first residual bound).
		b.WriteString(fmt.Sprintf("iptables -A OUTPUT -d %s -j DROP\n", mappedHostLoopback)) // nothing else on the host loopback
	}
	c.writeSplitTunnelDrops(&b) // RFC1918 / link-local defense-in-depth drops (LAN class only)
	return b.String()
}

// hasHostLoopbackAllow reports whether any --allow entry is a host-loopback
// destination (ADR-0019), so the pasta map + its excluded route + its DROP closer
// are emitted for the host-model case, INDEPENDENT of proxy locality. A host
// model on loopback needs the map even with a REMOTE proxy (the model reachback
// is orthogonal to the proxy reachback). With no host-loopback allow this is
// false, so a remote-proxy jail stays byte-identical to today (no map).
func (c Config) hasHostLoopbackAllow() bool {
	for _, a := range c.AllowDirect {
		if a.HostLoopback {
			return true
		}
	}
	return false
}

// hasLANAllow reports whether any --allow entry is a LAN (RFC1918/link-local)
// destination, so the RFC1918 defense-in-depth DROPs are emitted only when there
// is a LAN direct to defend (a host-loopback-only allowlist keeps the strict-jail
// LAN shape, adding only the map rules). A mixed allowlist emits both.
func (c Config) hasLANAllow() bool {
	for _, a := range c.AllowDirect {
		if !a.HostLoopback {
			return true
		}
	}
	return false
}

// mapExists reports whether the pasta host-loopback map (mappedHostLoopback) is
// present in the jail: either the proxy is on host loopback (the reachback the
// sidecar dials) OR there is a host-loopback --allow (the model reachback). The
// map's `-j DROP` closer, its `--map-host-loopback` pasta option, and its
// mappedHostLoopback/32 excluded route are ALL gated on this predicate, so they
// appear together whenever the map exists and NONE appears when it does not
// (ADR-0005 off-by-default for the model case).
func (c Config) mapExists() bool {
	return c.ProxyOnHostLoopback || c.hasHostLoopbackAllow()
}

// allowDest is the iptables DESTINATION for one --allow entry's accept rule. A
// LAN entry targets its own network (a /32 for a bare IP); a host-loopback entry
// is REWRITTEN to the reserved in-jail pasta map address (the user types the
// HOST's 127.0.0.1, netcage rewrites it to the reachback map at rule-emit time,
// ADR-0019). This is the class-dispatch at the rule-emit seam.
func allowDest(a cli.DirectAllow) string {
	if a.HostLoopback {
		return mappedHostLoopback
	}
	return a.Network.String()
}

// rfc1918DropRanges are the private / link-local ranges the split-tunnel block
// DROPS as defense-in-depth (in the same order the allowlist parser accepts
// them). With the excluded routes in place, a non-allowlisted host on the same
// LAN as an allowed one is merely unrouted-to-the-proxy; these drops make it a
// clean DROP instead, so allowing 192.168.1.150 does not silently expose the
// rest of 192.168.1.0/24 (prd story 7). Emitted ONLY for a non-empty allowlist.
var rfc1918DropRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
}

// writeSplitTunnelAccepts appends the split-tunnel ACCEPT rules (the NARROWING
// half of the spike), and ONLY for a NON-EMPTY allowlist. Each allowlist entry
// gets an ACCEPT for its net at its EXACT TCP port. It is emitted in the
// ENABLING-accepts block, BEFORE the broad drops, so an allowed destination is
// accepted and not shadowed by the RFC1918-range drop for its own LAN. TCP-only
// throughout: UDP was already hard-dropped (ADR-0003), so even an allowlisted
// host has no UDP path.
//
// Every entry carries an exact port (the all-ports / port-omitted form was
// DROPPED as a deanonymization risk, ADR-0020: the CLI now rejects a port-omitted
// value, so no exemption can open more than one exact TCP port). Because only the
// named port is accepted, a direct clear-DNS query on :53 to an allowed host is
// never accepted (it falls to the RFC1918/link-local range DROP below), so the
// split-tunnel hole is structurally incapable of carrying clear DNS to a LAN
// resolver without a separate 53-exclusion (ADR-0018 is now enforced by the
// exact-port shape alone).
//
// For an EMPTY allowlist this writes NOTHING (paired with writeSplitTunnelDrops),
// keeping firewallScript's default-jail shape unchanged (today's default jail
// has NO RFC1918 drops at all; its fail-closed comes from the TUN-only route).
func (c Config) writeSplitTunnelAccepts(b *strings.Builder) {
	for _, a := range c.AllowDirect {
		// allowDest dispatches on the entry's class: a LAN entry accepts its own /32;
		// a host-loopback entry accepts the rewritten pasta map address (ADR-0019).
		// Emitted before the map DROP closer, so a host-model accept is a hole in the
		// map exactly like the proxy-port reachback accept.
		b.WriteString(fmt.Sprintf("iptables -A OUTPUT -p tcp -d %s --dport %d -j ACCEPT\n", allowDest(a), a.Port))
	}
}

// writeSplitTunnelDrops appends the RFC1918 / link-local defense-in-depth DROPs
// (prd story 7), and ONLY for a NON-EMPTY allowlist. They are emitted in the
// broad-DROP block, AFTER the split-tunnel accepts, so the allowed destination
// is accepted and every other private-range host is a clean DROP. These ranges
// are IPv4-only, matching the previous nft `ip daddr` rules.
func (c Config) writeSplitTunnelDrops(b *strings.Builder) {
	// The RFC1918/link-local defense-in-depth drops defend a LAN direct (they make
	// a non-allowlisted neighbour on the allowed host's range a clean DROP). A
	// host-loopback-only allowlist has no LAN direct to defend, so it keeps the
	// strict-jail LAN shape (adding only the map accept + map DROP closer), which
	// preserves the byte-identical invariant for a remote-proxy-plus-host-model jail
	// (ADR-0005). A mixed allowlist emits these for its LAN half.
	if !c.hasLANAllow() {
		return
	}
	for _, r := range rfc1918DropRanges {
		b.WriteString(fmt.Sprintf("iptables -A OUTPUT -d %s -j DROP\n", r))
	}
}

// firewallVerifyRules returns the exact `iptables -S OUTPUT` / `ip6tables -S
// OUTPUT`-shaped rule lines netcage asserts are PRESENT after the sidecar is up
// (the fail-loud VERIFICATION layer, ADR-0008). Because EXTRA_COMMANDS cannot
// abort the sidecar on a half-applied firewall, this post-start probe is what
// gives the fail-loud guarantee the old `podman exec ... 'set -e; ...'` got from
// its Go-side exit code: if any expected rule is missing, Run aborts loudly.
//
// The lines mirror firewallScript's `-A OUTPUT ...` rules but in the CANONICAL
// form `iptables -S` renders them (which differs from the `-A` form we submit):
//
//   - the destination match `-d <addr>` is emitted BEFORE the protocol match
//     `-p <proto>` (iptables reorders match args on save);
//   - a bare host address (mappedHostLoopback) is normalised to /32;
//   - a `--dport` match is rendered with its explicit module: `-p tcp -m tcp
//     --dport N`.
//
// The rule SET (presence) is asserted, not the emit order (the DROP-first
// ordering is pinned separately by the unit test).
func (c Config) firewallVerifyRules(proxyPort string) (v4, v6 []string) {
	v4 = []string{
		"-A OUTPUT -d 127.0.0.0/8 -p udp -j ACCEPT",
		"-A OUTPUT -p udp -j DROP",
	}
	v6 = []string{
		"-A OUTPUT -d ::1/128 -p udp -j ACCEPT",
		"-A OUTPUT -p udp -j DROP",
	}
	if c.ProxyOnHostLoopback {
		// The proxy-port reachback accept on the shared map (the closer is added once
		// below, gated on mapExists, so it is not duplicated when a host-loopback allow
		// also needs it).
		v4 = append(v4,
			fmt.Sprintf("-A OUTPUT -d %s/32 -p tcp -m tcp --dport %s -j ACCEPT", mappedHostLoopback, proxyPort),
		)
	}
	for _, a := range c.AllowDirect {
		// Every entry is an exact port (the all-ports form was removed, ADR-0020).
		// allowDest rewrites a host-loopback entry to the map address (ADR-0019); a LAN
		// entry keeps its own /32. allowDest returns a bare host address for the map,
		// normalised to /32 in the canonical `iptables -S` form.
		v4 = append(v4, fmt.Sprintf("-A OUTPUT -d %s -p tcp -m tcp --dport %d -j ACCEPT", verifyDest(a), a.Port))
	}
	if c.mapExists() {
		// The map DROP closer, asserted whenever the map exists (proxy OR host-model),
		// so the fail-loud layer catches a half-applied host-loopback hole.
		v4 = append(v4, fmt.Sprintf("-A OUTPUT -d %s/32 -j DROP", mappedHostLoopback))
	}
	if c.hasLANAllow() {
		for _, r := range rfc1918DropRanges {
			v4 = append(v4, fmt.Sprintf("-A OUTPUT -d %s -j DROP", r))
		}
	}
	return v4, v6
}

// verifyDest is allowDest in the canonical `iptables -S` form: a host-loopback
// entry's map address is rendered as a /32 (iptables normalises a bare host
// address to /32 on save), while a LAN entry's network already carries its mask.
func verifyDest(a cli.DirectAllow) string {
	if a.HostLoopback {
		return mappedHostLoopback + "/32"
	}
	return a.Network.String()
}

// checkRulesPresent asserts every rule in want appears (line-exact, ignoring
// surrounding whitespace) in the captured `iptables -S` output. It returns a
// non-nil error naming the FIRST missing rule, so a half-applied firewall makes
// verifyFirewall abort loudly. It is a pure function so the fail-loud contract is
// unit-testable without podman.
func checkRulesPresent(want []string, output string) error {
	present := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		present[strings.TrimSpace(line)] = true
	}
	for _, w := range want {
		if !present[w] {
			return fmt.Errorf("expected firewall rule not present: %q", w)
		}
	}
	return nil
}

// proxyReachbackAddr is the address tun2socks's dialer must reach the proxy at:
// the pasta map for a host-loopback proxy, else the proxy's real host. It is the
// address that MUST be excluded from the TUN (TUN_EXCLUDED_ROUTES) so the dialer
// egresses over the real NIC instead of looping back through tun0.
func (c Config) proxyReachbackAddr() string {
	if c.ProxyOnHostLoopback {
		return mappedHostLoopback
	}
	return c.Proxy.Host
}

// SidecarRunArgs returns the podman args to start the tun2socks sidecar. Exposed
// for testing the wiring without executing podman.
//
// CLONE_MAIN=0 and TUN_EXCLUDED_ROUTES=<proxy-reachback>/32 are load-bearing,
// not cosmetic: the forced-egress spike proved that with the image default
// CLONE_MAIN=1 the TUN routing table clones the pasta-copied real-NIC routes and
// storms, and that without excluding the proxy address from the TUN, tun2socks's
// own dialer loops back through tun0 and pasta resets it. See
// work/notes/findings/spike-jail-forced-egress-clone-main-and-excluded-route.md.
func (c Config) SidecarRunArgs() []string {
	// Compose the pasta options. `-I,<name>` renames the in-netns interface to a
	// fixed neutral name so it does not inherit the host NIC's `enx<MAC>` name
	// (Leak 5, ADR-0013); it is ALWAYS present (the interface exists in both proxy
	// modes). For a host-loopback proxy, `--map-host-loopback,<addr>` follows so the
	// sidecar's dialer can reach the host-loopback proxy through the pasta map. The
	// route out is still the TUN, so neither opt affects forced egress.
	pastaOpts := []string{"-I", pastaIfName}
	if c.mapExists() {
		// The pasta host-loopback map is present whenever the map exists: a
		// host-loopback proxy (the sidecar's reachback) OR a host-loopback --allow (the
		// model reachback), INDEPENDENT of proxy locality (ADR-0019). A remote-proxy
		// jail with a host model on loopback still needs the map, and a remote-proxy
		// jail with no host-loopback allow does NOT get it (off-by-default).
		pastaOpts = append(pastaOpts, "--map-host-loopback", mappedHostLoopback)
	}
	network := "pasta:" + strings.Join(pastaOpts, ",")
	args := []string{
		"run", "-d", "--name", c.sidecarName(),
	}
	// Stamp the netcage.managed (+ role + run id) label so a left-behind sidecar is
	// identifiable at rest (ADR-0009), consumed by the pass-through verbs.
	args = append(args, c.managedLabelArgs(roleSidecar)...)
	args = append(args,
		"--network", network,
		"--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
		"-e", "CLONE_MAIN=0",
		"-e", "TUN_EXCLUDED_ROUTES="+c.excludedRoutes(),
		"-e", "PROXY="+c.sidecarProxyURL(),
		// The firewall is BAKED into EXTRA_COMMANDS at sidecar CREATE time (ADR-0008,
		// refining ADR-0006), not applied via a post-start `podman exec`. The pinned
		// tun2socks entrypoint runs EXTRA_COMMANDS on EVERY (re)start before it execs
		// tun2socks, so the firewall self-heals whenever podman auto-revives the
		// sidecar (e.g. as a `--network container:` dependency of a raw `podman
		// start`), closing the LAN/UDP restart leak. The fail-LOUD guarantee is
		// netcage's post-start verifyFirewall (EXTRA_COMMANDS cannot abort the
		// sidecar). The DNS forwarder is NOT baked in (it stays a separate `podman
		// exec -d` process); a raw bypass leaving DNS dead IS fail-closed.
		"-e", "EXTRA_COMMANDS="+c.firewallScript(c.Proxy.Port),
	)
	// Mount the netcage-dns helper read-only into the sidecar so the DNS
	// forwarder runs INSIDE it via `podman exec -d` (ADR-0006), instead of on the
	// host via nsenter. Run resolves the host path before starting the sidecar.
	if c.dnsHelperPath != "" {
		args = append(args, "-v", c.dnsHelperPath+":"+sidecarDNSHelperPath+":ro")
	}
	return append(args, redirector.RunPathImageReference())
}

// excludedRoutes composes the sidecar's TUN_EXCLUDED_ROUTES value: the proxy
// reachback /32 ALWAYS (the load-bearing forced-egress route the dialer needs)
// FOLLOWED BY each split-tunnel allowlist net. The tun2socks entrypoint reads
// TUN_EXCLUDED_ROUTES as a COMMA-separated list, turning each into `ip rule add
// to <route> table main`, so each excluded destination egresses the real NIC via
// pasta instead of the TUN (the ENABLER half of the split-tunnel spike).
//
// An EMPTY allowlist yields EXACTLY the reachback /32 (no comma, no extra
// routes), byte-identical to today's strict jail. The allowlist nets are
// appended in allowlist order, each as its normalised CIDR (a bare IP is already
// a /32 host route from the CLI parse), so a per-host exclusion exposes only that
// /32 (the spike proved per-host `/32` exclusion is per-host, not per-/24).
//
// A host-loopback --allow entry (ADR-0019) is rewritten to the pasta map
// address (mappedHostLoopback/32) via allowDest, so the model's dial to the map
// egresses the real NIC via pasta, not the TUN (the enabler half). When the proxy
// is ALSO host loopback the map route is SHARED with the proxy reachback /32, so
// it is deduplicated (one map address, one excluded route), not appended twice.
func (c Config) excludedRoutes() string {
	routes := []string{c.proxyReachbackAddr() + "/32"}
	seen := map[string]bool{routes[0]: true}
	for _, a := range c.AllowDirect {
		route := allowDest(a)
		if a.HostLoopback {
			route += "/32" // the map address is a bare host; exclude its /32 host route
		}
		if seen[route] {
			continue // the shared map route is already excluded (host-loopback proxy)
		}
		seen[route] = true
		routes = append(routes, route)
	}
	return strings.Join(routes, ",")
}

// toolRunSpec builds the RunSpec for the tool-run step, choosing the run mode
// from Config.Interactive. This is the interactive-vs-capture SEAM in one place:
//
//   - Interactive: RAW passthrough. Stdin is wired (os.Stdin via ToolStdin) and
//     the capture-tee live sinks are DELIBERATELY not attached, because podman's
//     `-it` owns the container PTY and netcage passes stdio straight through.
//     Nothing is captured (Result.ToolStdout is empty for an interactive run).
//   - Non-interactive: the existing capture/tee path. The live sinks stream the
//     tool's output to os.Stdout/os.Stderr while ExecRunner still captures it into
//     Result.ToolStdout/ToolStderr, which the verify/leak-test probes assert on.
//
// Keeping this in one method makes the run-mode seam unit-testable without podman
// (a test asserts the built spec) and guarantees the probes are never routed
// through the raw path.
func (c Config) toolRunSpec() RunSpec {
	spec := RunSpec{Name: "podman", Args: c.ToolRunArgs()}
	if c.Interactive {
		spec.Interactive = true
		spec.Stdin = c.ToolStdin
		return spec
	}
	spec.Stdout = c.ToolStdout
	spec.Stderr = c.ToolStderr
	return spec
}

// ToolRunArgs returns the podman args to start the wrapped tool sharing the
// sidecar's netns. Exposed for testing the wiring.
func (c Config) ToolRunArgs() []string {
	args := []string{
		"run", "--name", c.toolName(),
	}
	// The tool container's --rm follows netcage's Ephemeral flag (ADR-0009), NOT a
	// hard-coded default: an EPHEMERAL run (the netcage `--rm` user flag + every
	// internal one-shot) passes --rm so podman removes the tool on exit; a KEPT run
	// (a plain `netcage run`) omits it so podman leaves the stopped tool behind
	// (inspectable/restartable like `podman run`). netcage OWNS what --rm means: it
	// interprets its own flag into this lifecycle, it does NOT smuggle a raw podman
	// --rm from the user.
	if c.Ephemeral {
		args = append(args, "--rm")
	}
	// Stamp the netcage.managed (+ role + run id) label so a left-behind tool is
	// identifiable at rest (ADR-0009), consumed by the pass-through verbs.
	args = append(args, c.managedLabelArgs(roleTool)...)
	args = append(args,
		"--network", "container:"+c.sidecarName(),
	)
	// Interactive mode attaches a TTY + stdin (`podman run -it`) so a human/agent
	// can shell into the jail. It is opt-in (only `netcage run -it`); every other
	// path (verify probes, declarative runs) omits it and keeps the capture path.
	if c.Interactive {
		args = append(args, "-it")
	}
	// NOTE: --dns cannot be combined with --network container: (podman refuses;
	// the tool inherits the shared netns's resolv.conf). The tool's resolver is
	// pointed at the in-netns forwarder by mounting a resolv.conf that says
	// `nameserver 127.0.0.1`, set up in Run.
	if c.resolvConfPath != "" {
		// Mount a resolv.conf pointing at the in-netns forwarder (127.0.0.1:53), so
		// all name resolution goes proxy-side. This replaces --dns (which podman
		// refuses under --network container:).
		args = append(args, "-v", c.resolvConfPath+":/etc/resolv.conf:ro")
	}
	// Sanitize /etc/hosts + fix the hostname (Leak 1, ADR-0013). Mount a synthesized
	// localhost-only /etc/hosts read-only (mirroring the resolv.conf mount above) so
	// the tool no longer inherits podman's default /etc/hosts, which under rootless
	// podman carries the host's `127.0.1.1 <hostname>` line and leaks the host
	// machine name. The source file is a per-run temp fixture Run synthesizes (like
	// the resolv.conf), so the mount appears only when hostsPath is set. Unlike
	// --dns, both the /etc/hosts mount and --hostname ARE accepted under --network
	// container: (live-verified). --hostname is netcage's neutral DEFAULT; it is
	// emitted BEFORE the vetted pass-through flags so an explicit user --hostname
	// (ADR-0010) wins under podman's last-flag-wins.
	args = append(args, "--hostname", fixedHostname)
	if c.hostsPath != "" {
		args = append(args, "-v", c.hostsPath+":/etc/hosts:ro")
	}
	for _, m := range c.Mounts {
		args = append(args, "-v", m)
	}
	// The workdir is where the tool runs inside the container. For the repo-mount
	// ergonomic the CLI defaults this to /work (the repo mount target) so a repo
	// dropped in is worked in; an explicit -w overrides it. Empty leaves the
	// image's own default workdir.
	if c.Workdir != "" {
		args = append(args, "-w", c.Workdir)
	}
	// Env / user / entrypoint pass-throughs (the drift-bug fix): these were parsed
	// by the CLI but never wired here, so they were silently dropped. None is
	// network/isolation-relevant, so they pass straight through. Emitted BEFORE the
	// image (they are run flags), so the tool gets the env, runs as the given user,
	// and uses the overridden entrypoint. Empty values add nothing (image defaults).
	for _, e := range c.Env {
		args = append(args, "-e", e)
	}
	if c.User != "" {
		args = append(args, "-u", c.User)
	}
	if c.Entrypoint != "" {
		args = append(args, "--entrypoint", c.Entrypoint)
	}
	// Widened, vetted allow-list flags (ADR-0010), passed through verbatim in argv
	// order, BEFORE the image. The CLI parser only ever appends flags that pass the
	// vetting checklist, so this cannot introduce a network/isolation-relevant flag.
	args = append(args, c.PassThroughFlags...)
	args = append(args, c.Image)
	args = append(args, c.ToolArgv...)
	return args
}
