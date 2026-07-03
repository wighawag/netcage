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
// through the proxy. A firewall (iptables, applied INSIDE the sidecar via
// `podman exec`, ADR-0006) drops all UDP egress in the shared netns and narrows
// host-loopback reachback to exactly the proxy port. A DNS forwarder (the
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

	// AllowDirect is the validated split-tunnel LAN allowlist: private-only
	// destinations (network + optional TCP port) the jailed tool may reach
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
	cmd := exec.CommandContext(ctx, spec.Name, spec.Args...)

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
	if c.ProxyOnHostLoopback {
		b.WriteString(fmt.Sprintf("iptables -A OUTPUT -d %s -j DROP\n", mappedHostLoopback)) // nothing else on the host loopback
	}
	c.writeSplitTunnelDrops(&b) // RFC1918 / link-local defense-in-depth drops
	return b.String()
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
// gets an ACCEPT for its net (per-port, or all TCP ports for a port-less entry).
// It is emitted in the ENABLING-accepts block, BEFORE the broad drops, so an
// allowed destination is accepted and not shadowed by the RFC1918-range drop for
// its own LAN. TCP-only throughout: UDP was already hard-dropped (ADR-0003), so
// even an allowlisted host has no UDP path.
//
// For an EMPTY allowlist this writes NOTHING (paired with writeSplitTunnelDrops),
// keeping firewallScript's default-jail shape unchanged (today's default jail
// has NO RFC1918 drops at all; its fail-closed comes from the TUN-only route).
func (c Config) writeSplitTunnelAccepts(b *strings.Builder) {
	for _, a := range c.AllowDirect {
		daddr := a.Network.String()
		if a.Port == 0 {
			// Port omitted => all TCP ports to that net (TCP-only; UDP stays dropped).
			b.WriteString(fmt.Sprintf("iptables -A OUTPUT -p tcp -d %s -j ACCEPT\n", daddr))
		} else {
			b.WriteString(fmt.Sprintf("iptables -A OUTPUT -p tcp -d %s --dport %d -j ACCEPT\n", daddr, a.Port))
		}
	}
}

// writeSplitTunnelDrops appends the RFC1918 / link-local defense-in-depth DROPs
// (prd story 7), and ONLY for a NON-EMPTY allowlist. They are emitted in the
// broad-DROP block, AFTER the split-tunnel accepts, so the allowed destination
// is accepted and every other private-range host is a clean DROP. These ranges
// are IPv4-only, matching the previous nft `ip daddr` rules.
func (c Config) writeSplitTunnelDrops(b *strings.Builder) {
	if len(c.AllowDirect) == 0 {
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
		v4 = append(v4,
			fmt.Sprintf("-A OUTPUT -d %s/32 -p tcp -m tcp --dport %s -j ACCEPT", mappedHostLoopback, proxyPort),
			fmt.Sprintf("-A OUTPUT -d %s/32 -j DROP", mappedHostLoopback),
		)
	}
	for _, a := range c.AllowDirect {
		if a.Port == 0 {
			v4 = append(v4, fmt.Sprintf("-A OUTPUT -d %s -p tcp -j ACCEPT", a.Network.String()))
		} else {
			v4 = append(v4, fmt.Sprintf("-A OUTPUT -d %s -p tcp -m tcp --dport %d -j ACCEPT", a.Network.String(), a.Port))
		}
	}
	if len(c.AllowDirect) > 0 {
		for _, r := range rfc1918DropRanges {
			v4 = append(v4, fmt.Sprintf("-A OUTPUT -d %s -j DROP", r))
		}
	}
	return v4, v6
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
	network := "pasta"
	if c.ProxyOnHostLoopback {
		network = "pasta:--map-host-loopback," + mappedHostLoopback
	}
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
func (c Config) excludedRoutes() string {
	routes := []string{c.proxyReachbackAddr() + "/32"}
	for _, a := range c.AllowDirect {
		routes = append(routes, a.Network.String())
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
	args = append(args, c.Image)
	args = append(args, c.ToolArgv...)
	return args
}
