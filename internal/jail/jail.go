// Package jail stands up tooljail's forced-egress jail: the wrapped tool runs
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
// through the proxy. An nft ruleset in the shared netns drops all UDP egress and
// narrows host-loopback reachback to exactly the proxy port. A DNS forwarder in
// the netns resolves names via the proxy over TCP. Everything is labeled
// run-attributably and torn down on exit.
package jail

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"strings"

	"golang.org/x/net/proxy"

	"github.com/wighawag/tooljail/internal/cli"
	"github.com/wighawag/tooljail/internal/redirector"
)

// mappedHostLoopback is the dedicated link-local address pasta maps to host
// loopback (spike-pasta-loopback-reachback). Chosen so it is not a real LAN host
// and the nft narrowing rule's daddr is stable.
const mappedHostLoopback = "169.254.1.1"

// Config is a resolved jail run.
type Config struct {
	Proxy    cli.ProxyConfig
	Image    string
	ToolArgv []string
	Mounts   []string // podman -v values, passed through
	RunID    string   // run-attributable id; containers named tooljail-run-<RunID>-*

	// ProxyOnHostLoopback indicates the proxy listens on the HOST's 127.0.0.1
	// (local Tor / ssh -D), so the sidecar reaches it via the pasta map. When
	// false the proxy is a normal routable host the sidecar dials directly.
	ProxyOnHostLoopback bool

	// ToolStdout and ToolStderr are OPTIONAL live sinks for the wrapped tool's
	// output. When set, the tool's stdout/stderr are streamed to them AS THEY
	// ARRIVE (a tee) in addition to being captured into Result.ToolStdout /
	// Result.ToolStderr. `tooljail run` sets them to os.Stdout/os.Stderr so a
	// jailed tool feels like running it directly; the verify/leak-test probes leave
	// them nil (capture-only) since they only assert on the returned output. Kept
	// separate so the tool's stderr is never merged into the stdout a caller parses.
	ToolStdout io.Writer
	ToolStderr io.Writer

	// DNSUpstream optionally overrides the DNS resolver the in-netns forwarder
	// reaches THROUGH the proxy (DNS-over-TCP, addressed by hostname so the proxy
	// resolves it). Empty uses the forwarder's default public resolver. verify
	// sets this to a controllable resolver so the proxy-side-resolution assertion
	// is deterministic against the fixture.
	DNSUpstream string

	// dnsServer is set by Run once the in-netns forwarder is up (its presence
	// signals the resolv.conf wiring is active).
	dnsServer string
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
func (c Config) sidecarName() string { return "tooljail-run-" + c.RunID + "-sidecar" }
func (c Config) toolName() string    { return "tooljail-run-" + c.RunID + "-tool" }

// nftRuleset is the in-netns ruleset: drop all egress UDP except the local
// tool<->forwarder loopback hop, and narrow host-loopback reachback to exactly
// the proxy port. Applied via nsenter into the shared netns.
func (c Config) nftRuleset(proxyPort string) string {
	// The tool's DNS query AND the forwarder's reply are BOTH loopback UDP
	// (127.x<->127.x): the tool sends to 127.0.0.1:53 and the forwarder replies
	// FROM 127.0.0.1:53 to the tool's EPHEMERAL port. So allowing only `dport 53`
	// drops the reply (its dport is the ephemeral port) and DNS silently fails
	// closed. Allow ALL loopback UDP instead: it never egresses the netns, so it
	// is safe, while every OTHER (egress) UDP is still hard-dropped (ADR-0003).
	var b strings.Builder
	b.WriteString("table inet jail {\n  chain out {\n")
	b.WriteString("    type filter hook output priority 0; policy accept;\n")
	b.WriteString("    meta l4proto udp ip daddr 127.0.0.0/8 accept\n") // tool<->forwarder loopback DNS (query + reply)
	b.WriteString("    meta l4proto udp drop\n")                        // every other (egress) UDP dropped
	if c.ProxyOnHostLoopback {
		b.WriteString(fmt.Sprintf("    ip daddr %s tcp dport %s accept\n", mappedHostLoopback, proxyPort))
		b.WriteString(fmt.Sprintf("    ip daddr %s drop\n", mappedHostLoopback))
	}
	b.WriteString("  }\n}\n")
	return b.String()
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
	return []string{
		"run", "-d", "--name", c.sidecarName(),
		"--network", network,
		"--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
		"-e", "CLONE_MAIN=0",
		"-e", "TUN_EXCLUDED_ROUTES=" + c.proxyReachbackAddr() + "/32",
		"-e", "PROXY=" + c.sidecarProxyURL(),
		redirector.RunPathImageReference(),
	}
}

// ToolRunArgs returns the podman args to start the wrapped tool sharing the
// sidecar's netns. Exposed for testing the wiring.
func (c Config) ToolRunArgs() []string {
	args := []string{
		"run", "--rm", "--name", c.toolName(),
		"--network", "container:" + c.sidecarName(),
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
	args = append(args, c.Image)
	args = append(args, c.ToolArgv...)
	return args
}
