// Command netcage runs any containerized tool with all of its TCP and DNS
// egress forced through a SOCKS5h proxy, fail-closed, so the wrapped tool
// cannot leak the real IP or DNS.
//
// This entry point wires the CLI surface (parse + socks5h contract + fail-loud
// startup preflight) to the jail engine: `run` stands up the forced-egress jail
// and runs the wrapped tool through it; `verify` runs the leak-test. SIGINT
// cancels the run so the jail tears down with no residue.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/detectproxy"
	"github.com/wighawag/netcage/internal/forward"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/manage"
	"github.com/wighawag/netcage/internal/setupdefault"
	"github.com/wighawag/netcage/internal/verify"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// `netcage --version` / `netcage version` prints the version and exits before
	// any CLI parse or proxy preflight (it needs neither a subcommand nor a proxy).
	if isVersionArg(args) {
		fmt.Println("netcage " + resolveVersion())
		return 0
	}

	cmd, err := cli.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netcage: %v\n", err)
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}

	// Fail-loud, fail-closed startup: refuse to proceed if the proxy is down.
	if err := cmd.Preflight(); err != nil {
		fmt.Fprintf(os.Stderr, "netcage: %v\n", err)
		return 1
	}

	// SIGINT (Ctrl-C) / SIGTERM cancels the context that flows into the jail, so
	// the jail's deferred Teardown runs and leaves NO residue (the teardown
	// invariant's signal path). Teardown itself uses a fresh context, so it
	// completes even though this one is cancelled.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch {
	case cmd.Name == "verify":
		return runVerify(ctx, cmd)
	case cmd.Name == "detect-proxy":
		return runDetectProxy(ctx, cmd)
	case cmd.Name == "setup-default":
		return runSetupDefault(ctx, cmd)
	case cmd.Name == "start":
		return runStart(ctx, cmd)
	case cmd.Name == "forward":
		return runForward(ctx, cmd)
	case cmd.IsManagement():
		return runManage(ctx, cmd)
	default:
		return runRun(ctx, cmd)
	}
}

// runManage routes a pass-through management verb (ps/logs/inspect/exec/stop/rm/
// images) to the manage package, which wraps podman scoped to netcage-managed
// containers (via the netcage.managed label). These verbs are inspection /
// lifecycle only: they do NOT stand up or tear down a jail, do NOT require a
// proxy, and never alter a running jail's forced-egress state (`exec` enters the
// container's EXISTING jailed netns). A refusal (a non-netcage container) or a
// podman failure exits non-zero with a clear message.
func runManage(ctx context.Context, cmd *cli.Command) int {
	io := manage.IO{Stdout: os.Stdout, Stderr: os.Stderr}
	// `exec` is the one management verb that can be INTERACTIVE (`netcage exec -it
	// <c> <cmd>`): wire os.Stdin so the raw-stdio passthrough path has a real stdin,
	// and, when it is an interactive `-it` invocation, put netcage's controlling
	// terminal into raw mode (like `run -it`/`start -ai` do) so keystrokes and
	// Ctrl-C flow to the container's PTY as bytes rather than being cooked by the
	// host terminal. Restored on exit. The manage package parses -i/-t itself; we
	// re-parse ONLY to decide raw mode here (the parse is pure/side-effect-free).
	if cmd.Name == "exec" {
		io.Stdin = os.Stdin
		if flags, _, _, err := manage.ParseExecArgs(cmd.ManageArgv); err == nil && flags.Interactive && flags.TTY {
			if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
				if oldState, err := term.MakeRaw(fd); err == nil {
					defer term.Restore(fd, oldState)
				}
			}
		}
	}
	if err := manage.Run(ctx, jail.ExecRunner{}, cmd.Name, cmd.ManageArgv, io); err != nil {
		fmt.Fprintf(os.Stderr, "netcage: %s: %v\n", cmd.Name, err)
		return 1
	}
	return 0
}

// runRun stands up the jail and runs the wrapped tool, propagating the tool's
// exit code as netcage's own. A jail SETUP failure (a bad/unpullable image, a
// tool command not found, or sidecar/firewall/reachback) exits non-zero with a clear
// message; a tool that ran but exited non-zero passes that exit code through (the
// wrapped tool's result is the run's result). SIGINT cancels ctx, so the jail's
// deferred Teardown leaves no residue.
//
// The wrapped tool's stdout/stderr are STREAMED LIVE to netcage's own
// stdout/stderr (via the Config live sinks) so a jailed tool feels like running
// it directly, with no wait-until-exit and no unbounded in-memory buffering of
// the streamed output. The captured Result.ToolStdout is what the verify probes
// assert on; here it is already on screen, so it is NOT re-printed.
func runRun(ctx context.Context, cmd *cli.Command) int {
	interactive := cmd.Interactive || cmd.TTY
	cfg := jail.Config{
		Proxy:               cmd.Proxy,
		ProxyOnHostLoopback: cmd.ProxyOnHostLoopback(),
		Image:               cmd.Image,
		ToolArgv:            cmd.ToolArgv,
		Mounts:              cmd.Mounts,
		Workdir:             cmd.Workdir,
		// Env/User/Entrypoint were parsed by the CLI but historically dropped here
		// (silently); wire them through so `-e`/`-u`/`--entrypoint` actually reach the
		// tool container. PassThroughFlags carries the widened, vetted allow-list flags
		// (ADR-0010) verbatim.
		Env:              cmd.Env,
		User:             cmd.User,
		Entrypoint:       cmd.Entrypoint,
		PassThroughFlags: cmd.PassThroughFlags,
		Interactive:      interactive,
		AllowDirect:      cmd.AllowDirect,
		// The netcage-owned --rm maps to an EPHEMERAL run (remove both tool +
		// sidecar on exit). Without it the run is KEPT: the stopped tool + sidecar
		// are left behind (podman-run fidelity), fail-closed via the baked firewall.
		Ephemeral: cmd.Rm,
	}
	if interactive {
		// Interactive (`netcage run -it`): RAW stdio passthrough into the jailed
		// `podman run -it`. Wire os.Stdin and leave the capture sinks nil (the raw
		// path ignores them). Put netcage's controlling terminal into raw mode so
		// keystrokes and Ctrl-C are forwarded to the container's PTY as bytes (podman
		// owns that PTY) rather than being cooked by the host terminal or turned into
		// a SIGINT that would tear the jail down mid-keystroke. Restored on exit so
		// the user's terminal is never left in raw mode. The network jail is
		// unchanged; only stdio wiring differs.
		cfg.ToolStdin = os.Stdin
		if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
			if oldState, err := term.MakeRaw(fd); err == nil {
				defer term.Restore(fd, oldState)
			}
		}
	} else {
		cfg.ToolStdout = os.Stdout
		cfg.ToolStderr = os.Stderr
	}
	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netcage: run: %v\n", err)
		return 1
	}
	return res.ToolExit
}

// runStart resumes a kept, netcage-managed jailed container: it REVIVES the
// sidecar (the baked firewall re-applies), re-execs the DNS forwarder, and
// re-enters the kept tool with its state intact, refusing loudly if the requested
// jail config (--proxy/--allow-direct) differs from the one the container was
// created with (jail.ErrJailConfigChanged) or if the named container is not
// netcage-managed. It is the jail-aware exception to the pass-through verbs.
//
// Like `run`, it honours the interactive/TTY wiring (a resumed `-it` shell gets
// raw stdio passthrough with the terminal in raw mode) and the netcage-owned --rm
// (ephemeral: remove both on exit). Without --rm the pair is left stopped again,
// fail-closed via the baked firewall. The tool's exit code propagates as
// netcage's own; a jail/setup failure exits non-zero with a clear message.
func runStart(ctx context.Context, cmd *cli.Command) int {
	interactive := cmd.Interactive || cmd.TTY
	cfg := jail.Config{
		Proxy:               cmd.Proxy,
		ProxyOnHostLoopback: cmd.ProxyOnHostLoopback(),
		AllowDirect:         cmd.AllowDirect,
		Interactive:         interactive,
		// --rm makes the resume EPHEMERAL (remove both on exit); without it the pair is
		// left stopped again, fail-closed via the baked firewall.
		Ephemeral: cmd.Rm,
	}
	if interactive {
		// Same raw stdio passthrough as `netcage run -it`: wire os.Stdin and put the
		// controlling terminal into raw mode so keystrokes/Ctrl-C reach the container's
		// PTY as bytes. Restored on exit. The network jail is unchanged.
		cfg.ToolStdin = os.Stdin
		if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
			if oldState, err := term.MakeRaw(fd); err == nil {
				defer term.Restore(fd, oldState)
			}
		}
	} else {
		cfg.ToolStdout = os.Stdout
		cfg.ToolStderr = os.Stderr
	}
	res, err := jail.Start(ctx, jail.ExecRunner{}, cfg, cmd.StartName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netcage: start: %v\n", err)
		return 1
	}
	return res.ToolExit
}

// runForward stands up the `netcage forward <container> <port>` host-access verb
// (ADR-0014): a label-scoped, loopback-by-default, single-port, lifetime-bounded
// host->jail forward, with a warned `--bind 0.0.0.0` LAN opt-in, that NEVER
// touches the egress firewall. It resolves the named container to a
// netcage-managed tool (refusing a non-netcage or stopped jail loudly), warns
// before a 0.0.0.0 exposure, prints the start line, and holds the forward for the
// verb's lifetime. ctx is SIGINT/SIGTERM-cancellable (wired in run), so Ctrl-C
// tears the relay down cleanly, leaving no listener and no host state behind
// (a clean Ctrl-C is exit 0). The forward is a plain host process: a reboot ends
// it and nothing revives it. To re-establish after a reboot: `netcage start
// <container>`, relaunch the server if it was a tool-run process, then `netcage
// forward` again (nothing about host-access persists).
func runForward(ctx context.Context, cmd *cli.Command) int {
	err := forward.Run(ctx, jail.ExecRunner{}, forward.Config{
		Container: cmd.ForwardContainer,
		Port:      cmd.ForwardPort,
		Bind:      cmd.ForwardBind,
	}, forward.IO{Stdout: os.Stdout, Stderr: os.Stderr})
	if err != nil {
		fmt.Fprintf(os.Stderr, "netcage: forward: %v\n", err)
		return 1
	}
	return 0
}

// runVerify runs the leak-test against the configured proxy and exits per the
// report (non-zero on any failed assertion, so CI can gate on it, story 8). The
// per-assertion pass/fail summary goes to stderr. The passed ctx is
// SIGINT-cancellable so a Ctrl-C during verify tears the jail down cleanly.
func runVerify(ctx context.Context, cmd *cli.Command) int {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	rep := verify.RunCommandVerify(ctx, cmd.Proxy, cmd.ProxySource)
	fmt.Fprint(os.Stderr, rep.String())
	return rep.ExitCode()
}

// runDetectProxy runs the reusable, tool-agnostic proxy DETECTION primitive: it
// probes the common local SOCKS ports (9050/9150/1080), CONFIRMS each open port
// really speaks SOCKS5 via an RFC1928 handshake, attaches WEAK, HEDGED,
// provider-AGNOSTIC process hints, and (best-effort) shows the exit IP of the
// first confirmed candidate as EVIDENCE the egress is not the host IP (reusing
// verify's exit-IP machinery). It presents EVIDENCE ONLY and NEVER labels the
// exit provider. `--json` emits the versioned, provider-field-free reuse contract
// on stdout instead of the human findings.
//
// It carries no proxy and is not preflighted (cli.IsProxyless). The exit-IP step
// needs podman + network and is BEST-EFFORT: any failure OMITS the evidence
// (never a false one), so detect-proxy still works with no podman / offline. It
// exits 0 whenever the probe ran (finding no proxy is a valid, reported result,
// not an error).
func runDetectProxy(ctx context.Context, cmd *cli.Command) int {
	hints := detectproxy.PortHints(runningProcessNames())
	rep := detectproxy.Probe(detectproxy.DialProber{Hints: hints})

	// Optional exit-IP EVIDENCE for the first confirmed SOCKS5 candidate: reuse
	// verify's exit-IP machinery. Best-effort and non-fatal (no podman / offline /
	// unreachable => omit the evidence, never a false one, never a provider label).
	if port, ok := firstConfirmedPort(rep); ok {
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		proxy := cli.ProxyConfig{Host: "127.0.0.1", Port: fmt.Sprintf("%d", port)}
		if ip, err := verify.ExitIPForProxy(pctx, verify.DefaultJailRunner, proxy); err == nil {
			rep.ExitIP = ip
		}
		cancel()
	}

	if cmd.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(os.Stderr, "netcage: detect-proxy: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Print(rep.Human())
	return 0
}

// runSetupDefault runs the interactive, re-runnable onboarding that persists a
// credential-free DEFAULT proxy so a bare `netcage run` needs no --proxy. It
// composes the in-process detect-proxy engine, verify's exit-IP evidence step,
// and the SINGLE config writer (cli.WriteConfig), keeping the DECISION logic in
// the pure setupdefault package and only wiring the impure prompt / detect /
// verify / write / print seams here. It carries no proxy and is not preflighted
// (cli.IsProxyless): it is ESTABLISHING the proxy, not egressing through one.
//
// The config location is resolved from the real process env (XDG_CONFIG_HOME /
// HOME), so the writer targets ~/.config/netcage/config.json; the writer enforces
// the credential-free + socks5h + 0600 invariants at that one seam.
func runSetupDefault(ctx context.Context, _ *cli.Command) int {
	path, ok := cli.ConfigPath(os.LookupEnv)
	if !ok {
		fmt.Fprintln(os.Stderr, "netcage: setup-default: cannot resolve a config directory (set XDG_CONFIG_HOME or HOME)")
		return 1
	}
	existing, err := cli.ReadConfigView(os.LookupEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netcage: setup-default: %v\n", err)
		return 1
	}
	opts := setupdefault.Options{
		Prompter:   stdinPrompter{in: bufio.NewReader(os.Stdin), out: os.Stderr},
		Detector:   processHintDetector{},
		Verifier:   jailVerifier{ctx: ctx},
		Writer:     envConfigWriter{},
		Console:    stderrConsole{},
		ConfigPath: path,
		Existing:   existing,
	}
	if err := setupdefault.Run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "netcage: setup-default: %v\n", err)
		return 1
	}
	return 0
}

// stdinPrompter is the real interactive input seam: it prints prompts to out
// (stderr, so a piped-to-a-file stdout stays clean) and reads answers from in.
// An empty (bare-Enter) answer means "accept the default". Confirm reads a
// yes/no; a bare Enter uses the supplied default. EOF on stdin returns an error
// so the flow aborts cleanly rather than looping.
type stdinPrompter struct {
	in  *bufio.Reader
	out *os.File
}

func (p stdinPrompter) Ask(prompt, def string) (string, error) {
	fmt.Fprintf(p.out, "%s: ", prompt)
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func (p stdinPrompter) Confirm(prompt string, def bool) (bool, error) {
	suffix := " [y/N]"
	if def {
		suffix = " [Y/n]"
	}
	fmt.Fprintf(p.out, "%s%s: ", prompt, suffix)
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("reading input: %w", err)
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	if ans == "" {
		return def, nil
	}
	return ans == "y" || ans == "yes", nil
}

// processHintDetector is the real detection seam: it runs the detect-proxy engine
// with the WEAK, HEDGED process hints computed from the host process table (the
// same impure shell runDetectProxy uses). It presents evidence only and never
// labels the provider.
type processHintDetector struct{}

func (processHintDetector) Detect() detectproxy.Report {
	hints := detectproxy.PortHints(runningProcessNames())
	return detectproxy.Probe(detectproxy.DialProber{Hints: hints})
}

// jailVerifier is the real verify seam: it reuses verify's exit-IP machinery to
// gather the exit IP of a chosen proxy through an ephemeral jail (evidence the
// egress is not the host IP). It bounds each probe with a timeout. It makes NO
// claim about the provider (evidence only).
type jailVerifier struct{ ctx context.Context }

func (v jailVerifier) ExitIP(proxy cli.ProxyConfig) (string, error) {
	pctx, cancel := context.WithTimeout(v.ctx, 30*time.Second)
	defer cancel()
	return verify.ExitIPForProxy(pctx, verify.DefaultJailRunner, proxy)
}

// envConfigWriter is the real persist seam: it writes through the SINGLE config
// writer (cli.WriteConfig) bound to the real process env, so the credential-free
// + socks5h + 0600 invariants are enforced at that one place. It never forks a
// second writer.
type envConfigWriter struct{}

func (envConfigWriter) Write(proxyURL string, allowDirect []string) error {
	return cli.WriteConfig(os.LookupEnv, proxyURL, allowDirect)
}

// stderrConsole prints setup-default's human lines to stderr, so a redirected
// stdout stays clean (the verb writes no machine output).
type stderrConsole struct{}

func (stderrConsole) Printf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}

// firstConfirmedPort returns the port of the first candidate that CONFIRMED
// SOCKS5, for the optional exit-IP evidence (a confirmed SOCKS5 speaker is the
// only sensible target to probe an exit IP through).
func firstConfirmedPort(rep detectproxy.Report) (int, bool) {
	for _, c := range rep.Candidates {
		if c.SOCKS5 {
			return c.Port, true
		}
	}
	return 0, false
}

// runningProcessNames returns the lower-cased basenames of the host's running
// processes, best-effort, for the WEAK, HEDGED process hints (e.g. a `tor`
// process -> "likely Tor"). It reads /proc (Linux) and returns an empty slice on
// any error, so a missing/unreadable /proc simply yields NO hints (never a wrong
// one). This is the impure shell around detectproxy.PortHints.
func runningProcessNames() []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue // not a PID dir
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue
		}
		names = append(names, strings.TrimSpace(string(comm)))
	}
	return names
}

const usage = `usage:
  netcage run    [flags] [<image>] [<cmd> <args...>]
  netcage start  [--proxy ...] [--allow-direct ...] [-it] [--rm] <container>
  netcage verify [--proxy socks5h://[user:pass@]host:port]
  netcage detect-proxy [--json]
  netcage setup-default
  netcage forward [--bind 127.0.0.1|0.0.0.0] <container> <port>
  netcage ps
  netcage images
  netcage logs|inspect|stop|rm <container>
  netcage exec   [-it] [-w <dir>] [-e KEY=VAL]... [-u <user>] <container> <cmd> [args...]

management verbs (ps/logs/inspect/exec/stop/rm/images) are thin pass-throughs to
podman, scoped to netcage's own containers via the netcage.managed label: they
list/inspect/manage the containers a kept ` + "`netcage run`" + ` leaves behind. They do
NOT egress, so they need NO --proxy; they never stand up or tear down a jail
(` + "`exec`" + ` runs inside the container's existing jailed netns). A non-netcage
container is refused. ` + "`rm`" + ` removes the whole tool+sidecar pair (no orphaned
sidecar).

exec is podman-faithful: it honours -i/--interactive, -t/--tty (a real TTY +
stdin passthrough for -it, so ` + "`netcage exec -it <c> bash`" + ` is a usable
interactive shell), -w/--workdir <dir>, -e/--env KEY=VAL (repeatable), and
-u/--user <user>. These are all network/isolation-irrelevant (ADR-0010), so they
cannot breach the jail; any OTHER flag is refused (fail-closed on the unknown).
exec runs inside the container's EXISTING jailed netns and REFUSES if the jail is
not running (run ` + "`netcage start <c>`" + ` first), so a down jail never yields a
working un-jailed exec.

start is the jail-aware resume verb (NOT a thin pass-through): ` + "`netcage start <name>`" + `
REVIVES a kept netcage container's sidecar (the baked firewall re-applies),
re-execs the DNS forwarder, and re-enters the tool with its state intact, so a
named reusable jailed container is a durable environment. It CARRIES a --proxy
(and any --allow-direct) and RECONCILES it against the config the container was
created with: a DIFFERENT proxy/allowlist is REFUSED (remove it and run again, or
start it with the same jail config) rather than silently reviving a stale jail.

setup-default is a netcage-only onboarding verb (podman has no such verb; ` + "`init`" + `
was rejected because ` + "`podman init`" + ` is real): it is the INTERACTIVE, re-runnable
setup that DETECTS a SOCKS proxy (via detect-proxy), lets you CHOOSE or enter one,
VERIFIES it (shows the exit IP as evidence it differs from your host), WARNS ONCE
about the silent-default tradeoff, and PERSISTS the choice (credential-free) into
~/.config/netcage/config.json (0600), so a bare ` + "`netcage run`" + ` needs no --proxy. It
is the ONLY thing that writes the config file. It REFUSES to persist a ` + "`user:pass@`" + `
proxy (keep authed proxies in NETCAGE_PROXY/--proxy, transient); it is re-runnable
and CONFIRMS before overwriting an existing config. It carries NO --proxy (it is
establishing the proxy, not egressing through one) and is not preflighted.

detect-proxy is a netcage-only utility verb: it PROBES the common local SOCKS
ports (127.0.0.1:9050 Tor, :9150 Tor Browser, :1080 generic), CONFIRMS each open
port really speaks SOCKS5 via an RFC1928 handshake (an open port is not enough),
and presents EVIDENCE-ONLY findings (open ports, handshake result, weak hedged
process hints, and best-effort the exit IP as proof the egress is not the host
IP). It NEVER names/labels the exit provider. It carries NO --proxy (it is
looking FOR one, not egressing) and is not preflighted. --json emits a versioned,
provider-field-free machine contract other tools reuse.

run uses podman-native grammar: the FIRST positional is always the image and the
tool command + args follow it (like ` + "`podman run [flags] IMAGE [CMD...]`" + `), so
` + "`netcage run --proxy ... -it alpine sh`" + ` just works (no marker, no guessing).

default dev image: if NO positional image is given at all, a pinned broad dev
base (buildpack-deps, git + build toolchains) is used, so
` + "`netcage run -it -v <repo>:/work`" + ` drops into that image's shell out of the box.

repo-mount ergonomics: ` + "`-v <repo>`" + ` with no target defaults to ` + "`<repo>:/work`" + `, and
a mount at /work with no -w defaults the workdir to /work, so a repo is worked in
without hand-writing -w. An explicit -w overrides.

proxy (required): --proxy socks5h://[user:pass@]host:port, or the NETCAGE_PROXY
env var (flag wins; if neither is set the run refuses, fail-closed). Only
socks5h:// is accepted (plain socks5:// leaks DNS and is rejected).

allowed run flags: -i, -t, -it/-ti, --rm, -v/--volume host:container[:opts],
-w/--workdir <dir>, -e/--env KEY=VALUE, -u/--user <user>, --entrypoint <path>,
and the vetted network-irrelevant pass-throughs --memory, --cpus, --memory-swap,
-l/--label, --tmpfs, --read-only, --hostname, --pull, --platform, --env-file,
--ulimit, --shm-size. --rm is netcage-owned: it makes the run EPHEMERAL (both the
tool container and its sidecar are removed on exit). WITHOUT --rm the stopped
tool container and its sidecar are LEFT behind (inspectable/restartable like
` + "`podman run`" + `), kept fail-closed by the jail's baked firewall. jail-breaching
flags (--network, -p/--publish, --dns, --privileged, --cap-add, --device,
--name, --add-host) are rejected: netcage owns the network and isolation to keep
the jail leak-proof (--add-host is refused because it pins hostname->IP and
sidesteps proxy-side DNS). Any other flag is rejected by default (fail-closed on
the unknown).`
