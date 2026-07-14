// Package cli implements netcage's command-line surface: the `run` and `verify`
// subcommands, the socks5h proxy-URL contract, and the fail-loud startup
// preflight. It deliberately does NOT stand up the jail (sidecar/netns/firewall);
// that is the jail-run-forced-egress task. This package is pure parsing +
// validation + a reachability seam, so it is unit-testable without any system
// mutation.
package cli

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wighawag/netcage/internal/devimage"
)

// DefaultMountTarget is the container path a repo mount defaults to (and the
// workdir defaults to) when the user does not spell one out, so a repo dropped in
// with `-v <repo>` (or `-v <repo>:/work`) is worked in without hand-writing -w
// (spec story 10, repo-mount ergonomics).
const DefaultMountTarget = "/work"

// ProxyEnvVar is the environment variable an agent can set instead of passing
// --proxy, so the netcage command line carries nothing netcage-specific and is
// pure `podman run` vocabulary (spec story 8). Precedence is flag > env > refuse.
const ProxyEnvVar = "NETCAGE_PROXY"

// ProxyConfig is a parsed, validated socks5h proxy endpoint.
type ProxyConfig struct {
	Host     string
	Port     string
	Username string // optional
	Password string // optional
}

// Address returns "host:port".
func (p ProxyConfig) Address() string { return net.JoinHostPort(p.Host, p.Port) }

// ParseProxy parses a proxy URL and ENFORCES the socks5h scheme. A plain
// socks5:// (local DNS resolution) is rejected because it is a DNS leak by
// definition: with socks5 the client resolves hostnames on the host resolver,
// which is exactly what netcage exists to prevent. Only socks5h (remote,
// proxy-side resolution) is the target.
func ParseProxy(raw string) (ProxyConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return ProxyConfig{}, errors.New("empty --proxy: a socks5h:// URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("invalid --proxy URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "socks5h":
		// ok
	case "socks5":
		return ProxyConfig{}, fmt.Errorf("--proxy uses socks5:// (local DNS) which LEAKS hostnames to the host resolver; use socks5h:// (remote, proxy-side resolution)")
	default:
		return ProxyConfig{}, fmt.Errorf("--proxy scheme %q unsupported; netcage requires socks5h://", u.Scheme)
	}

	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return ProxyConfig{}, fmt.Errorf("--proxy %q must include host and port (socks5h://host:port)", raw)
	}

	p := ProxyConfig{Host: host, Port: port}
	if u.User != nil {
		p.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			p.Password = pw
		}
	}
	return p, nil
}

// Command is a parsed netcage invocation.
//
// The `run` grammar is podman-native and POSITIONAL: `run [flags] <image>
// [<cmd> <args...>]`, mirroring `podman run [flags] IMAGE [CMD...]`. The FIRST
// positional is ALWAYS the image (no image-vs-command guessing, so `run alpine
// sh` just works) and the tool argv is the remaining positionals. If NO
// positional image is given, the pinned default dev image is used. There is no
// --image flag; a standalone `--` is accepted only as an optional end-of-flags
// marker (a podman nicety) and is not load-bearing. Flags outside the curated
// allow-list are rejected: jail-breaching flags with an explanatory message,
// anything else as an unknown flag.
type Command struct {
	Name  string // "run", "verify", "start", or a management verb (ps/logs/inspect/exec/stop/rm/images/commit/build/pull/load)
	Proxy ProxyConfig

	// ProxySource records which of flag / env / config supplied the resolved
	// Proxy, so downstream verbs report it (verify prints `source: ...`;
	// setup-default reads it) without retrofitting the signal. Empty for
	// management verbs (they carry no proxy).
	ProxySource ProxySource
	Image       string   // required for run (first positional); unused for verify
	ToolArgv    []string // the tool command + args (positionals after the image)
	Mounts      []string // -v/--volume pass-through values (run)

	// StartName is the netcage-managed container NAME the jail-aware `netcage
	// start <name>` verb revives (its single positional). It is the TOOL container
	// name; jail.Start resolves it to the run-attributable pair via the labels. It
	// is EMPTY for every other subcommand. `start` is a jail path (it revives a
	// forced-egress jail and re-execs DNS), so unlike the pass-through management
	// verbs it CARRIES a proxy and IS preflighted + reconciled against the
	// container's baked config.
	StartName string

	// ManageArgv holds a management verb's arguments verbatim: the netcage container
	// NAME for logs/stop/rm, the name + command for exec, the name + read-only
	// inspect flags for inspect, and the read-only podman ps output/query flags
	// (--format/--format json/-q/--filter) for ps (ADR-0016). The management verbs
	// are inspection/lifecycle pass-throughs to podman (scoped by the
	// netcage.managed label in the manage package); they do NOT egress, so they
	// carry no proxy and are NOT subject to the run flag allow-list. The manage
	// package parses/forwards these; the CLI passes them through verbatim. Empty for
	// run/verify.
	ManageArgv []string

	// Interactive / TTY record the -i / -t (and -it/-ti) booleans. This package
	// only PARSES them; `main.go`'s runRun consumes them to run the jailed tool
	// with `podman run -it` (raw stdio passthrough, terminal in raw mode) via
	// jail.Config.Interactive, so a human/agent can shell into the jail.
	Interactive bool // -i / --interactive
	TTY         bool // -t / --tty

	// JSON records the --json flag on `detect-proxy`: emit the machine-readable
	// reuse CONTRACT (the versioned, provider-field-free detection schema) instead
	// of the human findings. It is meaningful ONLY for `detect-proxy` (the one
	// netcage-only UTILITY verb that produces a machine contract); it is unset for
	// every other subcommand.
	JSON bool // --json (detect-proxy: emit the machine reuse contract)

	// Rm records the netcage-owned --rm flag: an EPHEMERAL run (remove BOTH the
	// tool and the sidecar on exit, no residue). It is NOT smuggled to podman's raw
	// --rm; netcage OWNS the container lifecycle and INTERPRETS its own --rm into
	// jail.Config.Ephemeral (remove-both teardown), which also drives the tool
	// container's --rm. Without it a run is KEPT: the stopped tool + sidecar are
	// left behind (inspectable/restartable like `podman run`), fail-closed via the
	// baked firewall. (Contrast --name, which STAYS denied: netcage owns the
	// run-attributable container name.)
	Rm bool // --rm (netcage-owned: ephemeral this run)

	Workdir    string   // -w/--workdir pass-through (run)
	Env        []string // -e/--env pass-through values, repeatable (run)
	User       string   // -u/--user pass-through (run)
	Entrypoint string   // --entrypoint pass-through (run)

	// PassThroughFlags is the ORDERED, verbatim podman-run token stream for the
	// widened, vetted allow-list flags (ADR-0010): each accepted flag appends its
	// podman flag token (canonicalised, e.g. -l -> --label) followed by its value
	// (for a value-taking flag), preserving argv order and repetition. It is passed
	// THROUGH to the tool container's podman run args unchanged. ONLY flags that
	// pass the vetting checklist (they cannot alter network/netns, add caps/devices/
	// privilege, publish/bind ports, affect DNS/resolv, or collide with a
	// netcage-owned name/lifecycle field) append here; everything else is refused
	// (deny-set or unknown-flag), so the fail-closed allow-list is preserved. A
	// single ordered slice (not one typed field per flag) keeps these pure
	// pass-throughs together: netcage adds no defaulting/semantics to them, unlike
	// Mounts/Workdir/Env/User/Entrypoint which it shapes.
	PassThroughFlags []string

	// ForwardContainer / ForwardPort / ForwardHostPort / ForwardBind carry the
	// parsed, validated `netcage forward <container> [hostPort:]jailPort`
	// host-access verb (ADR-0014): the netcage-managed container NAME whose in-jail
	// server to expose, the in-jail JAIL/connect PORT (validated 1..65535, so the
	// wiring task consumes an already-checked port, mirroring DirectAllow.Port), the
	// HOST bind PORT, and the RESOLVED host bind address.
	//
	// The port positional is `[hostPort:]jailPort` (docker/kubectl-familiar): the
	// bare single-port form is the zero-remap special case (host port == jail port),
	// so `forward <c> 3001` stays byte-identical to before. ForwardHostPort DEFAULTS
	// to ForwardPort when no remap is given, so downstream wiring is uniform (it
	// always has a host port). ForwardBind is `127.0.0.1` by DEFAULT (loopback-only,
	// the bare verb) and is `0.0.0.0` ONLY when the operator passes the guardrailed
	// `--bind 0.0.0.0` opt-in; a specific-interface bind is Out of Scope (spec) and
	// refused at parse. All are the ZERO value for every other subcommand. This
	// package only PARSES + VALIDATES the surface; the forward MECHANISM (the
	// socat-into-netns forward) is a separate task that consumes these fields.
	ForwardContainer string // forward: the netcage-managed container name
	ForwardPort      int    // forward: the in-jail JAIL/connect port (1..65535)
	ForwardHostPort  int    // forward: the HOST bind port (1..65535; defaults to ForwardPort when no remap)
	ForwardBind      string // forward: resolved host bind (127.0.0.1 default, or 0.0.0.0)

	// PortsContainer carries the parsed, validated single positional of the
	// `netcage ports <container> [--json]` read verb: the netcage-managed container
	// NAME whose in-jail TCP listeners to enumerate. It is a DEDICATED field (not
	// reused from ForwardContainer) so `ports` and `forward` stay conceptually
	// distinct even though they share the same managed-container resolver. It is the
	// ZERO value for every other subcommand. `ports` reuses Command.JSON for its
	// --json machine-contract flag (one spelling for the machine contract, like
	// detect-proxy). This package only PARSES + VALIDATES the surface; the listener
	// ENUMERATION mechanism (read /proc/net/tcp* via the sidecar) is a separate task
	// that consumes PortsContainer + JSON.
	PortsContainer string // ports: the netcage-managed container name to enumerate

	// AllowDirect is the validated split-tunnel LAN allowlist: --allow
	// values (repeatable) parsed into private-only DirectAllow entries (network +
	// EXACT port). EMPTY by default (no flag) == today's strict jail. This
	// package only PARSES + VALIDATES the allowlist (accepting only RFC1918 /
	// link-local WITH an exact port, rejecting port-omitted/public/hostname/malformed
	// loudly at startup); the split-tunnel-jail-wiring task consumes it to open the
	// narrow direct path.
	AllowDirect []DirectAllow // --allow entries, repeatable (run)
}

// managementVerbs is the set of pass-through management verbs (inspection /
// lifecycle only), routed to the manage package instead of the jail. They are
// deliberately NOT jail verbs: none stands up or tears down a jail, none egresses,
// so none requires a proxy. `start` is intentionally ABSENT here: it is the
// jail-aware revive verb built in its own task, not a thin pass-through.
var managementVerbs = map[string]bool{
	"ps":      true,
	"logs":    true,
	"inspect": true,
	"exec":    true,
	"stop":    true,
	"rm":      true,
	"images":  true,
	// commit is a pass-through management verb like the others: it snapshots a
	// netcage-managed container's FILESYSTEM to a new image (a `podman commit`),
	// scoped by the netcage.managed label. It does NOT egress (a pure
	// filesystem->image snapshot), so it carries NO proxy preflight, exactly like
	// ps/logs/exec/... - and unlike `run`/`start` it never touches the jail.
	"commit": true,
	// build/pull/load are the WRITE side of the netcage image store (ADR-0013): the
	// siblings of the READ verb `images`. They pass through to `podman --root
	// <graphroot> <verb> ...` (the --root injected at the shared ExecRunner.Run
	// seam), forwarding their args VERBATIM, so a `netcage build`/`pull`/`load`
	// writes into the SAME store `netcage run`/`netcage images` read (fixing the
	// v0.7.0 regression where a locally-built image was invisible to `netcage run`).
	// They stand up NO jail and do NOT egress, so like the others they carry NO
	// proxy preflight; unlike the container verbs they are UNGUARDED (they act on
	// images, not run-labelled containers, mirroring `images`).
	"build": true,
	"pull":  true,
	"load":  true,
}

// IsManagementVerb reports whether name is one of the pass-through management
// verbs (so the caller skips the proxy preflight and routes it to the manage
// package rather than the jail).
func IsManagementVerb(name string) bool { return managementVerbs[name] }

// IsManagement reports whether this parsed command is a management verb.
func (c Command) IsManagement() bool { return IsManagementVerb(c.Name) }

// ProxyOnHostLoopback reports whether the proxy listens on the host's loopback
// (the local Tor / ssh -D case), so the jail reaches it via the pasta map with
// reachback narrowing (ADR-0002). A remote proxy is a normal routable host the
// sidecar dials directly and needs neither.
func (c Command) ProxyOnHostLoopback() bool {
	switch c.Proxy.Host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// Reachability checks whether a proxy address is reachable at startup. It is an
// interface so tests can inject a result without real network I/O.
type Reachability interface {
	Check(address string) error
}

// DialReachability checks reachability by attempting a TCP dial to the proxy.
type DialReachability struct{ Timeout time.Duration }

// Check dials the address and returns an error if it cannot connect.
func (d DialReachability) Check(address string) error {
	to := d.Timeout
	if to <= 0 {
		to = 3 * time.Second
	}
	c, err := net.DialTimeout("tcp", address, to)
	if err != nil {
		return err
	}
	return c.Close()
}

// IsProxyless reports whether this parsed command carries NO proxy and so is NOT
// subject to the proxy preflight: the pass-through management verbs (inspection /
// lifecycle, no egress) AND the netcage-only `detect-proxy` utility verb, which
// is LOOKING FOR a proxy rather than egressing through one. A proxy-reachability
// preflight on a verb that has no proxy would be nonsensical.
func (c Command) IsProxyless() bool {
	return c.IsManagement() || c.Name == "detect-proxy" || c.Name == "setup-default" || c.Name == "forward" || c.Name == "ports"
}

// Preflight runs the startup checks with a real TCP dial.
func (c *Command) Preflight() error {
	// Proxyless verbs (management pass-throughs + detect-proxy) do not egress and
	// carry no proxy, so there is nothing to preflight: a proxy-down check would be
	// wrong (requiring --proxy to `ps` / `logs` / `detect-proxy` makes no sense).
	// Skip it for them.
	if c.IsProxyless() {
		return nil
	}
	return c.PreflightWith(DialReachability{})
}

// PreflightWith runs the startup checks using the given reachability checker.
// It FAILS LOUD if the proxy is unreachable: netcage must never silently no-op
// or fall back to the host network when the proxy is down (story 10 / the
// fail-closed invariant).
func (c *Command) PreflightWith(r Reachability) error {
	if err := r.Check(c.Proxy.Address()); err != nil {
		return fmt.Errorf("proxy %s is unreachable at startup: %w (refusing to run: netcage fails closed, it never leaks to the host network)", c.Proxy.Address(), err)
	}
	return nil
}

// denyReasons maps each jail-breaching flag to WHY netcage refuses it. netcage
// OWNS the container's network and isolation (it sets `--network
// container:<sidecar>`, a run-attributable `--name`, and the in-netns DNS
// forwarder), so honouring a user/agent-supplied one would either collide with
// what netcage sets or open a leak path around the forced-egress jail. The
// message is part of the agent-facing interface: a self-correcting nudge.
//
// NOTE: --rm is NOT here. It is a netcage-OWNED flag (podman-fidelity split,
// ADR-0009): netcage interprets it as "ephemeral this run" (remove both tool +
// sidecar) into jail.Config.Ephemeral and never passes a raw podman --rm through.
// --name STAYS denied because netcage owns the run-attributable name.
var denyReasons = map[string]string{
	"--network":    "netcage owns the container network (it sets --network container:<sidecar> so all egress is forced through the socks5h proxy); overriding it would breach the jail and leak",
	"-p":           "publishing ports (-p/--publish) would open an inbound path around the jail; netcage owns the container's networking to keep it leak-proof. To view an in-jail server on the host, use `netcage forward <container> [hostPort:]jailPort` (loopback by default)",
	"--publish":    "publishing ports (-p/--publish) would open an inbound path around the jail; netcage owns the container's networking to keep it leak-proof. To view an in-jail server on the host, use `netcage forward <container> [hostPort:]jailPort` (loopback by default)",
	"--dns":        "netcage owns DNS (it forces resolution through the socks5h proxy via the in-netns forwarder); a user --dns would leak DNS to a host-reachable resolver, defeating the jail",
	"--privileged": "a privileged container can escape the network jail and the isolation netcage depends on; refused to keep the jail leak-proof",
	"--cap-add":    "added capabilities (e.g. NET_ADMIN) let the tool re-route around the forced-egress jail; netcage owns the container's capabilities to keep it leak-proof",
	"--device":     "passing host devices can bypass the network namespace the jail relies on; netcage owns device access to keep the jail leak-proof",
	"--name":       "netcage owns the container --name (it uses a run-attributable name for teardown); a user --name would collide with the jail's lifecycle management",
	"--add-host":   "--add-host pins a hostname->IP mapping in the container's /etc/hosts, which is consulted BEFORE the resolver and so sidesteps netcage's proxy-side DNS (the tool could reach an attacker-chosen IP for a name without the proxy resolving it); refused for now to keep DNS forced through the jail",
}

// passThroughValueFlags is the set of widened, vetted allow-list flags that TAKE
// A VALUE and are passed THROUGH verbatim to the tool container's podman run args
// (ADR-0010). Each passes the vetting checklist: it cannot alter network/netns,
// add caps/devices/privilege, publish/bind ports, affect DNS/resolv, or collide
// with a netcage-owned name/lifecycle field (--name/--rm/--network). The two
// value-less members of the widened set (--read-only) and the short-form -l/--label
// are handled as their own parse cases; every entry here is `--flag value`-shaped.
//
// This is the canonical vetting record: to widen the allow-list, add a flag here
// (or a dedicated case) ONLY after checking it against the checklist. --add-host
// deliberately FAILS the checklist (it pins hostname->IP, sidestepping proxy-side
// DNS) so it lives in denyReasons, not here.
var passThroughValueFlags = map[string]bool{
	"--memory":      true,
	"--cpus":        true,
	"--memory-swap": true,
	"--tmpfs":       true,
	"--hostname":    true,
	"--pull":        true,
	"--platform":    true,
	"--env-file":    true,
	"--ulimit":      true,
	"--shm-size":    true,
}

// isPassThroughValueFlag reports whether a is a value-taking pass-through flag in
// its `--flag` (separate value) form.
func isPassThroughValueFlag(a string) bool { return passThroughValueFlags[a] }

// isPassThroughValueFlagEquals reports whether a is a value-taking pass-through
// flag in its `--flag=value` form.
func isPassThroughValueFlagEquals(a string) bool {
	i := strings.IndexByte(a, '=')
	if i < 0 {
		return false
	}
	return passThroughValueFlags[a[:i]]
}

// splitFlagEquals splits a `--flag=value` into its name and value.
func splitFlagEquals(a string) (name, value string) {
	i := strings.IndexByte(a, '=')
	return a[:i], a[i+1:]
}

// Parse parses argv (without the program name) into a Command, reading the
// NETCAGE_PROXY fallback from the real process environment.
func Parse(args []string) (*Command, error) {
	return ParseWithEnv(args, os.LookupEnv)
}

// ParseWithEnv is Parse with an injectable environment lookup (os.LookupEnv in
// production) so the NETCAGE_PROXY precedence and env-validation paths are
// unit-testable without mutating the real process environment.
func ParseWithEnv(args []string, lookupEnv func(string) (string, bool)) (*Command, error) {
	if len(args) == 0 {
		return nil, errors.New("no subcommand: expected `run`, `verify`, `detect-proxy`, `setup-default`, `start`, `forward`, `ports`, or a management verb (ps/logs/inspect/exec/stop/rm/images)")
	}
	name := args[0]
	// Management verbs (ps/logs/inspect/exec/stop/rm/images) are thin podman
	// pass-throughs scoped by the netcage.managed label: they do NOT egress, so
	// they carry NO proxy (no --proxy, no preflight) and are NOT run through the
	// run flag allow-list. Their positionals (a container name, plus the command
	// for exec) pass through to the manage package verbatim.
	if IsManagementVerb(name) {
		return &Command{Name: name, ManageArgv: args[1:]}, nil
	}
	// `detect-proxy` is a NETCAGE-ONLY UTILITY verb (podman has no `detect-proxy`):
	// it PROBES for a local SOCKS proxy, so it is LOOKING FOR a proxy rather than
	// egressing through one. It therefore carries NO --proxy (a --proxy is a usage
	// error, not a silently-ignored flag), is NOT subject to the run flag allow-list
	// or the proxy preflight, and takes only the machine-contract `--json` flag. Its
	// tiny surface is parsed here, entirely separate from the run/verify/start
	// proxy-resolution path below.
	if name == "detect-proxy" {
		return parseDetectProxy(args[1:])
	}
	// `setup-default` is a NETCAGE-ONLY onboarding verb (podman has no such verb;
	// `init` was rejected because `podman init` is real, ADR-0012). It is the ONLY
	// config writer: it detects/chooses/verifies/warns/persists a credential-free
	// DEFAULT proxy so a bare `netcage run` needs no --proxy. It is NOT a jailed
	// run: it is ESTABLISHING the proxy, not egressing through one, so it carries
	// NO --proxy and is NOT preflighted (it resolves the proxy interactively, not
	// from flag/env/config). Its tiny surface is parsed here, separate from the
	// run/verify/start proxy-resolution path below.
	if name == "setup-default" {
		return parseSetupDefault(args[1:])
	}
	// `forward` is a NETCAGE-ONLY host-access verb (ADR-0014): it stands up ONE
	// host `<bind>:<hostPort>` -> in-jail `<jailPort>` INBOUND forward on demand
	// (the port positional is `[hostPort:]jailPort`; the bare form maps host==jail).
	// It is LOOPBACK-by-default and does NOT egress, so like detect-proxy/setup-default
	// it carries NO --proxy (a --proxy is a usage error), is NOT subject to the run
	// allow-list, and is NOT preflighted (IsProxyless). Its tiny surface
	// (<container> [hostPort:]jailPort + the guardrailed --bind) is parsed here,
	// separate from the run/verify/start proxy-resolution path below.
	if name == "forward" {
		return parseForward(args[1:])
	}
	// `ports` is a NETCAGE-ONLY read verb (podman has no `ports`): it LISTS a jailed
	// container's open TCP listeners by reading /proc/net/tcp* via the sidecar. It
	// only reads /proc and sends NO traffic, so like forward/detect-proxy/setup-default
	// it carries NO --proxy (a --proxy is a usage error), is NOT subject to the run
	// allow-list, and is NOT preflighted (IsProxyless). Its tiny surface (a single
	// <container> positional + the machine-contract --json) is parsed here, separate
	// from the run/verify/start proxy-resolution path below.
	if name == "ports" {
		return parsePorts(args[1:])
	}
	switch name {
	case "run", "verify", "start":
	default:
		return nil, fmt.Errorf("unknown subcommand %q: expected `run`, `verify`, `start`, `detect-proxy`, `setup-default`, `forward`, `ports`, or a management verb (ps/logs/inspect/exec/stop/rm/images/commit)", name)
	}

	rest := args[1:]
	cmd := &Command{Name: name}

	var proxyRaw string
	var proxyFromFlag bool
	var allowDirectFromFlag bool // any explicit --allow on the CLI (drives REPLACE vs config)
	var positionals []string
	endOfFlags := false

	for i := 0; i < len(rest); i++ {
		a := rest[i]

		// Once we are past the flags (either a standalone `--` marker or the first
		// positional image), everything else is positional: the image and the tool
		// argv. A `-t` here is a tool arg, not netcage's TTY flag.
		if endOfFlags {
			positionals = append(positionals, a)
			continue
		}
		if a == "--" {
			// Optional explicit end-of-flags marker (a podman nicety). The image and
			// argv follow it; the marker itself is not a positional. It is no longer
			// load-bearing: the first positional is the image with or without it.
			endOfFlags = true
			continue
		}

		// A jail-breaching flag: reject loudly, in both --flag and --flag=value forms.
		if reason, denied := denyFlag(a); denied {
			flag := denyFlagName(a)
			return nil, fmt.Errorf("flag %s is not allowed: %s", flag, reason)
		}

		switch {
		case a == "--proxy":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--proxy requires a value")
			}
			proxyRaw, proxyFromFlag = v, true
		case strings.HasPrefix(a, "--proxy="):
			proxyRaw, proxyFromFlag = strings.TrimPrefix(a, "--proxy="), true

		case a == "-i" || a == "--interactive":
			cmd.Interactive = true
		case a == "-t" || a == "--tty":
			cmd.TTY = true
		case a == "-it" || a == "-ti":
			cmd.Interactive, cmd.TTY = true, true
		case a == "--rm":
			// netcage-OWNED --rm: ephemeral this run (remove both tool + sidecar).
			// netcage interprets it into jail.Config.Ephemeral; it is NOT passed
			// through as a raw podman --rm.
			cmd.Rm = true

		case a == "-v" || a == "--volume":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-v/--volume requires a value (host:container[:opts])")
			}
			cmd.Mounts = append(cmd.Mounts, v)
		case strings.HasPrefix(a, "--volume="):
			cmd.Mounts = append(cmd.Mounts, strings.TrimPrefix(a, "--volume="))
		case strings.HasPrefix(a, "-v="):
			cmd.Mounts = append(cmd.Mounts, strings.TrimPrefix(a, "-v="))

		case a == "-w" || a == "--workdir":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-w/--workdir requires a value")
			}
			cmd.Workdir = v
		case strings.HasPrefix(a, "--workdir="):
			cmd.Workdir = strings.TrimPrefix(a, "--workdir=")
		case strings.HasPrefix(a, "-w="):
			cmd.Workdir = strings.TrimPrefix(a, "-w=")

		case a == "-e" || a == "--env":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-e/--env requires a value (KEY=VALUE)")
			}
			cmd.Env = append(cmd.Env, v)
		case strings.HasPrefix(a, "--env="):
			cmd.Env = append(cmd.Env, strings.TrimPrefix(a, "--env="))
		case strings.HasPrefix(a, "-e="):
			cmd.Env = append(cmd.Env, strings.TrimPrefix(a, "-e="))

		case a == "-u" || a == "--user":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-u/--user requires a value")
			}
			cmd.User = v
		case strings.HasPrefix(a, "--user="):
			cmd.User = strings.TrimPrefix(a, "--user=")
		case strings.HasPrefix(a, "-u="):
			cmd.User = strings.TrimPrefix(a, "-u=")

		case a == "--entrypoint":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--entrypoint requires a value")
			}
			cmd.Entrypoint = v
		case strings.HasPrefix(a, "--entrypoint="):
			cmd.Entrypoint = strings.TrimPrefix(a, "--entrypoint=")

		// --- Widened, vetted allow-list (ADR-0010): network/isolation-IRRELEVANT
		// podman flags passed THROUGH verbatim to the tool container. Each passes the
		// vetting checklist (cannot alter network/netns, add caps/devices/privilege,
		// publish/bind ports, affect DNS/resolv, or collide with a netcage-owned
		// name/lifecycle field: --name/--rm/--network). A value-taking flag MUST be
		// parsed as taking its value so the value is not mis-scanned as the positional
		// image. --read-only is the sole boolean. -l is podman's short --label; it is
		// canonicalised to --label so the pass-through carries a single spelling.
		case a == "--read-only":
			cmd.PassThroughFlags = append(cmd.PassThroughFlags, "--read-only")

		case a == "-l" || a == "--label":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("-l/--label requires a value (key=value)")
			}
			cmd.PassThroughFlags = append(cmd.PassThroughFlags, "--label", v)
		case strings.HasPrefix(a, "--label="):
			cmd.PassThroughFlags = append(cmd.PassThroughFlags, "--label", strings.TrimPrefix(a, "--label="))
		case strings.HasPrefix(a, "-l="):
			cmd.PassThroughFlags = append(cmd.PassThroughFlags, "--label", strings.TrimPrefix(a, "-l="))

		case isPassThroughValueFlag(a):
			v, ok := next(rest, &i)
			if !ok {
				return nil, fmt.Errorf("%s requires a value", a)
			}
			cmd.PassThroughFlags = append(cmd.PassThroughFlags, a, v)
		case isPassThroughValueFlagEquals(a):
			name, v := splitFlagEquals(a)
			cmd.PassThroughFlags = append(cmd.PassThroughFlags, name, v)

		case a == "--allow":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--allow requires a value (an RFC1918/link-local IP or CIDR WITH a :port, e.g. 192.168.1.150:8080)")
			}
			entry, aerr := parseAllowDirect(v)
			if aerr != nil {
				return nil, aerr
			}
			cmd.AllowDirect = append(cmd.AllowDirect, entry)
			allowDirectFromFlag = true
		case strings.HasPrefix(a, "--allow="):
			entry, aerr := parseAllowDirect(strings.TrimPrefix(a, "--allow="))
			if aerr != nil {
				return nil, aerr
			}
			cmd.AllowDirect = append(cmd.AllowDirect, entry)
			allowDirectFromFlag = true

		case strings.HasPrefix(a, "-") && a != "-":
			// An unlisted/unaudited flag: reject by default (fail-closed on the CLI)
			// so it cannot silently ride through into the tool container. "-" alone
			// (stdin) is treated as a positional, not a flag.
			return nil, fmt.Errorf("unknown flag %q: netcage accepts only a curated allow-list of podman flags (-i, -t, -it, --rm, -v/--volume, -w/--workdir, -e/--env, -u/--user, --entrypoint, --memory, --cpus, --memory-swap, -l/--label, --tmpfs, --read-only, --hostname, --pull, --platform, --env-file, --ulimit, --shm-size) plus --proxy and --allow; a network/isolation-relevant or unknown flag is refused (fail-closed on the unknown)", a)

		default:
			// The first non-flag positional ends the flags: it is the image, and
			// everything after it is the tool argv (mirroring podman/docker).
			endOfFlags = true
			positionals = append(positionals, a)
		}
	}

	// Config is a NEW, lowest-priority proxy SOURCE, never a bypass: it is loaded
	// (and its allow list validated) HERE, then fed into the SAME strict
	// resolution below. A missing file is a clean no-op; a present-but-broken file
	// is a loud error (config is not laxer than flag/env). See ADR-0012.
	conf, err := loadConfig(lookupEnv)
	if err != nil {
		return nil, err
	}

	// Proxy resolution: flag > env > config > refuse. ALL three paths go through
	// the SAME socks5h-enforcing ParseProxy (no path is laxer), and the winning
	// SOURCE is recorded so downstream verbs can report it.
	source := ProxySourceFlag
	if !proxyFromFlag {
		if v, ok := lookupEnv(ProxyEnvVar); ok && strings.TrimSpace(v) != "" {
			proxyRaw, source = v, ProxySourceEnv
		} else if conf.present && strings.TrimSpace(conf.proxyURL) != "" {
			proxyRaw, source = conf.proxyURL, ProxySourceConfig
		}
	}
	if strings.TrimSpace(proxyRaw) == "" {
		return nil, fmt.Errorf("no proxy: pass --proxy socks5h://host:port or set %s (netcage refuses to run without a proxy; it fails closed and never leaks to the host network)", ProxyEnvVar)
	}
	proxy, err := ParseProxy(proxyRaw)
	if err != nil {
		return nil, err
	}
	cmd.Proxy = proxy
	cmd.ProxySource = source

	// --allow precedence is REPLACE, not additive: an explicit CLI
	// --allow supplies the COMPLETE allowlist and fully overrides the
	// config list (nothing implicitly rides along). Only when NO CLI
	// --allow is given does the config allow list apply.
	if !allowDirectFromFlag && conf.present && len(conf.allowDirect) > 0 {
		cmd.AllowDirect = conf.allowDirect
	}

	// The CONFIG-dependent half of the host-loopback port-blocklist (ADR-0019):
	// refuse a host-loopback --allow on the CONFIGURED proxy port. This is checked
	// HERE (not in the context-free parseAllowDirect) because the proxy port is
	// known only after resolution, and it is applied to the FINAL allowlist so a
	// config-supplied host-loopback entry is covered too. A refusal here is still
	// at config time, before any container/firewall mutation, so the host is
	// untouched. A LAN --allow is unaffected.
	if err := refuseHostLoopbackProxyPort(cmd.AllowDirect, cmd.Proxy.Host, cmd.Proxy.Port); err != nil {
		return nil, err
	}

	switch name {
	case "run":
		resolveRunPositionals(cmd, positionals)
		resolveRepoMountDefaults(cmd)
	case "start":
		// `start` takes EXACTLY ONE positional: the netcage-managed container name to
		// revive. Zero is a usage error (nothing to start); more than one is refused
		// so a typo does not silently start the wrong container.
		if len(positionals) == 0 {
			return nil, errors.New("start requires a netcage container name to revive (netcage start <name>)")
		}
		if len(positionals) > 1 {
			return nil, fmt.Errorf("start takes exactly one netcage container name, got %v", positionals)
		}
		cmd.StartName = positionals[0]
		// `start` REVIVES an EXISTING container; the create-time flags (-v/-w/-e/-u/
		// --entrypoint + the widened pass-throughs) cannot apply to a `podman start` and
		// would be silently ignored, so refuse them loudly rather than pretend they took
		// effect. --proxy/--allow (the jail config to RECONCILE) and -i/-t/--rm
		// (attach mode + ephemeral) ARE accepted.
		if err := rejectStartCreateFlags(cmd); err != nil {
			return nil, err
		}
	default: // verify
		if len(positionals) > 0 {
			return nil, fmt.Errorf("verify takes no positional arguments, got %v", positionals)
		}
	}

	return cmd, nil
}

// parseForward parses the `netcage forward <container> [hostPort:]jailPort` host-access verb
// (ADR-0014). Its guardrails are enforced HERE, at the parse layer:
//
//   - Exactly two positionals: the netcage-managed container NAME and the port
//     spec `[hostPort:]jailPort` (docker/kubectl-familiar). The bare single-port
//     form is the zero-remap special case (host port == jail port), so it stays
//     byte-identical to before. Zero / one / three positionals, a non-numeric /
//     out-of-range host or jail side, or extra colons (`1:2:3`) is a loud usage
//     error. BOTH sides are validated 1..65535.
//   - The sole flag `--bind <addr>` (and `--bind=<addr>`) defaults to the
//     loopback `127.0.0.1`; the ONLY other accepted value is `0.0.0.0` (the
//     guardrailed LAN opt-in). Any other bind (a specific interface, ::1,
//     localhost, ...) is refused loudly: a specific-interface bind is Out of
//     Scope (spec), so it is refused now rather than silently accepted.
//   - NO --proxy (it does not egress; a --proxy is a usage error, not a
//     silently-ignored flag), and any unknown flag is refused (fail-closed on the
//     unknown), consistent with the other verbs.
//
// It does NOT stand up the forward: the MECHANISM (socat into the netns) is a
// separate task that consumes ForwardContainer/ForwardPort/ForwardBind.
func parseForward(rest []string) (*Command, error) {
	cmd := &Command{Name: "forward", ForwardBind: "127.0.0.1"}
	var positionals []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--bind":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--bind requires a value (127.0.0.1 for loopback, or 0.0.0.0 to expose on the LAN)")
			}
			bind, berr := resolveForwardBind(v)
			if berr != nil {
				return nil, berr
			}
			cmd.ForwardBind = bind
		case strings.HasPrefix(a, "--bind="):
			bind, berr := resolveForwardBind(strings.TrimPrefix(a, "--bind="))
			if berr != nil {
				return nil, berr
			}
			cmd.ForwardBind = bind
		case a == "--proxy" || strings.HasPrefix(a, "--proxy="):
			return nil, errors.New("forward takes no --proxy: it stands up an INBOUND loopback forward, not an egress (it does not proxy anything)")
		case strings.HasPrefix(a, "-") && a != "-":
			return nil, fmt.Errorf("unknown flag %q: forward accepts only --bind (127.0.0.1 default, or 0.0.0.0 for the guardrailed LAN opt-in) plus the positionals <container> [hostPort:]jailPort", a)
		default:
			positionals = append(positionals, a)
		}
	}
	if len(positionals) != 2 {
		return nil, fmt.Errorf("forward takes exactly <container> [hostPort:]jailPort, got %d positional(s) %v", len(positionals), positionals)
	}
	cmd.ForwardContainer = positionals[0]
	hostPort, jailPort, perr := parseForwardPortSpec(positionals[1])
	if perr != nil {
		return nil, perr
	}
	cmd.ForwardHostPort = hostPort
	cmd.ForwardPort = jailPort
	return cmd, nil
}

// parseForwardPortSpec parses the forward's `[hostPort:]jailPort` port positional
// into the (host bind port, in-jail connect port) pair, both validated 1..65535.
//
//   - Zero colons (`3001`) is the bare, backward-compatible form: host == jail,
//     so the single-port invocation is unchanged (the zero-remap special case).
//   - Exactly one colon (`8080:3001`) is the remap: host `8080` -> jail `3001`,
//     the familiar docker `-p` / kubectl `port-forward` order.
//   - Two or more colons (`1:2:3`) is a loud usage error.
//
// It uses a plain strings.Split + count check (NOT net.SplitHostPort): both sides
// are bare port NUMBERS with no host address, so net.SplitHostPort would
// mis-handle the colon-count / IPv6 cases and is the wrong tool here.
func parseForwardPortSpec(s string) (hostPort, jailPort int, err error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		p, perr := parseForwardPort(parts[0])
		if perr != nil {
			return 0, 0, perr
		}
		// The bare form is the zero-remap special case: host port defaults to the
		// jail port, so the single-port invocation is byte-identical to before.
		return p, p, nil
	case 2:
		hp, herr := parseForwardPort(parts[0])
		if herr != nil {
			return 0, 0, fmt.Errorf("forward host port: %w", herr)
		}
		jp, jerr := parseForwardPort(parts[1])
		if jerr != nil {
			return 0, 0, fmt.Errorf("forward jail port: %w", jerr)
		}
		return hp, jp, nil
	default:
		return 0, 0, fmt.Errorf("forward port %q has too many colons: expected [hostPort:]jailPort (at most one colon), e.g. 3001 or 8080:3001", s)
	}
}

// resolveForwardBind validates a --bind value against the two accepted binds and
// returns the resolved address. Loopback (127.0.0.1) is the default the bare verb
// uses; 0.0.0.0 is the guardrailed LAN opt-in (ADR-0014). Every other value (a
// specific interface, ::1, localhost, a host:port, a malformed string) is refused
// loudly: a specific-interface bind is Out of Scope (spec).
func resolveForwardBind(v string) (string, error) {
	switch v {
	case "127.0.0.1", "0.0.0.0":
		return v, nil
	default:
		return "", fmt.Errorf("--bind %q is not allowed: forward accepts only 127.0.0.1 (loopback, the default) or 0.0.0.0 (the guardrailed all-interfaces LAN opt-in); a specific-interface bind is out of scope", v)
	}
}

// parseForwardPort parses and validates the forward's single TCP port, mirroring
// the --allow port validation (1..65535). It returns the port as an int so
// the wiring task consumes an already-checked value.
func parseForwardPort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("forward port %q is not a number: expected a TCP port 1-65535", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("forward port %d is out of range: expected a TCP port 1-65535", p)
	}
	return p, nil
}

// parsePorts parses the `netcage ports <container> [--json]` read verb's tiny
// surface, mirroring the proxyless-verb pattern of detect-proxy / forward:
//
//   - Exactly ONE positional: the netcage-managed container NAME whose in-jail TCP
//     listeners to enumerate. Zero or two+ positionals is a loud usage error.
//   - The sole flag `--json` (and `--json=`... is NOT a thing; it is a boolean):
//     emit the machine-readable listener contract instead of the human table. It
//     reuses the existing Command.JSON field so there is one spelling for the
//     machine contract (like detect-proxy --json).
//   - NO --proxy (it only reads /proc, it does not egress; a --proxy is a usage
//     error, not a silently-ignored flag), and any unknown flag is refused
//     (fail-closed on the unknown), consistent with the other verbs.
//
// It does NOT enumerate the listeners: the MECHANISM (read /proc/net/tcp* via the
// sidecar) is a separate task that consumes PortsContainer + JSON.
func parsePorts(rest []string) (*Command, error) {
	cmd := &Command{Name: "ports"}
	var positionals []string
	for _, a := range rest {
		switch {
		case a == "--json":
			cmd.JSON = true
		case a == "--proxy" || strings.HasPrefix(a, "--proxy="):
			return nil, errors.New("ports takes no --proxy: it only reads /proc to list a jail's open TCP listeners, it does not egress (a pure read like detect-proxy)")
		case strings.HasPrefix(a, "-") && a != "-":
			return nil, fmt.Errorf("unknown flag %q: ports accepts only --json (emit the machine listener contract) plus the single positional <container>", a)
		default:
			positionals = append(positionals, a)
		}
	}
	if len(positionals) != 1 {
		return nil, fmt.Errorf("ports takes exactly one netcage container name, got %d positional(s) %v", len(positionals), positionals)
	}
	cmd.PortsContainer = positionals[0]
	return cmd, nil
}

// parseDetectProxy parses the `detect-proxy` verb's tiny surface: the boolean
// `--json` flag and nothing else. It deliberately does NOT resolve a proxy
// (flag/env/config) and does NOT accept --proxy, positionals, or the run
// allow-list flags: detect-proxy is LOOKING FOR a proxy, so requiring or
// preflighting one would be nonsensical. Any --proxy, positional, or unknown flag
// is refused loudly (fail-closed on the unknown), keeping the verb's "no proxy,
// not preflighted" contract unambiguous.
func parseDetectProxy(rest []string) (*Command, error) {
	cmd := &Command{Name: "detect-proxy"}
	for _, a := range rest {
		switch {
		case a == "--json":
			cmd.JSON = true
		case a == "--proxy" || strings.HasPrefix(a, "--proxy="):
			return nil, errors.New("detect-proxy takes no --proxy: it is looking FOR a proxy, not egressing through one (run `netcage verify` to test a specific proxy)")
		case strings.HasPrefix(a, "-") && a != "-":
			return nil, fmt.Errorf("unknown flag %q: detect-proxy accepts only --json (it probes the common local SOCKS ports and carries no proxy)", a)
		default:
			return nil, fmt.Errorf("detect-proxy takes no positional arguments, got %q (it probes the fixed common SOCKS ports 9050/9150/1080)", a)
		}
	}
	return cmd, nil
}

// parseSetupDefault parses the `setup-default` verb's tiny surface: it takes NO
// flags and NO positionals. It is INTERACTIVE onboarding (it prompts for the
// proxy), so it does NOT take a --proxy (that would be a usage error, not a
// silently-ignored flag) and is NOT subject to the run allow-list or the proxy
// preflight: it is ESTABLISHING the default proxy, not egressing through one. Any
// flag or positional is refused loudly, keeping the verb's "no proxy, not
// preflighted, interactive" contract unambiguous.
func parseSetupDefault(rest []string) (*Command, error) {
	for _, a := range rest {
		switch {
		case a == "--proxy" || strings.HasPrefix(a, "--proxy="):
			return nil, errors.New("setup-default takes no --proxy: it is INTERACTIVE onboarding that detects/asks for the proxy to persist as the default (pass one transiently with `netcage run --proxy ...` instead)")
		case strings.HasPrefix(a, "-") && a != "-":
			return nil, fmt.Errorf("unknown flag %q: setup-default takes no flags (it is interactive onboarding that detects/chooses/verifies/persists a default proxy)", a)
		default:
			return nil, fmt.Errorf("setup-default takes no positional arguments, got %q (it is interactive: it detects the proxy and prompts for the choice)", a)
		}
	}
	return &Command{Name: "setup-default"}, nil
}

// resolveRunPositionals splits the run positionals into the image and the tool
// argv, following podman's grammar exactly: `run [flags] IMAGE [CMD...]`.
//
//   - The FIRST positional is ALWAYS the image, just like `podman run IMAGE
//     [CMD...]`. So `run -it alpine sh` => image `alpine`, argv `[sh]`, with no
//     `--` marker and no image-vs-command guessing. A bare-token image (`alpine`,
//     `ubuntu`) needs nothing special: it is the first positional, so it is the
//     image.
//   - NO positionals at all => the pinned DEFAULT dev image with an EMPTY argv,
//     so `netcage run -it -v <repo>:/work` drops into the default image's own
//     shell out of the box (spec story 10). This is the ONLY case the default
//     image applies: a default is used solely when the user supplied no image.
//
// The `--` end-of-flags marker is still accepted (a podman nicety) but is no
// longer load-bearing: because the first positional is unconditionally the
// image, `run alpine sh` and `run -- alpine sh` mean the same thing.
func resolveRunPositionals(cmd *Command, positionals []string) {
	if len(positionals) == 0 {
		cmd.Image = defaultImageReference()
		return
	}
	cmd.Image = positionals[0]
	cmd.ToolArgv = positionals[1:]
}

// resolveRepoMountDefaults applies the repo-mount ergonomics (spec story 10): a
// bare `-v <repo>` value with no :container part defaults its target to /work,
// and if the user gave no explicit -w but there is a mount targeting /work, the
// workdir defaults to /work, so a repo dropped in is worked in without
// hand-writing -w. An explicit -w always wins (it is left untouched here).
func resolveRepoMountDefaults(cmd *Command) {
	mountsAtDefaultTarget := false
	for i, m := range cmd.Mounts {
		if mountHasNoContainerTarget(m) {
			cmd.Mounts[i] = m + ":" + DefaultMountTarget
			mountsAtDefaultTarget = true
			continue
		}
		if mountContainerTarget(m) == DefaultMountTarget {
			mountsAtDefaultTarget = true
		}
	}
	if cmd.Workdir == "" && mountsAtDefaultTarget {
		cmd.Workdir = DefaultMountTarget
	}
}

// defaultImageReference is the pinned, digest-immutable default dev image the CLI
// injects when no positional image is given. It is a var (not a direct call) only
// so the reference is resolved in one place; it always returns the pinned
// devimage reference.
func defaultImageReference() string { return devimage.ImageReference() }

// mountHasNoContainerTarget reports whether a -v value is a bare host path with no
// :container target (so its target should default to /work). A Windows-style
// drive letter (`C:\...`) is not a target separator, but netcage's mounts are
// host paths on a Linux host, so a lone `:` here means an explicit target.
func mountHasNoContainerTarget(m string) bool {
	return !strings.Contains(m, ":")
}

// mountContainerTarget returns the container-target segment of a `host:container`
// (or `host:container:opts`) -v value, or "" if there is none.
func mountContainerTarget(m string) string {
	parts := strings.SplitN(m, ":", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// rejectStartCreateFlags refuses the create-time run flags on `netcage start`: a
// revive of an EXISTING container cannot honour -v/-w/-e/-u/--entrypoint or the
// widened pass-throughs (they are baked at create time and a `podman start` takes
// none of them), so accepting-and-ignoring them would silently mislead. --proxy /
// --allow (the jail config reconciled against the container's baked one)
// and -i/-t/--rm are the flags start DOES take, so they are not rejected here.
func rejectStartCreateFlags(cmd *Command) error {
	switch {
	case len(cmd.Mounts) > 0:
		return errors.New("start does not take -v/--volume: it revives an EXISTING container (mounts are fixed at create time); remove it and `netcage run` again to change mounts")
	case cmd.Workdir != "":
		return errors.New("start does not take -w/--workdir: it revives an EXISTING container whose workdir is fixed at create time")
	case len(cmd.Env) > 0:
		return errors.New("start does not take -e/--env: it revives an EXISTING container whose env is fixed at create time")
	case cmd.User != "":
		return errors.New("start does not take -u/--user: it revives an EXISTING container whose user is fixed at create time")
	case cmd.Entrypoint != "":
		return errors.New("start does not take --entrypoint: it revives an EXISTING container whose entrypoint is fixed at create time")
	case len(cmd.PassThroughFlags) > 0:
		return errors.New("start does not take create-time flags (--memory/--label/--tmpfs/...): it revives an EXISTING container; those are fixed at create time")
	}
	return nil
}

// denyFlag reports whether a is a jail-breaching flag (in --flag or --flag=value
// form) and, if so, the reason it is refused.
func denyFlag(a string) (reason string, denied bool) {
	name := denyFlagName(a)
	r, ok := denyReasons[name]
	return r, ok
}

// denyFlagName strips a `=value` suffix so `--network=host` maps to `--network`.
func denyFlagName(a string) string {
	if i := strings.IndexByte(a, '='); i >= 0 {
		return a[:i]
	}
	return a
}

// next returns the value following the flag at *i and advances *i past it.
func next(args []string, i *int) (string, bool) {
	if *i+1 >= len(args) {
		return "", false
	}
	*i++
	return args[*i], true
}
