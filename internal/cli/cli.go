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
	"strings"
	"time"

	"github.com/wighawag/netcage/internal/devimage"
)

// DefaultMountTarget is the container path a repo mount defaults to (and the
// workdir defaults to) when the user does not spell one out, so a repo dropped in
// with `-v <repo>` (or `-v <repo>:/work`) is worked in without hand-writing -w
// (prd story 10, repo-mount ergonomics).
const DefaultMountTarget = "/work"

// ProxyEnvVar is the environment variable an agent can set instead of passing
// --proxy, so the netcage command line carries nothing netcage-specific and is
// pure `podman run` vocabulary (prd story 8). Precedence is flag > env > refuse.
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
	Name  string // "run", "verify", "start", or a management verb (ps/logs/inspect/exec/stop/rm/images)
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

	// ManageArgv holds a management verb's positional arguments verbatim: the
	// netcage container NAME for logs/inspect/stop/rm, the name + command for exec,
	// and nothing for ps/images. The management verbs are inspection/lifecycle
	// pass-throughs to podman (scoped by the netcage.managed label in the manage
	// package); they do NOT egress, so they carry no proxy and are NOT subject to
	// the run flag allow-list. Empty for run/verify.
	ManageArgv []string

	// Interactive / TTY record the -i / -t (and -it/-ti) booleans. This package
	// only PARSES them; `main.go`'s runRun consumes them to run the jailed tool
	// with `podman run -it` (raw stdio passthrough, terminal in raw mode) via
	// jail.Config.Interactive, so a human/agent can shell into the jail.
	Interactive bool // -i / --interactive
	TTY         bool // -t / --tty

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

	// AllowDirect is the validated split-tunnel LAN allowlist: --allow-direct
	// values (repeatable) parsed into private-only DirectAllow entries (network +
	// optional port). EMPTY by default (no flag) == today's strict jail. This
	// package only PARSES + VALIDATES the allowlist (accepting only RFC1918 /
	// link-local, rejecting public/hostname/malformed loudly at startup); the
	// split-tunnel-jail-wiring task consumes it to open the narrow direct path.
	AllowDirect []DirectAllow // --allow-direct entries, repeatable (run)
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

// Preflight runs the startup checks with a real TCP dial.
func (c *Command) Preflight() error {
	// Management verbs do not egress and carry no proxy, so there is nothing to
	// preflight: a proxy-down check would be wrong (requiring --proxy to `ps` /
	// `logs` makes no sense). Skip it for them.
	if c.IsManagement() {
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
	"-p":           "publishing ports (-p/--publish) would open an inbound path around the jail; netcage owns the container's networking to keep it leak-proof",
	"--publish":    "publishing ports (-p/--publish) would open an inbound path around the jail; netcage owns the container's networking to keep it leak-proof",
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
		return nil, errors.New("no subcommand: expected `run`, `verify`, or a management verb (ps/logs/inspect/exec/stop/rm/images)")
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
	switch name {
	case "run", "verify", "start":
	default:
		return nil, fmt.Errorf("unknown subcommand %q: expected `run`, `verify`, `start`, or a management verb (ps/logs/inspect/exec/stop/rm/images/commit)", name)
	}

	rest := args[1:]
	cmd := &Command{Name: name}

	var proxyRaw string
	var proxyFromFlag bool
	var allowDirectFromFlag bool // any explicit --allow-direct on the CLI (drives REPLACE vs config)
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

		case a == "--allow-direct":
			v, ok := next(rest, &i)
			if !ok {
				return nil, errors.New("--allow-direct requires a value (an RFC1918/link-local IP or CIDR, optionally with :port)")
			}
			entry, aerr := parseAllowDirect(v)
			if aerr != nil {
				return nil, aerr
			}
			cmd.AllowDirect = append(cmd.AllowDirect, entry)
			allowDirectFromFlag = true
		case strings.HasPrefix(a, "--allow-direct="):
			entry, aerr := parseAllowDirect(strings.TrimPrefix(a, "--allow-direct="))
			if aerr != nil {
				return nil, aerr
			}
			cmd.AllowDirect = append(cmd.AllowDirect, entry)
			allowDirectFromFlag = true

		case strings.HasPrefix(a, "-") && a != "-":
			// An unlisted/unaudited flag: reject by default (fail-closed on the CLI)
			// so it cannot silently ride through into the tool container. "-" alone
			// (stdin) is treated as a positional, not a flag.
			return nil, fmt.Errorf("unknown flag %q: netcage accepts only a curated allow-list of podman flags (-i, -t, -it, --rm, -v/--volume, -w/--workdir, -e/--env, -u/--user, --entrypoint, --memory, --cpus, --memory-swap, -l/--label, --tmpfs, --read-only, --hostname, --pull, --platform, --env-file, --ulimit, --shm-size) plus --proxy and --allow-direct; a network/isolation-relevant or unknown flag is refused (fail-closed on the unknown)", a)

		default:
			// The first non-flag positional ends the flags: it is the image, and
			// everything after it is the tool argv (mirroring podman/docker).
			endOfFlags = true
			positionals = append(positionals, a)
		}
	}

	// Config is a NEW, lowest-priority proxy SOURCE, never a bypass: it is loaded
	// (and its allowDirect list validated) HERE, then fed into the SAME strict
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

	// --allow-direct precedence is REPLACE, not additive: an explicit CLI
	// --allow-direct supplies the COMPLETE allowlist and fully overrides the
	// config list (nothing implicitly rides along). Only when NO CLI
	// --allow-direct is given does the config allowDirect apply.
	if !allowDirectFromFlag && conf.present && len(conf.allowDirect) > 0 {
		cmd.AllowDirect = conf.allowDirect
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
		// effect. --proxy/--allow-direct (the jail config to RECONCILE) and -i/-t/--rm
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
//     shell out of the box (prd story 10). This is the ONLY case the default
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

// resolveRepoMountDefaults applies the repo-mount ergonomics (prd story 10): a
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
// --allow-direct (the jail config reconciled against the container's baked one)
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
