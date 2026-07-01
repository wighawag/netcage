// Command tooljail runs any containerized tool with all of its TCP and DNS
// egress forced through a SOCKS5h proxy, fail-closed, so the wrapped tool
// cannot leak the real IP or DNS.
//
// This entry point wires the CLI surface (parse + socks5h contract + fail-loud
// startup preflight) to the jail engine: `run` stands up the forced-egress jail
// and runs the wrapped tool through it; `verify` runs the leak-test. SIGINT
// cancels the run so the jail tears down with no residue.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/wighawag/tooljail/internal/cli"
	"github.com/wighawag/tooljail/internal/jail"
	"github.com/wighawag/tooljail/internal/verify"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd, err := cli.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tooljail: %v\n", err)
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}

	// Fail-loud, fail-closed startup: refuse to proceed if the proxy is down.
	if err := cmd.Preflight(); err != nil {
		fmt.Fprintf(os.Stderr, "tooljail: %v\n", err)
		return 1
	}

	// SIGINT (Ctrl-C) / SIGTERM cancels the context that flows into the jail, so
	// the jail's deferred Teardown runs and leaves NO residue (the teardown
	// invariant's signal path). Teardown itself uses a fresh context, so it
	// completes even though this one is cancelled.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd.Name {
	case "verify":
		return runVerify(ctx, cmd)
	default:
		return runRun(ctx, cmd)
	}
}

// runRun stands up the jail and runs the wrapped tool, propagating the tool's
// exit code as tooljail's own. A jail SETUP failure (a bad/unpullable image, a
// tool command not found, or sidecar/nft/reachback) exits non-zero with a clear
// message; a tool that ran but exited non-zero passes that exit code through (the
// wrapped tool's result is the run's result). SIGINT cancels ctx, so the jail's
// deferred Teardown leaves no residue.
//
// The wrapped tool's stdout/stderr are STREAMED LIVE to tooljail's own
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
		Interactive:         interactive,
	}
	if interactive {
		// Interactive (`tooljail run -it`): RAW stdio passthrough into the jailed
		// `podman run -it`. Wire os.Stdin and leave the capture sinks nil (the raw
		// path ignores them). Put tooljail's controlling terminal into raw mode so
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
		fmt.Fprintf(os.Stderr, "tooljail: run: %v\n", err)
		return 1
	}
	return res.ToolExit
}

// runVerify runs the leak-test against the configured proxy and exits per the
// report (non-zero on any failed assertion, so CI can gate on it, story 8). The
// per-assertion pass/fail summary goes to stderr. The passed ctx is
// SIGINT-cancellable so a Ctrl-C during verify tears the jail down cleanly.
func runVerify(ctx context.Context, cmd *cli.Command) int {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	rep := verify.RunCommandVerify(ctx, cmd.Proxy)
	fmt.Fprint(os.Stderr, rep.String())
	return rep.ExitCode()
}

const usage = `usage:
  tooljail run    [flags] [<image>] [<cmd> <args...>]
  tooljail verify [--proxy socks5h://[user:pass@]host:port]

run uses podman-native grammar: the image is the first positional and the tool
command + args follow it (like ` + "`podman run [flags] IMAGE [CMD...]`" + `).

default dev image: if no positional image is given, a pinned broad dev base
(buildpack-deps, git + build toolchains) is used, so ` + "`tooljail run -it -v <repo>:/work bash`" + `
is useful bare. A bare command-shaped first positional (e.g. ` + "`run -it bash`" + `) is
taken as the COMMAND with the default image; a first positional that looks like an
image (has /, :, @, or .) is the image. Force a bare-token image with ` + "`run -- alpine sh`" + `.

repo-mount ergonomics: ` + "`-v <repo>`" + ` with no target defaults to ` + "`<repo>:/work`" + `, and
a mount at /work with no -w defaults the workdir to /work, so a repo is worked in
without hand-writing -w. An explicit -w overrides.

proxy (required): --proxy socks5h://[user:pass@]host:port, or the TOOLJAIL_PROXY
env var (flag wins; if neither is set the run refuses, fail-closed). Only
socks5h:// is accepted (plain socks5:// leaks DNS and is rejected).

allowed run flags: -i, -t, -it/-ti, -v/--volume host:container[:opts],
-w/--workdir <dir>, -e/--env KEY=VALUE, -u/--user <user>, --entrypoint <path>.
jail-breaching flags (--network, -p/--publish, --dns, --privileged, --cap-add,
--device, --name, --rm) are rejected: tooljail owns the network and isolation to
keep the jail leak-proof. Any other flag is rejected by default.`
