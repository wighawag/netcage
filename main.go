// Command tooljail runs any containerized tool with all of its TCP and DNS
// egress forced through a SOCKS5h proxy, fail-closed, so the wrapped tool
// cannot leak the real IP or DNS.
//
// This entry point currently wires the CLI surface (parse + socks5h contract +
// fail-loud startup preflight). The jail itself (tun2socks sidecar, nft, pasta
// reachback) and the verify leak-test are built by the work/tasks/ tasks; until
// those land, run/verify parse and preflight, then report that the jail is not
// yet wired rather than silently no-op.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wighawag/tooljail/internal/cli"
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
		// `run` wiring (the jail CLI integration) is a separate task; report
		// honestly with a non-zero exit instead of pretending to have run.
		fmt.Fprintf(os.Stderr, "tooljail: run: proxy %s reachable; `run` CLI wiring not yet implemented (see work/tasks/)\n", cmd.Proxy.Address())
		return 3
	}
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
  tooljail run    --proxy socks5h://[user:pass@]host:port --image <image> -- <tool> <args...>
  tooljail verify --proxy socks5h://[user:pass@]host:port`
