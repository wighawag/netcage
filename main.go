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
	"fmt"
	"os"

	"github.com/wighawag/tooljail/internal/cli"
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

	// The jail and verify wiring are not built yet (see work/tasks/). Report
	// honestly with a non-zero exit instead of pretending to have run.
	fmt.Fprintf(os.Stderr, "tooljail: %s: proxy %s reachable; jail wiring not yet implemented (see work/tasks/)\n", cmd.Name, cmd.Proxy.Address())
	return 3
}

const usage = `usage:
  tooljail run    --proxy socks5h://[user:pass@]host:port --image <image> -- <tool> <args...>
  tooljail verify --proxy socks5h://[user:pass@]host:port`
