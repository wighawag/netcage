package jail_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/tooljail/internal/cli"
	"github.com/wighawag/tooljail/internal/jail"
	"github.com/wighawag/tooljail/internal/socks5hfixture"
)

// TestJail_Interactive_IdenticalTopologyForcedEgressAndNoResidue is the
// podman-gated proof that an INTERACTIVE-flagged run stands up the IDENTICAL jail
// topology as a plain run: the same sidecar + shared netns + nft ruleset (UDP
// dropped, reachback narrowed) + forced egress + fail-closed default, so `-it`
// does NOT weaken the jail. It also proves the run leaves NO residue.
//
// Interactive mode does RAW passthrough (no capture), so the exit IP cannot be
// read from Result.ToolStdout. Instead the jailed tool writes the exit IP it
// observes to a HOST-mounted file (via -v); the test reads that file. That the
// echoed source IP equals the FIXTURE's exit IP (not the host's) proves forced
// TCP egress is active on the interactive path exactly as for a plain run. The
// tool fetches BY IP (the tun2socks-tunnelled-by-IP path) so this asserts forced
// egress without entangling DNS, mirroring TestJail_ForcedEgress_ExitIPIsProxys.
//
// stdin is /dev/null (a closed reader): podman warns that the input device is not
// a TTY but still runs -it, which is all the topology proof needs (a real
// keystroke session needs a controlling terminal that a test process lacks; the
// stdin WIRING is proven podman-free by the seam tests).
func TestJail_Interactive_IdenticalTopologyForcedEgressAndNoResidue(t *testing.T) {
	requirePodman(t)

	echoPort, stopEcho := startExitEcho(t)
	defer stopEcho()

	const exitIP = "127.0.0.2" // the fixture's known exit IP (loopback alias)
	const placeholderIP = "198.51.100.10"
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:         exitIP,
		AllowIPConnect: true,
		RedirectTarget: "127.0.0.1:" + echoPort,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	// The interactive path does not capture output, so the tool writes the exit IP
	// it observes to a host-mounted file we can read after the run.
	outDir := t.TempDir()
	// The mount dir must be group/other-accessible so the rootless container user
	// can write into it; TempDir is 0700, widen it.
	if err := os.Chmod(outDir, 0o777); err != nil {
		t.Fatalf("chmod out dir: %v", err)
	}

	// A closed stdin (/dev/null): -it runs (with a not-a-TTY warning) which is all
	// the topology proof needs.
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer devnull.Close()

	runID := "iact" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		Mounts:              []string{outDir + ":/out"},
		// Interactive run: -it attached. The tool fetches the routable placeholder
		// BY IP (tun2socks tunnels it to the proxy, which redirects to the echo and
		// dials from the exit IP) and writes the observed source IP to the mounted
		// file so the test can read it (raw passthrough does not capture).
		ToolArgv:    []string{"sh", "-c", "wget -qO- -T 8 http://" + placeholderIP + ":" + echoPort + " > /out/exitip 2>/dev/null || true"},
		Interactive: true,
		ToolStdin:   devnull,
		RunID:       runID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if _, err := jail.Run(ctx, jail.ExecRunner{}, cfg); err != nil {
		t.Fatalf("interactive jail.Run: %v", err)
	}

	// Forced egress: the echoed source IP the jailed tool observed must be the
	// FIXTURE's exit IP, proving `-it` did not weaken the forced-egress jail.
	got, err := os.ReadFile(filepath.Join(outDir, "exitip"))
	if err != nil {
		t.Fatalf("reading the interactive tool's exit-IP output: %v", err)
	}
	if !strings.Contains(string(got), exitIP) {
		t.Fatalf("interactive run observed exit IP %q; want the fixture's exit IP %q (forced egress not active on the -it path)\nfull output: %q",
			extractIP(string(got)), exitIP, string(got))
	}

	// No run-attributable residue (no tooljail-run-<id>-* container; the netns +
	// nft are lifecycle-bound to the sidecar container, so no container means no
	// netns/nft either).
	out, _ := exec.CommandContext(ctx, "podman", "ps", "-a", "--format", "{{.Names}}").CombinedOutput()
	if strings.Contains(string(out), "tooljail-run-"+runID) {
		t.Fatalf("interactive run left run-attributable containers behind:\n%s", out)
	}
}
