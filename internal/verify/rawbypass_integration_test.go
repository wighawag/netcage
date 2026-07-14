//go:build integration
// +build integration

package verify_test

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/socks5hfixture"
)

// TestVerify_RawPodmanStartBypassIsFailClosed is the raw-bypass leak assertion
// (spec stories 3 + 8, ADR-0008): a netcage tool container left behind and then
// started by a RAW `podman start` OUTSIDE netcage (podman auto-revives its
// stopped sidecar as a `--network container:` dependency) must be FAIL-CLOSED -
// a LAN/RFC1918 probe is DROPPED and a DNS lookup does NOT resolve - while
// public TCP by-IP still exits via the proxy. This is the leak the finding
// proved a runtime-`podman exec` firewall left open (it was lost on the revive);
// with the firewall baked into the sidecar's create-time EXTRA_COMMANDS it
// re-applies on every (re)start, closing it.
//
// The pair is created OUTSIDE jail.Run (a raw `podman start` does NOT run Run's
// deferred Teardown), using jail.Config.SidecarRunArgs() so the sidecar carries
// the exact baked EXTRA_COMMANDS firewall this task produces, and the tool is
// joined WITHOUT --rm so it survives its own exit. Shared-write isolation
// (podman is host-global): a unique run-id names the pair and t.Cleanup does
// `podman rm -f --depend` of the sidecar (which cascades to the tool) even on
// failure, and the test asserts no netcage-run-* residue for its id remains.
func TestVerify_RawPodmanStartBypassIsFailClosed(t *testing.T) {
	requirePodman(t)

	// The proxy + the stand-in "public" echo: a CONNECT to any IP is redirected
	// to a host echo, dialed from the fixture's known exit IP, so a by-IP TCP
	// fetch through the jail exits via the proxy (public egress stays proxied on
	// the bypass, which is not a leak).
	echoPort, stopEcho := startHTTPExitEcho(t)
	defer stopEcho()
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

	// A stand-in LAN/RFC1918 host service: a host-loopback TCP echo reached through
	// the jail at the pasta-mapped link-local address mappedHostLoopback on a port
	// that is NOT the proxy port. The baked firewall drops ALL TCP to
	// mappedHostLoopback except the proxy dport, so this probe must be DROPPED. It
	// is the one LAN-host address a jail netns can reach deterministically without
	// a real LAN peer (the same stand-in the split-tunnel verify cases use).
	lanPort, stopLAN := startHTTPExitEcho(t)
	defer stopLAN()
	if lanPort == proxyPort {
		t.Skipf("LAN echo port collided with the proxy port %s; rerun", proxyPort)
	}

	id := runID("vrawbypass")
	sidecarName := "netcage-run-" + id + "-sidecar"
	toolName := "netcage-run-" + id + "-tool"

	// Cleanup FIRST (registered before creation) so a failure anywhere below still
	// removes the pair. `rm -f --depend` of the sidecar cascades to the tool (the
	// `--network container:` dependent), the only way to drop the sidecar.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "podman", podmanTestArgs("rm", "-f", "--depend", sidecarName)...).Run()
		// Belt-and-braces: remove the tool by name too in case --depend did not.
		_ = exec.CommandContext(ctx, "podman", podmanTestArgs("rm", "-f", "-i", toolName)...).Run()
		if left := rawResidueFor(t, id); len(left) != 0 {
			t.Errorf("raw-bypass test left netcage-run-%s residue on the host: %v", id, left)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Build the sidecar args exactly as netcage would (the baked EXTRA_COMMANDS
	// firewall is what this task delivers), but run them RAW (outside jail.Run).
	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		RunID:               id,
	}
	if _, err := runPodmanRaw(ctx, cfg.SidecarRunArgs()...); err != nil {
		t.Fatalf("create sidecar (raw): %v", err)
	}

	// Create the tool joined to the sidecar netns, WITHOUT --rm so it survives
	// exit and can be raw-started later. It just sleeps; the probes below run as
	// throwaway containers sharing the same netns.
	if _, err := runPodmanRaw(ctx,
		"create", "--name", toolName,
		"--network", "container:"+sidecarName,
		"docker.io/library/alpine:latest", "sleep", "600"); err != nil {
		t.Fatalf("create tool (raw): %v", err)
	}

	// STOP the sidecar so the next `podman start` of the tool must AUTO-REVIVE it
	// (the exact bypass shape: a leftover tool started outside netcage).
	if _, err := runPodmanRaw(ctx, "stop", "-t", "1", sidecarName); err != nil {
		t.Fatalf("stop sidecar (raw): %v", err)
	}

	// The RAW bypass: `podman start <tool>` auto-revives the stopped sidecar and
	// re-runs its EXTRA_COMMANDS (the firewall self-heals). No netcage in the loop.
	if _, err := runPodmanRaw(ctx, "start", toolName); err != nil {
		t.Fatalf("raw podman start of the leftover tool: %v", err)
	}
	// Give the entrypoint a moment to re-apply EXTRA_COMMANDS before probing.
	time.Sleep(1500 * time.Millisecond)

	// --- Assertion 1: the LAN/RFC1918 probe is DROPPED on the bypass. ---
	// A short-lived container in the shared netns tries to reach the LAN stand-in
	// (mappedHostLoopback:lanPort). It must NOT connect (the firewall drops it).
	lanOut := probeInNetns(ctx, t, sidecarName,
		"nc -z -w 4 "+mappedHostLoopback+" "+lanPort+" && echo LAN-REACHED || echo LAN-DROPPED")
	if strings.Contains(lanOut, "LAN-REACHED") {
		t.Fatalf("raw-bypass LEAK: the LAN host %s:%s was REACHABLE after a raw podman start; the baked firewall did not drop it\noutput: %q",
			mappedHostLoopback, lanPort, lanOut)
	}
	if !strings.Contains(lanOut, "LAN-DROPPED") {
		t.Fatalf("LAN probe produced no verdict (infra problem?); output: %q", lanOut)
	}

	// --- Assertion 2: DNS does NOT resolve on the bypass. ---
	// The DNS forwarder is a SEPARATE podman-exec process (NOT part of
	// EXTRA_COMMANDS), so a raw bypass leaves it dead: names must not resolve
	// (fail-closed). Resolve a public name; it must fail (all egress UDP is
	// dropped and no forwarder is listening).
	dnsOut := probeInNetns(ctx, t, sidecarName,
		"nslookup -timeout=3 example.com 2>&1; echo DNS-DONE")
	if dnsResolved(dnsOut) {
		t.Fatalf("raw-bypass LEAK: DNS RESOLVED on the bypass; names must be dead (fail-closed) with no forwarder\noutput: %q", dnsOut)
	}

	// --- Assertion 3: public TCP by-IP still exits via the proxy. ---
	// Fetch a routable placeholder BY IP; tun2socks tunnels it to the proxy, which
	// redirects to the echo and dials from the exit IP. The echo returns the
	// observed source IP, which must be the proxy's exit IP (public egress stays
	// proxied even on the bypass; that is not a leak).
	pubOut := probeInNetns(ctx, t, sidecarName,
		"wget -qO- -T 8 http://"+placeholder+":"+echoPort+"/ 2>&1 || true")
	if !strings.Contains(pubOut, exitIP) {
		t.Fatalf("public by-IP TCP did not exit via the proxy on the bypass (want exit IP %s); output: %q", exitIP, pubOut)
	}

	// --- Assertion 4: rules do NOT accumulate across repeated restarts. ---
	// The netns is fresh each start, so EXTRA_COMMANDS applies to a clean table;
	// the OUTPUT chain rule count must be identical after N restart cycles.
	baseline := outputRuleCount(ctx, t, sidecarName)
	if baseline == 0 {
		t.Fatalf("baseline OUTPUT rule count is 0 (firewall not applied?)")
	}
	for i := 0; i < 3; i++ {
		if _, err := runPodmanRaw(ctx, "restart", "-t", "1", sidecarName); err != nil {
			t.Fatalf("restart cycle %d: %v", i, err)
		}
		time.Sleep(1200 * time.Millisecond)
		if got := outputRuleCount(ctx, t, sidecarName); got != baseline {
			t.Fatalf("firewall rules ACCUMULATED across restart cycle %d: baseline %d, now %d (the netns should be fresh each start)", i, baseline, got)
		}
	}
}

// runPodmanRaw runs a raw podman command (outside jail.Run) and returns its
// combined output, failing the test's error path via the returned error.
func runPodmanRaw(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "podman", podmanTestArgs(args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// probeInNetns runs a throwaway --rm alpine container sharing the sidecar's netns
// and returns the combined output of the shell command. Probe-infra errors are
// folded into the output string (the caller asserts on markers, not exit codes).
func probeInNetns(ctx context.Context, t *testing.T, sidecarName, sh string) string {
	t.Helper()
	out, _ := exec.CommandContext(ctx, "podman", podmanTestArgs("run", "--rm",
		"--network", "container:"+sidecarName,
		"docker.io/library/alpine:latest", "sh", "-c", sh)...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// outputRuleCount returns the number of `-A OUTPUT` rules in the sidecar's netns
// (via `podman exec ... iptables -S OUTPUT`), used to assert rules do not
// accumulate across restarts.
func outputRuleCount(ctx context.Context, t *testing.T, sidecarName string) int {
	t.Helper()
	out, err := exec.CommandContext(ctx, "podman", podmanTestArgs("exec", sidecarName,
		"iptables", "-S", "OUTPUT")...).CombinedOutput()
	if err != nil {
		t.Fatalf("iptables -S OUTPUT in sidecar: %v\n%s", err, out)
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-A OUTPUT") {
			n++
		}
	}
	return n
}

// dnsResolved reports whether nslookup output shows a successful public
// resolution (an Address line for a non-loopback answer). A dead forwarder /
// dropped UDP yields a timeout or failure, so this is false.
func dnsResolved(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		// Skip the server/self lines; a real answer is an "Address:" line that is
		// not the 127.0.0.1 resolver itself.
		if strings.HasPrefix(l, "Address:") || strings.HasPrefix(l, "Address ") {
			val := strings.TrimSpace(strings.SplitN(l, ":", 2)[len(strings.SplitN(l, ":", 2))-1])
			if ip := net.ParseIP(strings.Fields(val)[0]); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				return true
			}
		}
	}
	return false
}

// rawResidueFor returns any netcage-run-<id>-* containers still on the host, so
// the test can assert its raw-created pair left nothing behind.
func rawResidueFor(t *testing.T, id string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "podman", podmanTestArgs("ps", "-a", "--format", "{{.Names}}")...).CombinedOutput()
	var left []string
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name != "" && strings.Contains(name, "netcage-run-"+id) {
			left = append(left, name)
		}
	}
	return left
}
