//go:build integration
// +build integration

package jail_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/netcage/internal/cli"
	"github.com/wighawag/netcage/internal/jail"
	"github.com/wighawag/netcage/internal/socks5hfixture"
)

const (
	startExitIP       = "127.0.0.2"           // the fixture's known exit IP (loopback alias)
	startPlaceholder  = "198.18.7.7"          // in-TUN-subnet target the jail's TUN captures
	startUniqueName   = "resume.netcage.test" // a name only the proxy-side resolver knows
	startAnswerIP     = "203.0.113.77"        // the proxy-side answer for startUniqueName
	startUpstreamName = "dns.resume.test"     // the DNS resolver name, resolved proxy-side
	startResolverIP   = "127.0.0.4"           // where the test DNS-over-TCP resolver binds
)

// sawHost reports whether the proxy was asked to resolve name (case-insensitive),
// proving DNS went proxy-side through the re-exec'd forwarder.
func sawHost(hosts []string, name string) bool {
	for _, h := range hosts {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	return false
}

// startResumeDNSOverTCP serves DNS-over-TCP on startResolverIP:<ephemeral>,
// answering ONLY startUniqueName, so the restarted jail's proxy-side resolution
// has a deterministic answer. Returns the chosen port.
func startResumeDNSOverTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", startResolverIP+":0")
	if err != nil {
		t.Fatalf("dns resolver listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				resp := buildResumeAResponse(msg, decodeResumeName(msg[12:]))
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = c.Write(out)
			}(c)
		}
	}()
	return port
}

func buildResumeAResponse(query []byte, name string) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2], resp[3] = 0x81, 0x80
	if !strings.EqualFold(name, startUniqueName) {
		resp[3] = 0x83 // NXDOMAIN for anything but the unique name
		return resp
	}
	resp[6], resp[7] = 0, 1
	ans := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	ans = append(ans, net.ParseIP(startAnswerIP).To4()...)
	return append(resp, ans...)
}

func decodeResumeName(b []byte) string {
	var parts []string
	for len(b) > 0 {
		n := int(b[0])
		if n == 0 || 1+n > len(b) {
			break
		}
		parts = append(parts, string(b[1:1+n]))
		b = b[1+n:]
	}
	return strings.Join(parts, ".")
}

// forceRemoveStartPair removes a kept tool+sidecar pair even on failure. `rm -f
// --depend` of the sidecar cascades to its `--network container:` dependent tool
// (the only way to drop the sidecar), so the test cleans up after ITSELF: the run
// -> start cycle DELIBERATELY keeps the pair across the cycle (that is the feature
// under test), so the test MUST rm it even on failure, or a failing test orphans
// containers on the host (podman is host-global) or collides with a concurrent
// run.
func forceRemoveStartPair(runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "podman", podmanTestArgs("rm", "-f", "--depend", "netcage-run-"+runID+"-sidecar")...).Run()
	_ = exec.CommandContext(ctx, "podman", podmanTestArgs("rm", "-f", "-i", "netcage-run-"+runID+"-tool")...).Run()
	// Sweep the durable resolv.conf too, so this test (which deliberately keeps a
	// pair) cleans fully after itself and leaves no $TMPDIR orphan.
	jail.RemoveResolvConf(runID)
}

// TestJail_Start_RunThenStart_StateIntactAndLeakTight is the podman-gated proof
// of the jail-aware `netcage start` resume cycle (covers=[7,9]):
//
//  1. A KEPT `netcage run` writes a STATE MARKER into the tool container's
//     filesystem (container-internal, not a mount, so it proves CONTAINER state
//     persists) and leaves the stopped tool + sidecar behind.
//  2. `jail.Start` (DNS fixture) REVIVES the sidecar (the baked EXTRA_COMMANDS
//     firewall re-applies + is VERIFIED), re-execs the DNS forwarder, and re-enters
//     the tool with its state INTACT AND a name resolving PROXY-SIDE (the re-exec'd
//     forwarder resolves startUniqueName to the proxy-side answer, and the proxy
//     RECORDS the upstream lookup) plus egress UDP to a LAN host DROPPED.
//  3. A second `jail.Start` (exit-IP fixture on the SAME proxy port, so reconcile
//     REVIVES not refuses) proves forced TCP egress: a public fetch BY IP exits
//     from the PROXY's IP, not the host's.
//  4. A third `jail.Start` with the proxy KILLED proves the revived jail is
//     fail-closed on proxy-kill (survives revive): a public fetch does NOT egress.
//
// The exit-IP proof needs a by-IP RedirectTarget fixture and the DNS proof needs a
// clean DNS-over-TCP resolver; RedirectTarget would hijack the resolver dial, so
// they are separate PHASES. All phases bind the SAME proxy PORT so the container's
// baked jail config is unchanged and every start REVIVES (the reconcile compares
// the baked proxy socks5://169.254.1.1:<port>).
//
// Shared-write isolation (podman is host-global state): the cycle deliberately
// keeps the pair, so a unique run-id names it AND t.Cleanup does `podman rm -f
// --depend` of the pair even on failure.
func TestJail_Start_RunThenStart_StateIntactAndLeakTight(t *testing.T) {
	requirePodman(t)

	echoPort, stopEcho := startExitEcho(t)
	defer stopEcho()
	resolverPort := startResumeDNSOverTCP(t)

	// A single fixed proxy port shared across all phases (bind ephemeral once, then
	// re-bind the same port for each phase) so every `netcage start` sees the SAME
	// baked jail config and REVIVES rather than refusing on a changed proxy.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve proxy port: %v", err)
	}
	proxyPort := strconv.Itoa(pl.Addr().(*net.TCPAddr).Port)
	pl.Close()
	proxyAddr := "127.0.0.1:" + proxyPort
	proxyCfg := cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort}

	const stateFile = "/root/netcage-state" // container-internal (persists iff kept)
	const marker = "NETCAGE-STATE-OK"

	lanHost := "192.168.255.254"
	if gw := defaultGateway(t); gw != "" && net.ParseIP(gw) != nil && isPrivateOrLinkLocal(net.ParseIP(gw)) {
		lanHost = siblingOnSameRange(gw)
	}

	runID := "start" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	t.Cleanup(func() { forceRemoveStartPair(runID) })

	// The container COMMAND is fixed at CREATE (phase 1) and re-runs VERBATIM on
	// every `podman start` (a start cannot change it), so ONE baked script prints
	// ALL labels and each phase asserts only the ones its fixture serves:
	//   STATE:new|intact  - container filesystem persisted the prior marker
	//   DNS:<ip|fail>     - startUniqueName resolves proxy-side (DNS fixture phase)
	//   UDP:<dropped>     - egress UDP to a LAN host is dropped (any phase)
	//   EXIT:<ip|none>    - public fetch BY IP exits from the proxy IP (exit-IP phase)
	script := strings.Join([]string{
		"if [ -f " + stateFile + " ]; then STATE=intact; else STATE=new; fi",
		"echo " + marker + " >> " + stateFile,
		"echo STATE:$STATE",
		"if [ \"$STATE\" = intact ]; then",
		"  if nslookup " + startUniqueName + " 2>/dev/null | grep -qF " + startAnswerIP + "; then echo DNS:" + startAnswerIP + "; else echo DNS:fail; fi",
		"  if nslookup -type=A -timeout=3 example.com " + lanHost + " >/dev/null 2>&1; then echo UDP:reached; else echo UDP:dropped; fi",
		"  echo EXIT:$(wget -qO- -T 8 http://" + startPlaceholder + ":" + echoPort + " 2>/dev/null || echo none)",
		"fi",
	}, "\n")
	toolArgv := []string{"sh", "-c", script}

	baseCfg := func() jail.Config {
		return jail.Config{
			Proxy:               proxyCfg,
			ProxyOnHostLoopback: true,
			Image:               "docker.io/library/alpine:latest",
			ToolArgv:            toolArgv,
			RunID:               runID,
			DNSUpstream:         startUpstreamName + ":" + resolverPort,
			Ephemeral:           false,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// --- Phase 1: KEPT run (DNS fixture) seeds the state marker and leaves the pair. ---
	dnsFx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:     startExitIP,
		KnownHosts: map[string]string{startUpstreamName: startResolverIP},
	})
	if err := dnsFx.Start(proxyAddr); err != nil {
		t.Fatalf("dns fixture start: %v", err)
	}
	res, err := jail.Run(ctx, jail.ExecRunner{}, baseCfg())
	if err != nil {
		dnsFx.Close()
		t.Fatalf("phase 1 kept run: %v\nstderr: %s", err, res.ToolStderr)
	}
	if !strings.Contains(res.ToolStdout, "STATE:new") {
		dnsFx.Close()
		t.Fatalf("phase 1 must seed the state marker (STATE:new); got:\n%s", res.ToolStdout)
	}
	if left := residueFor(t, runID); len(left) != 2 {
		dnsFx.Close()
		t.Fatalf("kept run must leave the tool + sidecar for start to revive; got %d: %v", len(left), left)
	}

	// --- Phase 2: netcage start REVIVES; state intact + DNS proxy-side + UDP drop. ---
	res, err = jail.Start(ctx, jail.ExecRunner{}, baseCfg(), "netcage-run-"+runID+"-tool")
	dnsFx.Close()
	if err != nil {
		t.Fatalf("phase 2 netcage start (revive): %v\nstderr: %s", err, res.ToolStderr)
	}
	out := res.ToolStdout
	if !strings.Contains(out, "STATE:intact") {
		t.Fatalf("start must re-enter the tool with its state INTACT (the prior marker present); got:\n%s", out)
	}
	if !strings.Contains(out, "DNS:"+startAnswerIP) {
		t.Fatalf("start must re-exec the DNS forwarder so %s resolves PROXY-SIDE to %s; got:\n%s", startUniqueName, startAnswerIP, out)
	}
	if !sawHost(dnsFx.ResolvedHosts(), startUpstreamName) {
		t.Fatalf("the proxy never resolved the upstream resolver %q proxy-side; DNS did not go through the re-exec'd forwarder (saw=%v)", startUpstreamName, dnsFx.ResolvedHosts())
	}
	if !strings.Contains(out, "UDP:dropped") {
		t.Fatalf("restarted jail must DROP egress UDP to a LAN/RFC1918 host (%s); the baked firewall must be re-applied + verified on start; got:\n%s", lanHost, out)
	}

	// --- Phase 3: netcage start (exit-IP fixture, SAME proxy port) proves forced
	// TCP egress: a public fetch BY IP exits from the proxy's IP. ---
	exitFx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:         startExitIP,
		AllowIPConnect: true,
		RedirectTarget: "127.0.0.1:" + echoPort,
	})
	if err := exitFx.Start(proxyAddr); err != nil {
		t.Fatalf("exit-IP fixture start: %v", err)
	}
	res, err = jail.Start(ctx, jail.ExecRunner{}, baseCfg(), "netcage-run-"+runID+"-tool")
	exitFx.Close()
	if err != nil {
		t.Fatalf("phase 3 netcage start (exit-IP revive): %v\nstderr: %s", err, res.ToolStderr)
	}
	if !strings.Contains(res.ToolStdout, startExitIP) {
		t.Fatalf("restarted jail must force public TCP egress through the proxy (exit IP %s); got:\n%s", startExitIP, res.ToolStdout)
	}

	// --- Phase 4: with the proxy KILLED (nothing bound on the port), a revived jail
	// is fail-closed on proxy-kill. A public fetch must NOT egress. ---
	res, err = jail.Start(ctx, jail.ExecRunner{}, baseCfg(), "netcage-run-"+runID+"-tool")
	if err == nil && strings.Contains(res.ToolStdout, startExitIP) {
		t.Fatalf("with the proxy KILLED the revived jail LEAKED (reached the echo at %s); it must be fail-closed on proxy-kill; got:\n%s", startExitIP, res.ToolStdout)
	}
}

// TestJail_Start_RefusesNonNetcageContainer is the podman-gated proof that
// `netcage start` refuses a container that is not netcage-managed (missing the
// netcage.managed label), so the verb can never revive an unrelated container.
func TestJail_Start_RefusesNonNetcageContainer(t *testing.T) {
	requirePodman(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	name := "netcage-start-unmanaged-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	if err := exec.CommandContext(ctx, "podman", podmanTestArgs("create", "--name", name, "docker.io/library/alpine:latest", "true")...).Run(); err != nil {
		t.Skipf("could not create the unmanaged fixture container: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("podman", podmanTestArgs("rm", "-f", "-i", name)...).Run() })

	cfg := jail.Config{
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
		ProxyOnHostLoopback: true,
	}
	if _, err := jail.Start(ctx, jail.ExecRunner{}, cfg, name); err == nil {
		t.Fatalf("netcage start of a non-netcage container %s must be refused", name)
	}
}
