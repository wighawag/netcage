//go:build integration
// +build integration

package verify_test

import (
	"context"
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

// startHostLoopbackBanner stands up a TCP listener on the HOST's 127.0.0.1 that
// writes a fixed banner on connect, standing in for a same-host service bound to
// loopback only (e.g. a local model server). It returns the chosen port + a stop
// func. It is a genuine host-loopback service, reachable from the jailed tool
// ONLY via the pasta map (169.254.1.1:<port>) and ONLY if a host-loopback --allow
// names its port (ADR-0019).
func startHostLoopbackBanner(t *testing.T, banner string) (port string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("host-loopback banner listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, banner+"\n")
			}(c)
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p, func() { ln.Close() }
}

// TestVerify_HostLoopbackReachback_ExemptPortReachableRestClosed is the
// host-loopback coverage mirroring split-tunnel-tight (ADR-0019, task
// allow-host-loopback-reachback): with a host-loopback --allow ACTIVE for a same-
// host model port, verify PROVES, end to end against real podman, that
//
//   - the EXEMPTED host-loopback port IS reachable from the jailed tool (dialed at
//     the pasta map 169.254.1.1:<modelPort>, since the tool shares the sidecar
//     netns), AND
//   - the REST of host loopback stays UNREACHABLE: a DIFFERENT, non-named host-
//     loopback port is DROPPED at the map (the map's DROP closer holds), so the
//     exemption does not widen host loopback.
//
// A probe that cannot run FAILS LOUD (a jail-run error is a failure, never a
// silent pass, ADR-0003 discipline). The run leaves NO run-attributable residue.
//
// The proxy is on host loopback here (the deterministic, real-LAN-host-free
// setup the other verify cases use), so the map already exists for the proxy
// reachback; the host-loopback --allow adds the MODEL accept on the SAME shared
// map, and the non-named "other" port proves the closer still drops everything
// unnamed. The proxy/control ports cannot be named at all (the guardrail refuses
// them at parse), so they can never be accepted; the un-named-port DROP here is
// the same closer that keeps them shut.
func TestVerify_HostLoopbackReachback_ExemptPortReachableRestClosed(t *testing.T) {
	requirePodman(t)

	// The exempted same-host model (named in the allow) and a NON-named sibling
	// host-loopback service (must stay dropped): both are genuine host-loopback
	// listeners, distinguished only by whether the allow names their port.
	const modelBanner = "MODEL-REACHED"
	const otherBanner = "OTHER-REACHED"
	modelPort, stopModel := startHostLoopbackBanner(t, modelBanner)
	defer stopModel()
	otherPort, stopOther := startHostLoopbackBanner(t, otherBanner)
	defer stopOther()

	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: exitIP, AllowIPConnect: true})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()
	_, proxyPort, _ := net.SplitHostPort(fx.Addr())

	modelPortNum, _ := strconv.Atoi(modelPort)
	// The host-loopback --allow names the HOST's 127.0.0.1:<modelPort>; netcage
	// rewrites it to the map at rule-emit time. This is exactly the CLASS the CLI
	// would produce for `--allow 127.0.0.1:<modelPort>`.
	allow := []cli.DirectAllow{{
		Network:      &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)},
		Port:         modelPortNum,
		Raw:          "127.0.0.1:" + modelPort,
		HostLoopback: true,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// One jailed probe, two legs, dialed at the pasta map (the tool shares the
	// sidecar netns, so it reaches host loopback ONLY via 169.254.1.1):
	//   MODEL: connect to the exempted port -> must read modelBanner (reachable).
	//   OTHER: connect to the non-named sibling port -> must NOT read otherBanner
	//     (the map DROP closer drops it), printed as OTHER-DROPPED on no-answer.
	// nc -w bounds the connect; a dropped SYN gives no banner within the timeout.
	script := strings.Join([]string{
		"if nc -w 5 " + mappedHostLoopback + " " + modelPort + " </dev/null 2>/dev/null | grep -q " + modelBanner + "; then echo MODEL:reached; else echo MODEL:unreached; fi",
		"if nc -w 5 " + mappedHostLoopback + " " + otherPort + " </dev/null 2>/dev/null | grep -q " + otherBanner + "; then echo OTHER:reached; else echo OTHER:dropped; fi",
	}, "; ")

	cfg := jail.Config{
		Ephemeral:           true, // internal one-shot: remove-both, no residue
		Proxy:               cli.ProxyConfig{Host: "127.0.0.1", Port: proxyPort},
		ProxyOnHostLoopback: true,
		Image:               "docker.io/library/alpine:latest",
		ToolArgv:            []string{"sh", "-c", script},
		RunID:               runID("vhlb"),
		AllowDirect:         allow,
	}

	// Fail-loud: a jail-run error is a FAILURE (the probe could not run), never a
	// silent pass. This is the ADR-0003 discipline the split-tunnel probes use.
	res, err := jail.Run(ctx, jail.ExecRunner{}, cfg)
	if err != nil {
		t.Fatalf("host-loopback reachback probe: jail run failed (fail-loud, no verdict): %v\nstderr: %s", err, res.ToolStderr)
	}
	out := res.ToolStdout

	if !strings.Contains(out, "MODEL:reached") {
		t.Fatalf("the exempted host-loopback port %s was NOT reachable from the tool via the map %s (the model accept + map + excluded route not opening the reachback)\noutput:\n%s", modelPort, mappedHostLoopback, out)
	}
	if !strings.Contains(out, "OTHER:dropped") {
		t.Fatalf("a NON-named host-loopback port %s was reachable via the map: the exemption widened host loopback (the map DROP closer is missing/ineffective)\noutput:\n%s", otherPort, out)
	}

	// No run-attributable container may remain (no residue), and no OTHER jail is
	// touched: this test stands up exactly its own run id.
	psOut, _ := exec.CommandContext(ctx, "podman", podmanTestArgs("ps", "-a", "--format", "{{.Names}}")...).CombinedOutput()
	if strings.Contains(string(psOut), "netcage-run-"+cfg.RunID) {
		t.Fatalf("host-loopback reachback run left run-attributable residue:\n%s", psOut)
	}
}
