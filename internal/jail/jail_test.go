package jail

import (
	"strings"
	"testing"

	"github.com/wighawag/netcage/internal/cli"
)

func cfg() Config {
	return Config{
		Proxy:    cli.ProxyConfig{Host: "127.0.0.1", Port: "9050"},
		Image:    "nuclei",
		ToolArgv: []string{"nuclei", "-u", "https://target"},
		RunID:    "abc123",
	}
}

func TestSidecarProxyURL_TranslatesSocks5hToSocks5(t *testing.T) {
	c := cfg()
	got := c.sidecarProxyURL()
	if strings.HasPrefix(got, "socks5h://") {
		t.Fatalf("sidecar proxy URL %q still uses socks5h; tun2socks rejects it, must be socks5://", got)
	}
	if !strings.HasPrefix(got, "socks5://") {
		t.Fatalf("sidecar proxy URL %q is not socks5://", got)
	}
}

func TestSidecarProxyURL_HostLoopbackUsesMappedAddr(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	got := c.sidecarProxyURL()
	if !strings.Contains(got, mappedHostLoopback) {
		t.Fatalf("host-loopback proxy URL %q must use the pasta-mapped addr %s", got, mappedHostLoopback)
	}
}

func TestSidecarProxyURL_RemoteProxyKeepsHostAndAuth(t *testing.T) {
	c := cfg()
	c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080", Username: "u", Password: "p"}
	got := c.sidecarProxyURL()
	if !strings.Contains(got, "bastion.example:1080") {
		t.Fatalf("remote proxy URL %q lost host:port", got)
	}
	if !strings.Contains(got, "u:p@") {
		t.Fatalf("remote proxy URL %q lost user:pass auth", got)
	}
}

func TestSidecarRunArgs_ForcedEgressShape(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	args := strings.Join(c.SidecarRunArgs(), " ")
	for _, want := range []string{
		"--cap-add NET_ADMIN", "--device /dev/net/tun",
		"--network pasta:--map-host-loopback," + mappedHostLoopback,
		"PROXY=socks5://" + mappedHostLoopback + ":9050",
		"netcage-run-abc123-sidecar",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("sidecar args missing %q\ngot: %s", want, args)
		}
	}
	// Must consume the pinned redirector digest, never a mutable tag.
	if !strings.Contains(args, "@sha256:") {
		t.Fatalf("sidecar must run the digest-pinned redirector; got: %s", args)
	}
}

// TestSidecarRunArgs_CloneMainOffAndExcludesProxyRoute pins the two sidecar-env
// settings the forced-egress spike proved are load-bearing
// (work/notes/findings/spike-jail-forced-egress-clone-main-and-excluded-route.md):
//
//   - CLONE_MAIN=0 so the TUN routing table is exactly `default dev tun0` and
//     does NOT clone the pasta-copied real-NIC routes (which caused a routing
//     loop / packet storm).
//   - TUN_EXCLUDED_ROUTES=<proxy-reachback-addr>/32 so tun2socks's own dialer
//     reaches the proxy over the real NIC (the pasta map) instead of looping
//     back through the TUN (which pasta reset). For a host-loopback proxy the
//     excluded address is the pasta map; for a remote proxy it is the remote
//     host so the bastion is reached over the real outbound.
func TestSidecarRunArgs_CloneMainOffAndExcludesProxyRoute(t *testing.T) {
	t.Run("host-loopback proxy excludes the pasta map address", func(t *testing.T) {
		c := cfg()
		c.ProxyOnHostLoopback = true
		args := strings.Join(c.SidecarRunArgs(), " ")
		if !strings.Contains(args, "CLONE_MAIN=0") {
			t.Fatalf("sidecar must set CLONE_MAIN=0 (else the TUN table clones the real NIC and storms); got: %s", args)
		}
		if !strings.Contains(args, "TUN_EXCLUDED_ROUTES="+mappedHostLoopback+"/32") {
			t.Fatalf("host-loopback sidecar must exclude the pasta map %s/32 from the TUN; got: %s", mappedHostLoopback, args)
		}
	})
	t.Run("remote proxy excludes the remote host address", func(t *testing.T) {
		c := cfg()
		c.Proxy = cli.ProxyConfig{Host: "203.0.113.9", Port: "1080"}
		c.ProxyOnHostLoopback = false
		args := strings.Join(c.SidecarRunArgs(), " ")
		if !strings.Contains(args, "CLONE_MAIN=0") {
			t.Fatalf("remote sidecar must set CLONE_MAIN=0; got: %s", args)
		}
		if !strings.Contains(args, "TUN_EXCLUDED_ROUTES=203.0.113.9/32") {
			t.Fatalf("remote sidecar must exclude the bastion 203.0.113.9/32 from the TUN; got: %s", args)
		}
		if strings.Contains(args, mappedHostLoopback) {
			t.Fatalf("remote sidecar must not reference the host-loopback map addr; got: %s", args)
		}
	})
}

func TestSidecarRunArgs_RemoteProxyNoHostLoopbackMap(t *testing.T) {
	c := cfg()
	c.Proxy = cli.ProxyConfig{Host: "bastion.example", Port: "1080"}
	c.ProxyOnHostLoopback = false
	args := strings.Join(c.SidecarRunArgs(), " ")
	if strings.Contains(args, "map-host-loopback") {
		t.Fatalf("remote proxy must NOT use --map-host-loopback; got: %s", args)
	}
}

func TestToolRunArgs_SharesNetnsAndPassesThrough(t *testing.T) {
	c := cfg()
	c.Mounts = []string{"/host/out:/out", "/host/words:/words:ro"}
	args := strings.Join(c.ToolRunArgs(), " ")
	for _, want := range []string{
		"--network container:netcage-run-abc123-sidecar",
		"-v /host/out:/out", "-v /host/words:/words:ro",
		"nuclei -u https://target",
		"--rm",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("tool args missing %q\ngot: %s", want, args)
		}
	}
}

func TestToolRunArgs_SetsWorkdirWhenGiven(t *testing.T) {
	c := cfg()
	c.Mounts = []string{"/host/repo:/work"}
	c.Workdir = "/work"
	args := strings.Join(c.ToolRunArgs(), " ")
	if !strings.Contains(args, "-w /work") {
		t.Fatalf("tool args should set the container workdir with -w /work (repo-mount ergonomic)\ngot: %s", args)
	}
}

func TestToolRunArgs_OmitsWorkdirWhenEmpty(t *testing.T) {
	c := cfg()
	c.Workdir = ""
	args := strings.Join(c.ToolRunArgs(), " ")
	if strings.Contains(args, " -w ") {
		t.Fatalf("tool args must NOT set -w when no workdir is given (leave the image's own workdir)\ngot: %s", args)
	}
}

// The firewall is applied INSIDE the sidecar via `podman exec` (ADR-0006), so
// the ruleset is an iptables/ip6tables shell script (the pinned redirector image
// ships iptables, not nft), not an nft ruleset piped through host nsenter.
func TestFirewallScript_DropsUDPExceptLocalDNSAndNarrowsReachback(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	rs := c.firewallScript("9050")
	for _, want := range []string{
		"iptables -A OUTPUT -p udp -d 127.0.0.0/8 -j ACCEPT",                             // tool<->forwarder loopback DNS (query + reply)
		"iptables -A OUTPUT -p udp -j DROP",                                              // all other IPv4 UDP dropped (ADR-0003)
		"ip6tables -A OUTPUT -p udp -j DROP",                                             // ... and IPv6 UDP (the nft `inet` table covered both)
		"iptables -A OUTPUT -p tcp -d " + mappedHostLoopback + " --dport 9050 -j ACCEPT", // exactly the proxy port
		"iptables -A OUTPUT -d " + mappedHostLoopback + " -j DROP",                       // nothing else on the host
	} {
		if !strings.Contains(rs, want) {
			t.Fatalf("firewall script missing %q\ngot:\n%s", want, rs)
		}
	}
	// The reachback accept must precede the reachback drop (else the proxy port
	// itself is dropped and the jail fails closed against its own proxy).
	accept := strings.Index(rs, "--dport 9050 -j ACCEPT")
	drop := strings.Index(rs, "iptables -A OUTPUT -d "+mappedHostLoopback+" -j DROP")
	if accept < 0 || drop < 0 || accept > drop {
		t.Fatalf("reachback accept must precede the reachback drop\ngot:\n%s", rs)
	}
	// The script must fail loudly if any rule fails to apply (a silently
	// half-applied firewall is a leak).
	if !strings.HasPrefix(rs, "set -e\n") {
		t.Fatalf("firewall script must start with `set -e` so a failed rule aborts the run\ngot:\n%s", rs)
	}
}

func TestFirewallScript_RemoteProxyHasNoReachbackNarrowing(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = false
	rs := c.firewallScript("1080")
	if strings.Contains(rs, mappedHostLoopback) {
		t.Fatalf("remote proxy ruleset must not reference the host-loopback map addr\ngot:\n%s", rs)
	}
	// UDP still hard-dropped (both families).
	for _, want := range []string{"iptables -A OUTPUT -p udp -j DROP", "ip6tables -A OUTPUT -p udp -j DROP"} {
		if !strings.Contains(rs, want) {
			t.Fatalf("UDP must still be dropped for a remote proxy (missing %q)\ngot:\n%s", want, rs)
		}
	}
}

// TestSidecarRunArgs_MountsDNSHelper: when Run has resolved the netcage-dns
// helper's host path, the sidecar args mount it read-only at the in-container
// path the jail execs it from (ADR-0006: the forwarder runs INSIDE the sidecar
// via podman exec, not on the host via nsenter).
func TestSidecarRunArgs_MountsDNSHelper(t *testing.T) {
	c := cfg()
	c.dnsHelperPath = "/opt/bin/netcage-dns"
	args := strings.Join(c.SidecarRunArgs(), " ")
	want := "-v /opt/bin/netcage-dns:" + sidecarDNSHelperPath + ":ro"
	if !strings.Contains(args, want) {
		t.Fatalf("sidecar args missing the DNS-helper mount %q\ngot: %s", want, args)
	}
}
