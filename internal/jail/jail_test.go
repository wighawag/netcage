package jail

import (
	"strings"
	"testing"

	"github.com/wighawag/tooljail/internal/cli"
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
		"tooljail-run-abc123-sidecar",
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
		"--network container:tooljail-run-abc123-sidecar",
		"-v /host/out:/out", "-v /host/words:/words:ro",
		"nuclei -u https://target",
		"--rm",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("tool args missing %q\ngot: %s", want, args)
		}
	}
}

func TestNftRuleset_DropsUDPExceptLocalDNSAndNarrowsReachback(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = true
	rs := c.nftRuleset("9050")
	for _, want := range []string{
		"udp dport 53 ip daddr 127.0.0.0/8 accept",                  // tool -> local forwarder allowed
		"meta l4proto udp drop",                                     // all other UDP dropped (ADR-0003)
		"ip daddr " + mappedHostLoopback + " tcp dport 9050 accept", // exactly the proxy port
		"ip daddr " + mappedHostLoopback + " drop",                  // nothing else on the host
	} {
		if !strings.Contains(rs, want) {
			t.Fatalf("nft ruleset missing %q\ngot:\n%s", want, rs)
		}
	}
}

func TestNftRuleset_RemoteProxyHasNoReachbackNarrowing(t *testing.T) {
	c := cfg()
	c.ProxyOnHostLoopback = false
	rs := c.nftRuleset("1080")
	if strings.Contains(rs, mappedHostLoopback) {
		t.Fatalf("remote proxy ruleset must not reference the host-loopback map addr\ngot:\n%s", rs)
	}
	// UDP still hard-dropped.
	if !strings.Contains(rs, "meta l4proto udp drop") {
		t.Fatalf("UDP must still be dropped for a remote proxy\ngot:\n%s", rs)
	}
}
