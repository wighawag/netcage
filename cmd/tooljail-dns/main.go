// Command tooljail-dns is the in-netns DNS-to-SOCKS-TCP forwarder helper. The
// jail launches it INSIDE the shared netns via nsenter so the wrapped tool's
// resolv.conf (127.0.0.1:53) resolves names proxy-side over TCP, never via the
// host resolver and never as egress UDP (ADR-0003). It dials the SOCKS proxy at
// the address it is given (the pasta-mapped host-loopback address for a local
// proxy, or the real host for a remote one).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"golang.org/x/net/proxy"

	"github.com/wighawag/tooljail/internal/dnsforwarder"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:53", "UDP address to serve DNS on (inside the netns)")
	proxyAddr := flag.String("proxy", "", "SOCKS5 proxy host:port (reachable from this netns)")
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream DNS resolver (DNS-over-TCP via the proxy)")
	user := flag.String("user", "", "optional SOCKS5 username")
	pass := flag.String("pass", "", "optional SOCKS5 password")
	flag.Parse()

	if *proxyAddr == "" {
		fmt.Fprintln(os.Stderr, "tooljail-dns: -proxy is required")
		os.Exit(2)
	}
	var auth *proxy.Auth
	if *user != "" {
		auth = &proxy.Auth{User: *user, Password: *pass}
	}

	ctx := context.Background()
	if _, err := dnsforwarder.Start(ctx, dnsforwarder.Config{
		Listen:    *listen,
		ProxyAddr: *proxyAddr,
		ProxyAuth: auth,
		Upstream:  *upstream,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "tooljail-dns: %v\n", err)
		os.Exit(1)
	}
	select {} // serve until killed (the jail kills it at teardown)
}
