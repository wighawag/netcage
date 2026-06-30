// Command dns-forwarder is the spike probe for spike-dns-to-socks-bridge.
//
// It proves the mechanism ADR-0003 assumes for DNS-through-the-proxy without any
// UDP path: a forwarder that accepts the tool's ordinary UDP DNS query, resolves
// it VIA THE SOCKS PROXY OVER TCP (DNS-over-TCP through a socks5 CONNECT), and
// answers the tool. UDP never leaves the jail; the host resolver never sees the
// name. This is what tor-resolve / Tor's DNSPort / dns2socks do, and what
// tun2socks (which has no DNS handling) does NOT.
//
// Flow per query:
//
//	tool --UDP--> forwarder(:53)
//	forwarder --SOCKS5 CONNECT <upstreamDNS:53> (proxy resolves it remotely)--> proxy
//	forwarder --DNS-over-TCP (2-byte length prefix)--> (tunnel) --> upstream resolver
//	forwarder <--answer-- ... <-- forwarder --UDP--> tool
//
// The upstream resolver is addressed BY HOSTNAME so the proxy does the
// resolution (socks5h), keeping even the resolver's own address off the host.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1053", "UDP address to serve DNS on")
	proxyAddr := flag.String("proxy", "", "SOCKS5 proxy host:port")
	upstream := flag.String("upstream", "dns.tooljail.test:53", "upstream DNS resolver, addressed by HOSTNAME so the proxy resolves it (socks5h)")
	flag.Parse()

	if *proxyAddr == "" {
		fmt.Fprintln(os.Stderr, "FORWARDER FAIL: -proxy is required")
		os.Exit(2)
	}

	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FORWARDER FAIL: listen %s: %v\n", *listen, err)
		os.Exit(1)
	}
	defer pc.Close()
	fmt.Printf("FORWARDER UP: udp %s -> socks5 %s -> dns-over-tcp %s\n", *listen, *proxyAddr, *upstream)
	os.Stdout.Sync()

	dialer, err := proxy.SOCKS5("tcp", *proxyAddr, nil, proxy.Direct)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FORWARDER FAIL: build SOCKS5 dialer: %v\n", err)
		os.Exit(1)
	}

	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func() {
			resp, err := resolveViaSOCKS(dialer, *upstream, query)
			if err != nil {
				return // drop on failure (fail-closed: no fallback to a host resolver)
			}
			_, _ = pc.WriteTo(resp, addr)
		}()
	}
}

// resolveViaSOCKS forwards a DNS message to the upstream resolver over a SOCKS5
// TCP connection, using DNS-over-TCP framing (2-byte big-endian length prefix).
func resolveViaSOCKS(dialer proxy.Dialer, upstream string, query []byte) ([]byte, error) {
	conn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Write the DNS query with a 2-byte length prefix (RFC 1035 TCP framing).
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	// Read the length-prefixed response.
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
