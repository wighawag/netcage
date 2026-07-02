// Package dnsforwarder is netcage's DNS-to-SOCKS-TCP bridge: the leak-proof DNS
// seam (see work/notes/findings/dns-through-socks-is-tcp-not-udp.md and
// spike-dns-to-socks-bridge). DNS through a SOCKS proxy is a CLIENT-SIDE UDP->TCP
// conversion, never a UDP datagram to the proxy (Tor/Mullvad accept no UDP). So
// the forwarder accepts the tool's ordinary DNS query, resolves it via the
// SOCKS proxy over TCP (DNS-over-TCP through a CONNECT to an upstream resolver
// addressed by hostname, i.e. resolved proxy-side), and answers the tool. The
// query never leaves the jail; the host resolver never sees the name; if the
// proxy is down the query is dropped (fail-closed, no host fallback).
//
// It serves on BOTH UDP and TCP at the listen address. TCP is load-bearing:
// resolv.conf carries `options use-vc` (force TCP, since egress UDP is dropped),
// and glibc's getaddrinfo honours it by querying over TCP (RFC 7766). A UDP-only
// forwarder answers musl (alpine) but leaves glibc images (node/debian/
// buildpack-deps) with EAI_AGAIN, so both listeners are required.
package dnsforwarder

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

// Config configures a Forwarder.
type Config struct {
	// Listen is the UDP address to serve DNS on (the tool's resolv.conf points
	// here), e.g. "127.0.0.1:53".
	Listen string
	// ProxyAddr is the SOCKS5 proxy host:port the queries are tunnelled through.
	ProxyAddr string
	// ProxyAuth is optional SOCKS5 user/pass.
	ProxyAuth *proxy.Auth
	// Upstream is the DNS resolver addressed BY HOSTNAME so the proxy resolves it
	// (socks5h), reached as DNS-over-TCP. Defaults to a public resolver name.
	Upstream string
}

// Forwarder is a running DNS-to-SOCKS-TCP bridge, serving UDP and TCP.
type Forwarder struct {
	cfg    Config
	pc     net.PacketConn
	ln     net.Listener
	dialer proxy.Dialer
}

// Start binds the UDP and TCP listeners and serves in the background until ctx
// is done. Both are required: UDP for musl clients, TCP for glibc clients that
// honour resolv.conf's `use-vc` (see the package doc).
func Start(ctx context.Context, cfg Config) (*Forwarder, error) {
	if cfg.Upstream == "" {
		cfg.Upstream = "1.1.1.1:53" // addressed as-is; for a hostname the proxy resolves it
	}
	dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, cfg.ProxyAuth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("dns forwarder: build SOCKS5 dialer: %w", err)
	}
	pc, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("dns forwarder: listen udp %s: %w", cfg.Listen, err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("dns forwarder: listen tcp %s: %w", cfg.Listen, err)
	}
	f := &Forwarder{cfg: cfg, pc: pc, ln: ln, dialer: dialer}
	go f.serveUDP(ctx)
	go f.serveTCP(ctx)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
		_ = ln.Close()
	}()
	return f, nil
}

// Addr returns the bound UDP address.
func (f *Forwarder) Addr() string { return f.pc.LocalAddr().String() }

// TCPAddr returns the bound TCP address.
func (f *Forwarder) TCPAddr() string { return f.ln.Addr().String() }

// Close stops the forwarder.
func (f *Forwarder) Close() error {
	err := f.pc.Close()
	if e := f.ln.Close(); e != nil && err == nil {
		err = e
	}
	return err
}

func (f *Forwarder) serveUDP(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := f.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func() {
			resp, err := f.resolveViaSOCKS(query)
			if err != nil {
				return // fail-closed: drop, never fall back to a host resolver
			}
			_, _ = f.pc.WriteTo(resp, addr)
		}()
	}
}

// serveTCP accepts DNS-over-TCP connections (RFC 7766), each carrying one or
// more 2-byte-length-prefixed queries. Required for glibc `use-vc` clients.
func (f *Forwarder) serveTCP(ctx context.Context) {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handleTCPConn(conn)
	}
}

func (f *Forwarder) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	for {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return // EOF or timeout: done with this connection
		}
		query := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp, err := f.resolveViaSOCKS(query)
		if err != nil {
			return // fail-closed: drop, never fall back
		}
		framed := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(resp)))
		copy(framed[2:], resp)
		if _, err := conn.Write(framed); err != nil {
			return
		}
	}
}

// resolveViaSOCKS forwards a DNS message to the upstream resolver over a SOCKS5
// TCP connection using DNS-over-TCP framing (RFC 1035 2-byte length prefix).
func (f *Forwarder) resolveViaSOCKS(query []byte) ([]byte, error) {
	conn, err := f.dialer.Dial("tcp", f.cfg.Upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
