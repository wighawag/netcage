// Package socks5hfixture is a controllable, in-process SOCKS5h proxy used as the
// deterministic test harness for netcage's leak assertions. It is NOT a
// production proxy: it exists so tests can assert the three leak properties
// (exit IP is the proxy's, a unique hostname resolves proxy-side, proxy-killed
// fails closed) without depending on real Tor.
//
// "socks5h" means remote (proxy-side) name resolution: a client sends the proxy
// a HOSTNAME (SOCKS5 ATYP=domain), and the proxy resolves it. This fixture
// resolves hostnames from a caller-supplied table (Options.KnownHosts) and
// RECORDS every hostname it was asked to resolve (ResolvedHosts), so a test can
// prove a lookup arrived proxy-side and not at the host resolver.
//
// The fixture presents a known EXIT IP by dialing its outbound connections FROM
// a configured loopback source address (Options.ExitIP); the destination then
// observes the proxy's source, not the client's. On Linux the whole 127.0.0.0/8
// is loopback, so any 127.x address is bindable as a source for tests.
package socks5hfixture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Options configures a Fixture.
type Options struct {
	// ExitIP is the source address the proxy dials its outbound connections
	// from, i.e. the exit IP a destination observes. Must be a locally bindable
	// address (e.g. a 127.x loopback alias in tests).
	ExitIP string

	// KnownHosts is the proxy-side DNS view: hostname -> resolved IP. A CONNECT
	// to a hostname not in this table is refused (so tests control exactly what
	// the proxy can resolve).
	KnownHosts map[string]string

	// AllowIPConnect permits ATYP=ipv4/ipv6 CONNECTs (dialed from ExitIP). It
	// defaults to FALSE so the fixture rejects IP CONNECTs as a local-resolution
	// leak in unit tests. The jail's tun2socks path legitimately tunnels by IP
	// (it captured packets, not a resolver call), so the jail forced-egress-by-IP
	// integration test sets this true.
	AllowIPConnect bool

	// RedirectTarget, when set, makes every CONNECT (any host/IP/port) dial THIS
	// host:port instead, from ExitIP. It lets a test target a routable placeholder
	// IP (so the jail's TUN captures it) while the fixture connects to a real local
	// echo. The exit IP the destination observes is still ExitIP.
	RedirectTarget string
}

// Fixture is a controllable SOCKS5h proxy. The zero value is not usable; build
// one with New.
type Fixture struct {
	opts Options

	mu       sync.Mutex
	ln       net.Listener
	closed   bool
	resolved []string
}

// New builds a Fixture. Call Start to bind and serve.
func New(opts Options) *Fixture {
	return &Fixture{opts: opts}
}

// Start binds the proxy on bindAddr (e.g. "127.0.0.1:0" for an ephemeral port)
// and begins serving in the background. Use Addr to learn the bound address.
func (f *Fixture) Start(bindAddr string) error {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("socks5h fixture bind %s: %w", bindAddr, err)
	}
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()

	go f.serve(ln)
	return nil
}

// Addr returns the bound address ("host:port"), or "" if not started.
func (f *Fixture) Addr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln == nil {
		return ""
	}
	return f.ln.Addr().String()
}

// ResolvedHosts returns, in order, the hostnames the proxy was asked to resolve
// proxy-side. This is the observability hook the DNS-through-proxy assertion
// binds to.
func (f *Fixture) ResolvedHosts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.resolved))
	copy(out, f.resolved)
	return out
}

// Close stops the proxy (the kill switch): the listener closes and subsequent
// dials to it fail. Idempotent.
func (f *Fixture) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.ln != nil {
		return f.ln.Close()
	}
	return nil
}

func (f *Fixture) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go f.handle(c)
	}
}

func (f *Fixture) recordResolved(host string) {
	f.mu.Lock()
	f.resolved = append(f.resolved, host)
	f.mu.Unlock()
}

// SOCKS5 constants (RFC 1928).
const (
	socksVer   = 0x05
	cmdConnect = 0x01
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded         = 0x00
	repGeneralFailure    = 0x01
	repHostUnreachable   = 0x04
	repCommandNotSupport = 0x07
	repAtypNotSupported  = 0x08
)

func (f *Fixture) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	if err := f.handshake(c); err != nil {
		return
	}
	host, port, err := f.readConnectRequest(c)
	if err != nil {
		return
	}

	// socks5h: resolve the hostname PROXY-SIDE from the controlled view. An
	// IP-literal target (allowed only when AllowIPConnect is set, e.g. the jail's
	// tun2socks path) is dialed directly; it is not a resolver lookup, so it is
	// not recorded as a resolved host.
	var ip string
	if parsed := net.ParseIP(host); parsed != nil {
		ip = host // IP-literal CONNECT (AllowIPConnect path)
	} else {
		f.recordResolved(host)
		var ok bool
		ip, ok = f.opts.KnownHosts[host]
		if !ok {
			writeReply(c, repHostUnreachable)
			return
		}
	}

	// Dial out FROM the configured exit IP so the destination observes the
	// proxy's exit IP, not the client's. A RedirectTarget overrides the dial
	// destination (still from ExitIP), so a test can target a routable placeholder
	// IP (captured by the jail's TUN) while the fixture reaches a real local echo.
	dialTarget := net.JoinHostPort(ip, port)
	if f.opts.RedirectTarget != "" {
		dialTarget = f.opts.RedirectTarget
	}
	var localAddr net.Addr
	if f.opts.ExitIP != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(f.opts.ExitIP)}
	}
	dialer := net.Dialer{LocalAddr: localAddr, Timeout: 5 * time.Second}
	upstream, err := dialer.Dial("tcp", dialTarget)
	if err != nil {
		writeReply(c, repHostUnreachable)
		return
	}
	defer upstream.Close()

	if err := writeReply(c, repSucceeded); err != nil {
		return
	}

	// Splice both directions until either side closes.
	_ = c.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

// handshake does the SOCKS5 method negotiation, accepting only no-auth.
func (f *Fixture) handshake(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != socksVer {
		return errors.New("bad socks version")
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	// Reply: version 5, method 0 (no auth).
	_, err := c.Write([]byte{socksVer, 0x00})
	return err
}

// readConnectRequest parses a CONNECT request and returns the requested host and
// port. It REQUIRES ATYP=domain (socks5h): an IP-typed request would mean the
// client resolved locally, which is the leak this fixture exists to detect.
func (f *Fixture) readConnectRequest(c net.Conn) (host, port string, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(c, hdr); err != nil {
		return "", "", err
	}
	if hdr[0] != socksVer {
		return "", "", errors.New("bad socks version in request")
	}
	if hdr[1] != cmdConnect {
		writeReply(c, repCommandNotSupport)
		return "", "", errors.New("only CONNECT supported")
	}
	switch hdr[3] {
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(c, lenByte); err != nil {
			return "", "", err
		}
		name := make([]byte, int(lenByte[0]))
		if _, err = io.ReadFull(c, name); err != nil {
			return "", "", err
		}
		host = string(name)
	case atypIPv4:
		if !f.opts.AllowIPConnect {
			// An IP-typed request is NOT socks5h; reject it so a leak (local
			// resolution) cannot pass silently through the fixture.
			writeReply(c, repAtypNotSupported)
			return "", "", errors.New("IP address type rejected: socks5h requires a hostname (ATYP=domain)")
		}
		ip := make([]byte, 4)
		if _, err = io.ReadFull(c, ip); err != nil {
			return "", "", err
		}
		host = net.IP(ip).String()
	case atypIPv6:
		if !f.opts.AllowIPConnect {
			writeReply(c, repAtypNotSupported)
			return "", "", errors.New("IP address type rejected: socks5h requires a hostname (ATYP=domain)")
		}
		ip := make([]byte, 16)
		if _, err = io.ReadFull(c, ip); err != nil {
			return "", "", err
		}
		host = net.IP(ip).String()
	default:
		writeReply(c, repAtypNotSupported)
		return "", "", errors.New("unsupported address type")
	}

	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(c, portBytes); err != nil {
		return "", "", err
	}
	p := int(portBytes[0])<<8 | int(portBytes[1])
	return host, fmt.Sprintf("%d", p), nil
}

// writeReply writes a minimal SOCKS5 reply with a zero BND.ADDR/BND.PORT.
func writeReply(c net.Conn, rep byte) error {
	_, err := c.Write([]byte{socksVer, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
