package socks5hfixture_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/wighawag/netcage/internal/socks5hfixture"
)

// startEchoExit stands up a tiny TCP server that, on connect, writes back the
// client's observed source address. It plays "the destination service" that the
// SOCKS5h proxy connects out to, so a test can read what exit IP the proxy
// presented. It listens on 127.0.0.1 and returns its addr.
func startEchoExit(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo exit listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				_, _ = io.WriteString(c, host)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// dialThroughFixture uses an x/net/proxy SOCKS5 dialer that resolves the target
// HOSTNAME remotely (socks5h semantics): the dialer hands the proxy a hostname,
// not an IP, so the proxy is the one that resolves it.
func dialThroughFixture(t *testing.T, proxyAddr, targetHostPort string) (net.Conn, error) {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build SOCKS5 dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cd := d.(proxy.ContextDialer)
	return cd.DialContext(ctx, "tcp", targetHostPort)
}

func TestFixture_KnownExitIP(t *testing.T) {
	exitAddr, stopExit := startEchoExit(t)
	defer stopExit()
	_, exitPort, _ := net.SplitHostPort(exitAddr)

	// The proxy's known exit IP is a loopback alias it dials OUT from, so the
	// destination observes the proxy's source, not the client's. On Linux the
	// whole 127.0.0.0/8 is loopback, so 127.0.0.2 is bindable as a source.
	const exitIP = "127.0.0.2"
	const knownHost = "unique-target.netcage.test"

	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP: exitIP,
		KnownHosts: map[string]string{
			// The proxy resolves the unique hostname to the echo exit's IP, so a
			// socks5h dial to knownHost:exitPort reaches the echo server.
			knownHost: "127.0.0.1",
		},
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()

	conn, err := dialThroughFixture(t, fx.Addr(), net.JoinHostPort(knownHost, exitPort))
	if err != nil {
		t.Fatalf("dial through fixture: %v", err)
	}
	defer conn.Close()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read exit echo: %v", err)
	}
	if string(got) != exitIP {
		t.Fatalf("observed exit IP = %q, want the proxy's exit IP %q", string(got), exitIP)
	}
}

func TestFixture_ResolvesUniqueHostnameProxySide(t *testing.T) {
	exitAddr, stopExit := startEchoExit(t)
	defer stopExit()
	_, exitPort, _ := net.SplitHostPort(exitAddr)

	const knownHost = "unique-target.netcage.test"
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:     "127.0.0.2",
		KnownHosts: map[string]string{knownHost: "127.0.0.1"},
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	defer fx.Close()

	// Before any dial, the proxy has resolved nothing.
	if got := fx.ResolvedHosts(); len(got) != 0 {
		t.Fatalf("ResolvedHosts before dial = %v, want empty", got)
	}

	conn, err := dialThroughFixture(t, fx.Addr(), net.JoinHostPort(knownHost, exitPort))
	if err != nil {
		t.Fatalf("dial through fixture: %v", err)
	}
	conn.Close()

	// The observability hook must show the unique hostname was resolved
	// PROXY-SIDE (the host resolver never saw it).
	resolved := fx.ResolvedHosts()
	found := false
	for _, h := range resolved {
		if h == knownHost {
			found = true
		}
	}
	if !found {
		t.Fatalf("ResolvedHosts = %v, want it to contain %q (resolved proxy-side)", resolved, knownHost)
	}
}

func TestFixture_KillFailsClosed(t *testing.T) {
	const knownHost = "unique-target.netcage.test"
	fx := socks5hfixture.New(socks5hfixture.Options{
		ExitIP:     "127.0.0.2",
		KnownHosts: map[string]string{knownHost: "127.0.0.1"},
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	addr := fx.Addr()

	// Kill it.
	fx.Close()

	// A subsequent dial to the proxy must fail (no silent fallback).
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", knownHost+":80"); err == nil {
		conn.Close()
		t.Fatal("dial through killed fixture succeeded, want failure (fail-closed)")
	}
}

func TestFixture_CallerChosenBindAndCleanTeardown(t *testing.T) {
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("fixture start: %v", err)
	}
	addr := fx.Addr()
	if addr == "" {
		t.Fatal("Addr() empty after Start; caller must be able to learn the bound address")
	}
	// The bound address must be a real, connectable TCP address.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		t.Fatalf("Addr() = %q, not a host:port: %v", addr, err)
	}
	fx.Close()

	// After Close, the port must be released (clean teardown): a fresh listen on
	// the same port should succeed within a short window.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %s still bound after Close (teardown leak): %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
