// Command listener is a tiny throwaway TCP listener for the pasta reachback
// spike. It binds one host-loopback port and answers each connection with a
// fixed banner naming itself, so a client inside a container can prove WHICH
// host-loopback port it actually reached.
//
// Two instances are run on the host during the spike:
//
//	127.0.0.1:19050  -banner=PROXY    (must stay reachable from the sidecar)
//	127.0.0.1:19051  -banner=CONTROL  (must become UNreachable after narrowing)
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19050", "host-loopback address to bind")
	banner := flag.String("banner", "PROXY", "banner to send on each connection")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listener bind %s failed: %v\n", *addr, err)
		os.Exit(1)
	}
	fmt.Printf("listener up: %s banner=%s\n", *addr, *banner)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			fmt.Fprintf(c, "REACHED:%s\n", *banner)
		}(c)
	}
}
