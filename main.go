// Command tooljail runs any containerized tool with all of its TCP and DNS
// egress forced through a SOCKS5h proxy, fail-closed, so the wrapped tool
// cannot leak the real IP or DNS.
//
// This is a scaffold entry point; the CLI is built per the prd in
// work/prds/ and the tasks in work/tasks/.
package main

import "fmt"

func main() {
	fmt.Println("tooljail: scaffold. See work/tasks/ for the build plan.")
}
