# Hard-block all UDP in v1 (single leak-proof invariant)

**Status:** accepted

The jail hard-drops ALL UDP unconditionally in v1, rather than opting in to SOCKS5 UDP-associate when the proxy advertises it. This keeps a single, trivially-verifiable invariant: "UDP is dropped, period." Crucially, hard-blocking UDP does NOT break DNS: with `socks5h` the proxy resolves hostnames proxy-side (over the proxy's TCP), so the jail never needs client-side UDP for name resolution.

We rejected opt-in UDP-associate because it is a genuine leak footgun: the UDP relay is a separate path negotiated with the proxy, Tor (the prime use case) does not support it at all, and getting the relay-address handling and encapsulation right is exactly where a leak hides. Opt-in UDP would also make the invariant conditional and roughly double the leak-test matrix.

## Consequences

- A wrapped tool that emits raw UDP (e.g. QUIC/HTTP3 probing, raw DNS, ping-style traffic) has that traffic dropped, not leaked, satisfying user story 5.
- **UDP-associate support is deferred, not designed out.** If a wrapped tool's core function genuinely needs outbound UDP, that is the trigger to revisit in a future ADR; v1 still ships hard-blocked, because "the invariant held" is worth more than one tool's UDP feature. No tool in the motivating webscan set requires outbound UDP for its core function today.
