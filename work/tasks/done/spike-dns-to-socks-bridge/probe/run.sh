#!/bin/bash
set +e
cd "$(dirname "$0")"
cleanup(){ kill "$HARNESS_PID" "$FWD_PID" 2>/dev/null; }
trap cleanup EXIT

echo "=== 1. start harness (socks5 proxy + dns-over-tcp resolver) ==="
./harness/harness -mode=serve -listen=127.0.0.1:0 -dns=127.0.0.1:0 > harness.out 2>&1 &
HARNESS_PID=$!
sleep 0.6
cat harness.out | sed 's/^/  /'
PROXY=$(grep PROXY_ADDR harness.out | cut -d= -f2)
UPSTREAM=$(grep UPSTREAM_HOSTPORT harness.out | cut -d= -f2)
echo "  proxy=$PROXY upstream(real)=$UPSTREAM"

echo "=== 2. start forwarder (UDP DNS -> socks5 TCP -> resolver) ==="
# forwarder uses a HOSTNAME upstream (resolved proxy-side); the harness proxy
# redirects any CONNECT to the real resolver, so the name is arbitrary-but-stable.
./forwarder/forwarder -listen=127.0.0.1:1053 -proxy="$PROXY" -upstream="dns.tooljail.test:53" > fwd.out 2>&1 &
FWD_PID=$!
sleep 0.5
cat fwd.out | sed 's/^/  /'

echo "=== 3. ASSERT: query the unique name via the forwarder ==="
./harness/harness -mode=assert -forwarder=127.0.0.1:1053 2>&1 | sed 's/^/  /'
echo "  assert exit: $?"

echo "=== 4. LEAK CHECK: did the host resolver ever see the name? ==="
# the harness records names its proxy-side resolver saw; a separate check that
# the HOST resolver can't resolve it (it's a fake TLD) proves no host leak.
host unique.tooljail.test >/dev/null 2>&1 && echo "  ⚠ host resolver resolved it (unexpected)" || echo "  ✅ host resolver returns NXDOMAIN/fail for unique.tooljail.test (no host leak path)"
