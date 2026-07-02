#!/bin/bash
set +e
cd "$(dirname "$0")"
cleanup(){ kill "$FWD_PID" 2>/dev/null; }
trap cleanup EXIT
echo "=== forwarder pointed at a DEAD proxy (nothing listening) ==="
./forwarder/forwarder -listen=127.0.0.1:1054 -proxy="127.0.0.1:1" -upstream="dns.netcage.test:53" > fwd2.out 2>&1 &
FWD_PID=$!
sleep 0.5
echo "=== assert: query must get NO answer (fail-closed, no host fallback) ==="
./harness/harness -mode=assert -forwarder=127.0.0.1:1054 2>&1 | sed 's/^/  /'
rc=$?
if [ $rc -ne 0 ]; then echo "  ✅ FAIL-CLOSED: no DNS answer when the proxy is down (exit $rc), no fallback to host resolver"; else echo "  ⚠ got an answer with proxy down (would be a leak)"; fi
