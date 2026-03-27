#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# xiraNET v2.1.0 — Benchmark Suite
# ═══════════════════════════════════════════════════════════════
# Prerequisites: hey (https://github.com/rakyll/hey) or wrk
# Usage: ./scripts/bench.sh [host:port] [api_key]

HOST="${1:-http://localhost:9000}"
API_KEY="${2:-xira-default-key}"
DURATION="10s"
CONCURRENT=50
REQUESTS=5000

echo "═══════════════════════════════════════════════════════════"
echo "  xiraNET Benchmark Suite v2.1.0"
echo "  Target: $HOST"
echo "  Duration: $DURATION | Concurrent: $CONCURRENT"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Check for hey
if ! command -v hey &> /dev/null; then
    echo "❌ 'hey' not found. Install: go install github.com/rakyll/hey@latest"
    echo "   Or use: brew install hey / choco install hey"
    exit 1
fi

echo "▶ Test 1: Health Endpoint (baseline)"
hey -n $REQUESTS -c $CONCURRENT -z $DURATION "$HOST/health"
echo ""

echo "▶ Test 2: Metrics Endpoint"
hey -n $REQUESTS -c $CONCURRENT -z $DURATION "$HOST/metrics"
echo ""

echo "▶ Test 3: Dashboard Endpoint"
hey -n $REQUESTS -c $CONCURRENT -z $DURATION "$HOST/dashboard"
echo ""

echo "▶ Test 4: Admin API - Services List"
hey -n $REQUESTS -c $CONCURRENT -z $DURATION \
    -H "X-Api-Key: $API_KEY" \
    "$HOST/xira/services"
echo ""

echo "▶ Test 5: Admin API - Stats"
hey -n $REQUESTS -c $CONCURRENT -z $DURATION \
    -H "X-Api-Key: $API_KEY" \
    "$HOST/xira/stats"
echo ""

echo "▶ Test 6: Admin API - SLA Report"
hey -n $REQUESTS -c $CONCURRENT -z $DURATION \
    -H "X-Api-Key: $API_KEY" \
    "$HOST/xira/sla"
echo ""

echo "▶ Test 7: Gateway Proxy (404 - no upstream)"
hey -n $REQUESTS -c $CONCURRENT -z $DURATION "$HOST/api/test"
echo ""

echo "▶ Test 8: WAF Attack Payload (should be blocked)"
hey -n 1000 -c 10 \
    -H "X-Api-Key: $API_KEY" \
    "$HOST/api/test?id=1%20union%20select%20from%20users"
echo ""

echo "═══════════════════════════════════════════════════════════"
echo "  Benchmark complete!"
echo "═══════════════════════════════════════════════════════════"
