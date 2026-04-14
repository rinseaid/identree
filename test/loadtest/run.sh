#!/usr/bin/env bash
#
# Load test runner for identree.
# Starts the test stack, runs system-level load tests, and reports results.
#
# Usage: bash test/loadtest/run.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOADTEST_BIN="$SCRIPT_DIR/loadtest"

URL="${IDENTREE_URL:-http://localhost:8090}"
SECRET="${IDENTREE_SECRET:-test-shared-secret-1234567890abc}"
SKIP_STACK="${SKIP_STACK:-}"

echo "============================================================"
echo "identree load test suite"
echo "============================================================"
echo "URL:    $URL"
echo "Root:   $ROOT_DIR"
echo ""

# ── Build load test binary ─────────────────────────────────────────────────
echo ">>> Building load test binary..."
cd "$ROOT_DIR"
go build -o "$LOADTEST_BIN" ./test/loadtest/
echo "    Built: $LOADTEST_BIN"

# ── Start the test stack (unless SKIP_STACK is set) ────────────────────────
if [ -z "$SKIP_STACK" ]; then
    echo ""
    echo ">>> Starting test stack (make up)..."
    make up
    echo "    Stack started."
fi

# ── Wait for health ────────────────────────────────────────────────────────
echo ""
echo ">>> Waiting for server health..."
MAX_WAIT=60
for i in $(seq 1 $MAX_WAIT); do
    if curl -sf "$URL/healthz" > /dev/null 2>&1; then
        echo "    Server healthy after ${i}s"
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo "    FAIL: server not healthy after ${MAX_WAIT}s"
        exit 1
    fi
    sleep 1
done

# ── Capture pre-test metrics ──────────────────────────────────────────────
echo ""
echo ">>> Pre-test metrics snapshot"
curl -sf "$URL/metrics" 2>/dev/null | grep '^identree_' | head -20 || echo "    (metrics endpoint unavailable)"

# ── Test 1: Challenge creation throughput ──────────────────────────────────
echo ""
echo "============================================================"
echo "TEST 1: Challenge creation throughput (1000 challenges, 10 workers)"
echo "============================================================"
"$LOADTEST_BIN" \
    -url "$URL" \
    -secret "$SECRET" \
    -workers 10 \
    -requests 100 \
    -mode create

# ── Test 2: Concurrent challenge creation ──────────────────────────────────
echo ""
echo "============================================================"
echo "TEST 2: Concurrent challenge creation (50 workers x 20 challenges)"
echo "============================================================"
"$LOADTEST_BIN" \
    -url "$URL" \
    -secret "$SECRET" \
    -workers 50 \
    -requests 20 \
    -mode create

# ── Test 3: Poll throughput ────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "TEST 3: Poll throughput (10 workers x 10 challenges x 10 polls each)"
echo "============================================================"
"$LOADTEST_BIN" \
    -url "$URL" \
    -secret "$SECRET" \
    -workers 10 \
    -requests 10 \
    -mode poll

# ── Test 4: Mixed workload ────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "TEST 4: Mixed workload (20 workers x 50 cycles, create+poll)"
echo "============================================================"
"$LOADTEST_BIN" \
    -url "$URL" \
    -secret "$SECRET" \
    -workers 20 \
    -requests 50 \
    -mode mixed

# ── Capture post-test metrics ─────────────────────────────────────────────
echo ""
echo ">>> Post-test metrics snapshot"
curl -sf "$URL/metrics" 2>/dev/null | grep '^identree_' | head -30 || echo "    (metrics endpoint unavailable)"

# ── Tear down (unless SKIP_STACK is set) ──────────────────────────────────
if [ -z "$SKIP_STACK" ]; then
    echo ""
    echo ">>> Tearing down test stack (make down)..."
    cd "$ROOT_DIR"
    make down
    echo "    Stack stopped."
fi

echo ""
echo "============================================================"
echo "Load test suite complete."
echo "============================================================"

# Clean up binary
rm -f "$LOADTEST_BIN"
