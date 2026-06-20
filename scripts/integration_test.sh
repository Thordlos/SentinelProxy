#!/usr/bin/env bash
set -e

# Use local Go
export PATH="$HOME/.local/go/bin:$PATH"

cd /home/meliodas/文档/proxy/SentinelProxy

# Start mock upstream
python3 scripts/mock_upstream.py > /tmp/mock_upstream.log 2>&1 &
MOCK_PID=$!
echo "Mock upstream PID: $MOCK_PID"

# Wait for mock upstream
sleep 2

# Start SentinelProxy
./sentinelproxy > /tmp/sentinel_run.log 2>&1 &
SENTINEL_PID=$!
echo "SentinelProxy PID: $SENTINEL_PID"

# Wait for SentinelProxy
sleep 5

cleanup() {
    echo "Cleaning up..."
    kill $SENTINEL_PID 2>/dev/null || true
    kill $MOCK_PID 2>/dev/null || true
    wait $SENTINEL_PID 2>/dev/null || true
    wait $MOCK_PID 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Non-streaming test ==="
curl -s -X POST http://localhost:3000/v1/chat/completions \
    -H "Authorization: Bearer sk-test123" \
    -H "Content-Type: application/json" \
    -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"我的手机号是13812345678"}]}' | python3 -m json.tool

echo ""
echo "=== Streaming test ==="
curl -s -X POST http://localhost:3000/v1/chat/completions \
    -H "Authorization: Bearer sk-test123" \
    -H "Content-Type: application/json" \
    -H "x-session-id: test-session" \
    -d '{"model":"deepseek-chat","stream":true,"messages":[{"role":"user","content":"我的邮箱是alice@example.com"}]}'

echo ""
echo "=== Logs ==="
cat /tmp/mock_upstream.log | tail -20
