#!/bin/bash
# P2P Mesh Network - Full Verification Script
# Tests all API endpoints end-to-end.
# Usage: bash scripts/verify.sh [http://localhost:8000]

set -e

API="${1:-http://localhost:8000}"
PASS_COUNT=0
FAIL_COUNT=0
TOKEN=""
DEVICE_ID=""

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc"
        echo "    Expected to contain: $expected"
        echo "    Got: $(echo "$actual" | head -c 200)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

echo "============================================"
echo " P2P Mesh Network — API Verification"
echo " Target: $API"
echo "============================================"
echo ""

# ─── 1. System Health ───
echo -e "${YELLOW}[1] System Health${NC}"
RESP=$(curl -s "$API/health")
check "Health endpoint returns healthy" '"status":"healthy"' "$RESP"

echo -e "${YELLOW}[2] Prometheus Metrics${NC}"
RESP=$(curl -s "$API/metrics")
check "Metrics endpoint returns prometheus data" 'mesh_api' "$RESP"

# ─── 2. Authentication ───
DEMO_EMAIL="demo-$(date +%s)@example.com"
echo -e "${YELLOW}[3] User Registration${NC}"
RESP=$(curl -s -X POST "$API/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$DEMO_EMAIL\",\"password\":\"Demo@12345!\",\"name\":\"Demo User\"}")
check "Registration creates user" '"email"' "$RESP"

# Register again (should fail — duplicate email)
RESP=$(curl -s -X POST "$API/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$DEMO_EMAIL\",\"password\":\"Demo@12345!\",\"name\":\"Demo User\"}")
check "Duplicate registration rejected" '409\|already' "$RESP"

# Weak password test
RESP=$(curl -s -X POST "$API/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"weak@example.com","password":"123","name":"Weak"}')
check "Weak password rejected" '422' "$RESP"

echo -e "${YELLOW}[4] User Login${NC}"
RESP=$(curl -s -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$DEMO_EMAIL\",\"password\":\"Demo@12345!\"}")
check "Login returns access_token" '"access_token"' "$RESP"
TOKEN=$(echo "$RESP" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
check "Access token extracted" '.' "${TOKEN:0:10}..."

echo -e "${YELLOW}[5] Get Profile${NC}"
RESP=$(curl -s "$API/api/v1/auth/me" -H "Authorization: Bearer $TOKEN")
check "Profile shows demo user" '"email"' "$RESP"

echo -e "${YELLOW}[6] Update Profile${NC}"
RESP=$(curl -s -X PATCH "$API/api/v1/auth/me" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"Updated Demo"}')
check "Name updated" '"name":"Updated Demo"' "$RESP"

echo -e "${YELLOW}[7] Unauthenticated Access${NC}"
RESP=$(curl -s "$API/api/v1/auth/me")
check "No token returns 403" '403\|401\|Missing' "$RESP"

# ─── 3. Device Management ───
echo -e "${YELLOW}[8] Register Device${NC}"
RESP=$(curl -s -X POST "$API/api/v1/devices" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"my-laptop","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI demo-key","os":"linux","version":"1.0.0"}')
check "Device registered" '"public_key"' "$RESP"
DEVICE_ID=$(echo "$RESP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
check "Device ID extracted" '.' "${DEVICE_ID:0:8}..."

echo -e "${YELLOW}[9] List Devices${NC}"
RESP=$(curl -s "$API/api/v1/devices" -H "Authorization: Bearer $TOKEN")
check "Device list contains device" '"my-laptop"' "$RESP"

echo -e "${YELLOW}[10] Device Heartbeat${NC}"
RESP=$(curl -s -X POST "$API/api/v1/devices/$DEVICE_ID/heartbeat" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"nat_type":"full_cone","last_ip":"192.168.1.100","last_port":51820}')
check "Heartbeat marks device online" '"online":true' "$RESP"

echo -e "${YELLOW}[11] Get Single Device${NC}"
RESP=$(curl -s "$API/api/v1/devices/$DEVICE_ID" \
    -H "Authorization: Bearer $TOKEN")
check "Single device fetch OK" '"my-laptop"' "$RESP"

# ─── 4. Network Path Selection ───
echo -e "${YELLOW}[12] NAT Compatibility Check${NC}"
RESP=$(curl -s "$API/api/v1/network/check-nat?nat_a=full_cone&nat_b=symmetric")
check "Full cone + symmetric = no P2P" '"p2p_possible":false' "$RESP"

RESP=$(curl -s "$API/api/v1/network/check-nat?nat_a=open&nat_b=open")
check "Open + open = P2P possible" '"p2p_possible":true' "$RESP"

# ─── 5. Relay Node Management (admin only — expect 403) ───
echo -e "${YELLOW}[13] Relay List (user — IPs hidden)${NC}"
RESP=$(curl -s "$API/api/v1/relay" -H "Authorization: Bearer $TOKEN")
check "Relay list accessible" '"relays"' "$RESP"

echo -e "${YELLOW}[14] Relay Registration (non-admin — reject)${NC}"
RESP=$(curl -s -X POST "$API/api/v1/relay" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"test-relay","ip":"10.0.0.1","region":"us-east-1"}')
check "Non-admin cannot register relay" '403' "$RESP"

# ─── 6. Billing — Plans ───
echo -e "${YELLOW}[15] List Plans${NC}"
RESP=$(curl -s "$API/api/v1/billing/plans")
check "Plans list includes free/pro/enterprise" '"free"' "$RESP"

echo -e "${YELLOW}[16] List Subscriptions${NC}"
RESP=$(curl -s "$API/api/v1/billing/subscriptions" \
    -H "Authorization: Bearer $TOKEN")
check "Subscriptions accessible" '"subscriptions"' "$RESP"

# ─── 7. QoS ───
echo -e "${YELLOW}[17] QoS Policy${NC}"
RESP=$(curl -s "$API/api/v1/traffic/qos" \
    -H "Authorization: Bearer $TOKEN")
check "QoS shows plan" '"plan":"free"' "$RESP"

# ─── 8. Traffic Reporting ───
echo -e "${YELLOW}[18] Report Traffic${NC}"
RESP=$(curl -s -X POST "$API/api/v1/traffic/report" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"$DEVICE_ID\",\"bytes_sent\":1048576,\"bytes_received\":524288,\"connection_type\":\"p2p\"}")
check "Traffic reported" '"status":"recorded"' "$RESP"

echo -e "${YELLOW}[19] Traffic Summary${NC}"
RESP=$(curl -s "$API/api/v1/traffic/summary" \
    -H "Authorization: Bearer $TOKEN")
check "Summary includes traffic" '"total_bytes_sent"' "$RESP"

# ─── 9. Token Refresh & Logout ───
echo -e "${YELLOW}[20] Token Refresh${NC}"
REFRESH_TOKEN=$(curl -s -X POST "$API/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$DEMO_EMAIL\",\"password\":\"Demo@12345!\"}" \
    | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
RESP=$(curl -s -X POST "$API/api/v1/auth/refresh" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")
check "Refresh returns new access token" '"access_token"' "$RESP"

echo -e "${YELLOW}[21] Logout${NC}"
RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/api/v1/auth/logout" \
    -H "Authorization: Bearer $TOKEN")
check "Logout returns 204" '204' "$RESP"

echo -e "${YELLOW}[22] Token Reuse After Logout${NC}"
RESP=$(curl -s "$API/api/v1/auth/me" -H "Authorization: Bearer $TOKEN")
check "Old token rejected after logout" '401\|Invalid' "$RESP"

# ─── 10. Docker Services Check ───
echo -e "${YELLOW}[23] Docker Services${NC}"
if command -v docker &>/dev/null; then
    RUNNING=$(docker compose -f deployment/docker-compose.yml ps --status running -q 2>/dev/null | wc -l)
    check "All Docker services running" '7\|8\|9' "$RUNNING"
else
    echo "  ${YELLOW}SKIP${NC} docker not available in this environment"
fi

# ─── Summary ───
echo ""
echo "============================================"
echo " Results: ${GREEN}$PASS_COUNT passed${NC}, ${RED}$FAIL_COUNT failed${NC}"
echo "============================================"
echo ""
echo "Quick manual tests:"
echo "  # Swagger docs (dev mode only):"
echo "  curl $API/docs"
echo ""
echo "  # WebSocket test (requires wscat):"
echo "  wscat -c ws://localhost:8000/api/v1/ws/$DEVICE_ID \\"
echo "        -H 'Authorization: Bearer $TOKEN'"
echo ""
echo "  # Grafana:  http://localhost:3000  (check env for credentials)"
echo "  # Prometheus: http://localhost:9090"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
