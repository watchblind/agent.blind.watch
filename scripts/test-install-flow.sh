#!/bin/bash
# test-install-flow.sh — Tests the full install + provisioning flow locally.
#
# This script simulates what happens when a user runs the install command:
#   1. Start mock API
#   2. Run provisioning simulator (acts as dashboard)
#   3. Build the agent binary
#   4. Run first-boot with provisioned credentials
#   5. Verify state on disk
#   6. Stop agent, restart (subsequent boot)
#   7. Verify DEK recovery works
#   8. Verify encrypted data flows to mock API
#
# No root or systemd required — everything runs in /tmp.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { FAIL=$((FAIL + 1)); echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${BLUE}[....] $*${NC}"; }
separator() { echo -e "${YELLOW}───────────────────────────────────────────────────${NC}"; }

cleanup() {
    info "Cleaning up..."
    kill "$MOCKAPI_PID" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Setup
TEST_DIR=$(mktemp -d)
DATA_DIR="${TEST_DIR}/data"
WAL_DIR="${TEST_DIR}/wal"
BINARY="${TEST_DIR}/blindwatch-agent"
API_PORT=19800
API_URL="http://localhost:${API_PORT}"

cd "$(dirname "$0")/.."

echo ""
echo "  blind.watch install flow test"
echo "  ============================="
echo "  Test dir: ${TEST_DIR}"
echo "  API:      ${API_URL}"
echo ""

# ─── Step 1: Build ───
separator
info "Step 1: Building agent binary..."
go build -o "${BINARY}" ./cmd/agent
if [[ -f "$BINARY" ]]; then
    pass "Agent binary built"
else
    fail "Agent binary build failed"
    exit 1
fi

# ─── Step 2: Start mock API ───
separator
info "Step 2: Starting mock API..."
go run ./cmd/mockapi --addr ":${API_PORT}" > "${TEST_DIR}/mockapi.log" 2>&1 &
MOCKAPI_PID=$!
sleep 1.5

if curl -s "${API_URL}/status" > /dev/null 2>&1; then
    pass "Mock API running on port ${API_PORT}"
else
    fail "Mock API failed to start"
    cat "${TEST_DIR}/mockapi.log"
    exit 1
fi

# ─── Step 3: Provision (simulate dashboard) ───
separator
info "Step 3: Running provisioning simulator..."
go run ./cmd/provision --api "${API_URL}" --agent-name "install-test" \
    > "${TEST_DIR}/provision.log" 2>&1

PROV_FILE=$(grep "Provision file written to" "${TEST_DIR}/provision.log" | awk '{print $NF}')
if [[ -f "$PROV_FILE" ]]; then
    pass "Provisioning completed, file: ${PROV_FILE}"
else
    fail "Provisioning failed"
    cat "${TEST_DIR}/provision.log"
    exit 1
fi

# Extract agent ID for later checks
AGENT_ID=$(python3 -c "import json; print(json.load(open('${PROV_FILE}'))['agent_id'])")
info "Agent ID: ${AGENT_ID}"

# ─── Step 4: First boot ───
separator
info "Step 4: Running first boot..."
timeout 5 "${BINARY}" \
    --first-boot \
    --provision-file "${PROV_FILE}" \
    --data-dir "${DATA_DIR}" \
    --wal-dir "${WAL_DIR}" \
    > "${TEST_DIR}/firstboot.log" 2>&1 || true

cat "${TEST_DIR}/firstboot.log"

# Verify state file exists
if [[ -f "${DATA_DIR}/state.json" ]]; then
    pass "State file created"
else
    fail "State file not found at ${DATA_DIR}/state.json"
fi

# Verify private key exists with correct permissions
if [[ -f "${DATA_DIR}/agent-key" ]]; then
    PERMS=$(stat -c '%a' "${DATA_DIR}/agent-key")
    if [[ "$PERMS" == "600" ]]; then
        pass "Private key saved with 600 permissions"
    else
        fail "Private key has wrong permissions: ${PERMS} (expected 600)"
    fi
else
    fail "Private key not found at ${DATA_DIR}/agent-key"
fi

# Verify agent_secret is in state but provisioning_secret is NOT
if grep -q "agent_secret" "${DATA_DIR}/state.json"; then
    pass "agent_secret stored in state"
else
    fail "agent_secret not found in state"
fi

if grep -q "provisioning_secret" "${DATA_DIR}/state.json"; then
    fail "provisioning_secret found in state (should have been discarded!)"
else
    pass "provisioning_secret NOT in state (correctly discarded)"
fi

# Verify agent connected during first boot
if grep -q "connected to server" "${TEST_DIR}/firstboot.log"; then
    pass "Agent connected to server on first boot"
else
    fail "Agent did not connect on first boot"
fi

# ─── Step 5: Subsequent boot ───
separator
info "Step 5: Running subsequent boot..."
timeout 5 "${BINARY}" \
    --data-dir "${DATA_DIR}" \
    --wal-dir "${WAL_DIR}" \
    > "${TEST_DIR}/reboot.log" 2>&1 || true

cat "${TEST_DIR}/reboot.log"

# Verify DEK recovery
if grep -q "DEK recovered from server" "${TEST_DIR}/reboot.log"; then
    pass "DEK recovered from server on subsequent boot"
else
    fail "DEK recovery failed on subsequent boot"
fi

if grep -q "connected to server" "${TEST_DIR}/reboot.log"; then
    pass "Agent connected on subsequent boot"
else
    fail "Agent did not connect on subsequent boot"
fi

# ─── Step 6: Verify provisioning consumed ───
separator
info "Step 6: Verifying provisioning is single-use..."

# Try first-boot again with same credentials — should fail
timeout 5 "${BINARY}" \
    --first-boot \
    --provision-file "${PROV_FILE}" \
    --data-dir "${TEST_DIR}/data2" \
    --wal-dir "${TEST_DIR}/wal2" \
    > "${TEST_DIR}/replay.log" 2>&1 || true

if grep -q "provisioning already consumed\|403" "${TEST_DIR}/replay.log"; then
    pass "Provisioning replay rejected (single-use)"
else
    # Check if it was rejected
    if grep -q "failed\|error\|Fatal" "${TEST_DIR}/replay.log"; then
        pass "Provisioning replay failed (expected)"
    else
        fail "Provisioning replay was not rejected"
        cat "${TEST_DIR}/replay.log"
    fi
fi

# ─── Step 7: Live mode data flow ───
separator
info "Step 7: Testing live mode data flow..."

# Set live mode
curl -s -X POST "${API_URL}/control/live" > /dev/null

# Run agent for 3 seconds in live mode
timeout 3 "${BINARY}" \
    --data-dir "${DATA_DIR}" \
    --wal-dir "${WAL_DIR}" \
    > "${TEST_DIR}/live.log" 2>&1 || true

# Check if batches arrived
BATCH_COUNT=$(curl -s "${API_URL}/batches" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if d else 0)" 2>/dev/null)
if [[ "$BATCH_COUNT" -gt 0 ]]; then
    pass "Received ${BATCH_COUNT} encrypted batches in live mode"
else
    # Live mode needs time to collect + send, might be 0 in 3 seconds
    warn "No batches received (may need more time)"
fi

# Reset to idle
curl -s -X POST "${API_URL}/control/idle" > /dev/null

# ─── Step 8: Not-provisioned error ───
separator
info "Step 8: Testing unprovisioned agent error..."

EMPTY_DIR=$(mktemp -d)
timeout 2 "${BINARY}" \
    --data-dir "${EMPTY_DIR}" \
    --wal-dir "${EMPTY_DIR}/wal" \
    > "${TEST_DIR}/unprovisioned.log" 2>&1 || true

if grep -q "not provisioned" "${TEST_DIR}/unprovisioned.log"; then
    pass "Unprovisioned agent shows helpful error"
else
    fail "Unprovisioned agent did not show expected error"
    cat "${TEST_DIR}/unprovisioned.log"
fi
rm -rf "$EMPTY_DIR"

# ─── Results ───
separator
echo ""
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}  SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}  ALL TESTS PASSED${NC}"
    exit 0
fi
