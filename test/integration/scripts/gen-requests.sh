#!/bin/bash
# gen-requests.sh — generate sudo challenge requests against an identree instance.
# Creates challenges directly via POST /api/challenge (bypasses PAM) so the
# script runs without needing interactive TTY sessions inside host containers.
#
# Usage:
#   # Full-mode (PocketID)
#   IDENTREE_URL=http://localhost:8110 \
#   SHARED_SECRET=integ-full-shared-secret-abc123456 \
#   HOSTNAMES="prod-ubuntu22-01 prod-ubuntu24-01 prod-debian12-01 prod-fedora41-01 prod-rocky9-01" \
#   bash test/integration/scripts/gen-requests.sh
#
#   # lldap-dex
#   IDENTREE_URL=http://localhost:8111 \
#   SHARED_SECRET=integ-lldap-dex-shared-secret-xyz \
#   HOSTNAMES="dev-ubuntu22-01 dev-ubuntu24-01 dev-debian12-01 dev-fedora41-01 dev-rocky9-01" \
#   bash test/integration/scripts/gen-requests.sh
set -euo pipefail

IDENTREE_URL="${IDENTREE_URL:-http://localhost:8110}"
SHARED_SECRET="${SHARED_SECRET:-integ-full-shared-secret-abc123456}"
ROUNDS="${ROUNDS:-3}"       # challenges per (user, host) pair → 25 users × 5 hosts × 3 = 375 total
DELAY="${DELAY:-0.05}"      # seconds between requests to avoid rate-limiting

# Comma/space-separated list of hostnames to spread challenges across
HOSTNAMES_RAW="${HOSTNAMES:-prod-ubuntu22-01 prod-ubuntu24-01 prod-debian12-01 prod-fedora41-01 prod-rocky9-01}"

USERS=(
    alice bob carol dave erin frank grace henry iris jack
    kate liam mia noah olivia paul quinn rose steve theo
    sam tina ursula victor wendy
)

REASONS=(
    "Deploy application update"
    "Restart nginx service"
    "Check system logs"
    "Rotate TLS certificates"
    "Run database migration"
    "Install security patch"
    "Investigate high CPU usage"
    "Clear application cache"
    "Update configuration file"
    "Emergency hotfix deployment"
    "Backup database"
    "Test new deployment script"
)

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() {
    echo "==> Waiting for identree at ${IDENTREE_URL}..."
    for i in $(seq 1 30); do
        if curl -sf "${IDENTREE_URL}/healthz" >/dev/null 2>&1; then
            echo "    identree ready."
            return
        fi
        sleep 2
    done
    echo "ERROR: identree not ready" >&2
    exit 1
}

create_challenge() {
    local user="$1" host="$2" reason="$3"
    local resp
    resp=$(curl -sf -X POST "${IDENTREE_URL}/api/challenge" \
        -H "Content-Type: application/json" \
        -H "X-Shared-Secret: ${SHARED_SECRET}" \
        -d "{\"username\":\"${user}\",\"hostname\":\"${host}\",\"reason\":\"${reason}\"}" 2>&1) || {
        echo "    WARN: challenge failed for ${user}@${host}: $resp"
        return 1
    }
    local id status
    id=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('challenge_id',''))" 2>/dev/null || echo "")
    status=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','pending'))" 2>/dev/null || echo "pending")
    echo "$id:$status"
}

random_reason() {
    echo "${REASONS[$((RANDOM % ${#REASONS[@]}))]}"
}

# ── Parse hostnames ────────────────────────────────────────────────────────────

IFS=' ,' read -ra HOSTNAMES <<< "$HOSTNAMES_RAW"

# ── Wait ───────────────────────────────────────────────────────────────────────

wait_for

# ── Generate challenges ────────────────────────────────────────────────────────

total=0
approved=0
pending=0
failed=0

CHALLENGE_IDS=()

echo ""
echo "==> Generating challenges: ${#USERS[@]} users × ${#HOSTNAMES[@]} hosts × ${ROUNDS} rounds"
echo "    = $((${#USERS[@]} * ${#HOSTNAMES[@]} * ROUNDS)) total requests"
echo ""

for ((round=1; round<=ROUNDS; round++)); do
    echo "── Round ${round}/${ROUNDS} ─────────────────────────────────────────"
    for user in "${USERS[@]}"; do
        for host in "${HOSTNAMES[@]}"; do
            reason=$(random_reason)
            result=$(create_challenge "$user" "$host" "$reason" 2>&1) || { failed=$((failed+1)); total=$((total+1)); continue; }
            if [ -n "$result" ]; then
                id="${result%%:*}"
                status="${result##*:}"
                total=$((total+1))
                if [ "$status" = "approved" ]; then
                    approved=$((approved+1))
                    printf "  ✓ auto  %s@%-20s %s\n" "$user" "$host" "${id:0:8}"
                elif [ -n "$id" ]; then
                    pending=$((pending+1))
                    CHALLENGE_IDS+=("$id")
                    printf "  ● pend  %s@%-20s %s\n" "$user" "$host" "${id:0:8}"
                fi
                sleep "$DELAY"
            fi
        done
    done
    echo ""
done

# ── Write challenge IDs to file ────────────────────────────────────────────────

ID_FILE="/tmp/identree-challenge-ids-$(echo "${IDENTREE_URL}" | tr ':/' '_').txt"
printf '%s\n' "${CHALLENGE_IDS[@]}" > "$ID_FILE"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Challenge generation complete"
echo ""
echo "  Total:    ${total}"
echo "  Pending:  ${pending}   (saved to ${ID_FILE})"
echo "  Auto-approved (grace): ${approved}"
echo "  Failed:   ${failed}"
echo ""
echo "  Next step: run-suite.sh to approve/reject pending challenges"
echo "    IDENTREE_URL=${IDENTREE_URL} \\"
echo "    SHARED_SECRET=${SHARED_SECRET} \\"
echo "    CHALLENGE_ID_FILE=${ID_FILE} \\"
echo "    bash test/integration/scripts/run-suite.sh"
echo "════════════════════════════════════════════════════════════"
