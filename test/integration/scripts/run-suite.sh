#!/bin/bash
# run-suite.sh — full integration test suite runner.
# Generates challenges then approves/rejects them as admin via computed CSRF.
# Requires python3 (stdlib only) for HMAC computation.
#
# Usage (run once for each stack):
#
#   # Full-mode (PocketID)
#   STACK=full-mode \
#   IDENTREE_URL=http://localhost:8110 \
#   SHARED_SECRET=integ-full-shared-secret-abc123456 \
#   POCKETID_URL=http://localhost:1413 \
#   POCKETID_API_KEY=integ-full-static-key \
#   bash test/integration/scripts/run-suite.sh
#
#   # lldap-dex
#   STACK=lldap-dex \
#   IDENTREE_URL=http://localhost:8111 \
#   SHARED_SECRET=integ-lldap-dex-shared-secret-xyz \
#   LLDAP_URL=http://localhost:17175 \
#   bash test/integration/scripts/run-suite.sh
#
#   # vault-escrow
#   STACK=vault-escrow \
#   IDENTREE_URL=http://localhost:8114 \
#   SHARED_SECRET=integ-vault-escrow-shared-secret-xyz \
#   LLDAP_URL=http://localhost:17177 \
#   bash test/integration/scripts/run-suite.sh
set -euo pipefail

STACK="${STACK:-full-mode}"
IDENTREE_URL="${IDENTREE_URL:-http://localhost:8110}"
SHARED_SECRET="${SHARED_SECRET:-integ-full-shared-secret-abc123456}"
ADMIN_USER="${ADMIN_USER:-sam}"   # a member of the 'admins' group
ROUNDS="${ROUNDS:-3}"
APPROVE_RATIO="${APPROVE_RATIO:-0.7}"  # 70% approve, 30% reject
DELAY="${DELAY:-0.1}"

# Host sets per stack
case "$STACK" in
    full-mode)
        HOSTNAMES="prod-ubuntu22-01 prod-ubuntu24-01 prod-debian12-01 prod-fedora41-01 prod-rocky9-01"
        SETUP_CMD="bash test/integration/scripts/create-users-pocketid.sh"
        ;;
    lldap-dex)
        HOSTNAMES="dev-ubuntu22-01 dev-ubuntu24-01 dev-debian12-01 dev-fedora41-01 dev-rocky9-01"
        SETUP_CMD="bash test/integration/scripts/create-users-lldap.sh"
        ;;
    vault-escrow)
        HOSTNAMES="vault-ubuntu22-01 vault-ubuntu24-01 vault-debian12-01 vault-fedora41-01 vault-rocky9-01"
        SETUP_CMD="LLDAP_URL=${LLDAP_URL:-http://localhost:17177} CLIENT=integ-vault-ubuntu2204 bash test/integration/scripts/create-users-lldap.sh"
        ;;
    *)
        echo "ERROR: unknown STACK '${STACK}'. Valid: full-mode, lldap-dex, vault-escrow" >&2
        exit 1
        ;;
esac

USERS=(
    alice bob carol dave erin frank grace henry iris jack
    kate liam mia noah olivia paul quinn rose steve theo
    sam tina ursula victor wendy
)

# ── Python helpers (inline) ────────────────────────────────────────────────────
# All HMAC computation is done in Python (stdlib only) to avoid shell portability issues.

PY_HMAC='
import sys, hmac, hashlib, time

def derive_key(secret, context):
    return hmac.new(secret.encode(), context.encode(), hashlib.sha256).digest()

def compute_csrf(secret, username, ts):
    key = derive_key(secret, "csrf")
    return hmac.new(key, ("csrf:" + username + ":" + str(ts)).encode(), hashlib.sha256).hexdigest()

def compute_session(secret, username, role, ts, nonce):
    key = derive_key(secret, "session")
    msg = "session:" + username + ":" + role + ":" + str(ts) + ":" + nonce
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

cmd = sys.argv[1] if len(sys.argv) > 1 else ""
secret = sys.argv[2] if len(sys.argv) > 2 else ""

if cmd == "csrf":
    username = sys.argv[3]
    ts = sys.argv[4]
    print(compute_csrf(secret, username, ts))
elif cmd == "session_cookie":
    username = sys.argv[3]
    role = sys.argv[4]
    ts = str(int(time.time()))
    nonce = "integ"
    sig = compute_session(secret, username, role, ts, nonce)
    print(username + ":" + role + ":" + ts + ":" + nonce + ":" + sig)
'

csrf_token() {
    local username="$1" ts="$2"
    python3 -c "$PY_HMAC" csrf "$SHARED_SECRET" "$username" "$ts"
}

session_cookie_value() {
    local username="$1" role="$2"
    python3 -c "$PY_HMAC" session_cookie "$SHARED_SECRET" "$username" "$role"
}

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

dev_login() {
    # DEV_LOGIN=true: GET /dev/login?user=X&role=Y sets pam_session cookie.
    # Extract Set-Cookie and save for reuse.
    local username="$1" role="$2"
    COOKIE_JAR=$(mktemp /tmp/identree-cookie-XXXXXX.txt)
    curl -sf -c "$COOKIE_JAR" \
        "${IDENTREE_URL}/dev/login?user=${username}&role=${role}" >/dev/null
    # Extract pam_session value from cookie jar
    SESSION_COOKIE=$(grep 'pam_session' "$COOKIE_JAR" | awk '{print $NF}')
    echo "    session established for ${username} (${role})"
}

approve_challenge() {
    local challenge_id="$1"
    local ts
    ts=$(date +%s)
    local token
    token=$(csrf_token "$ADMIN_USER" "$ts")
    local rc
    rc=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST "${IDENTREE_URL}/api/challenges/approve" \
        --cookie "pam_session=${SESSION_COOKIE}" \
        -d "username=${ADMIN_USER}&csrf_token=${token}&csrf_ts=${ts}&challenge_id=${challenge_id}" \
        2>&1) || rc="000"
    if [ "$rc" = "303" ] || [ "$rc" = "200" ]; then
        echo "approved"
    else
        echo "err:${rc}"
    fi
}

reject_challenge() {
    local challenge_id="$1"
    local ts
    ts=$(date +%s)
    local token
    token=$(csrf_token "$ADMIN_USER" "$ts")
    local rc
    rc=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST "${IDENTREE_URL}/api/challenges/reject" \
        --cookie "pam_session=${SESSION_COOKIE}" \
        -d "username=${ADMIN_USER}&csrf_token=${token}&csrf_ts=${ts}&challenge_id=${challenge_id}" \
        2>&1) || rc="000"
    if [ "$rc" = "303" ] || [ "$rc" = "200" ]; then
        echo "rejected"
    else
        echo "err:${rc}"
    fi
}

create_challenge() {
    local user="$1" host="$2" reason="$3"
    curl -sf -X POST "${IDENTREE_URL}/api/challenge" \
        -H "Content-Type: application/json" \
        -H "X-Shared-Secret: ${SHARED_SECRET}" \
        -d "{\"username\":\"${user}\",\"hostname\":\"${host}\",\"reason\":\"${reason}\"}" \
        2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('challenge_id','') + ':' + d.get('status','pending'))
" 2>/dev/null || echo ":error"
}

REASONS=(
    "Deploy application update"
    "Restart nginx"
    "Check system logs"
    "Rotate TLS certificates"
    "Run database migration"
    "Install security patch"
    "Investigate high CPU"
    "Clear cache"
    "Update config"
    "Emergency hotfix"
    "Backup database"
    "Test deployment"
)

random_reason() {
    echo "${REASONS[$((RANDOM % ${#REASONS[@]}))]}"
}

# ── Run ────────────────────────────────────────────────────────────────────────

wait_for

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  identree integration suite: ${STACK}"
echo "  Server: ${IDENTREE_URL}"
echo "  Admin:  ${ADMIN_USER}"
echo "═══════════════════════════════════════════════════════════════"

# Establish admin session via dev login
echo ""
echo "==> Establishing admin session (DEV_LOGIN)..."
dev_login "$ADMIN_USER" "admin"

IFS=' ,' read -ra HOSTNAME_ARR <<< "$HOSTNAMES"

# Track stats
total=0
approved_count=0
rejected_count=0
auto_count=0
failed_count=0

echo ""
echo "==> Generating and resolving challenges..."
echo "    ${#USERS[@]} users × ${#HOSTNAME_ARR[@]} hosts × ${ROUNDS} rounds"
echo "    Approve ratio: ${APPROVE_RATIO} ($(python3 -c "print(round(${APPROVE_RATIO}*100))") approve / $(python3 -c "print(100-round(${APPROVE_RATIO}*100))") reject)"
echo ""

for ((round=1; round<=ROUNDS; round++)); do
    echo "── Round ${round}/${ROUNDS} ──────────────────────────────────────────────"

    # Shuffle users each round for variety
    SHUFFLED_USERS=("${USERS[@]}")
    for ((i=${#SHUFFLED_USERS[@]}-1; i>0; i--)); do
        j=$((RANDOM % (i+1)))
        tmp="${SHUFFLED_USERS[$i]}"
        SHUFFLED_USERS[$i]="${SHUFFLED_USERS[$j]}"
        SHUFFLED_USERS[$j]="$tmp"
    done

    for user in "${SHUFFLED_USERS[@]}"; do
        for host in "${HOSTNAME_ARR[@]}"; do
            reason=$(random_reason)
            result=$(create_challenge "$user" "$host" "$reason")
            id="${result%%:*}"
            status="${result##*:}"
            total=$((total+1))

            if [ "$status" = "approved" ] || [ "$status" = "auto_approved" ]; then
                auto_count=$((auto_count+1))
                printf "  ✓ auto  %-12s  %-22s  %s\n" "$user" "$host" "${id:0:8}"
            elif [ -z "$id" ] || [ "$status" = "error" ]; then
                failed_count=$((failed_count+1))
                printf "  ✗ fail  %-12s  %-22s\n" "$user" "$host"
            else
                # Decide approve vs reject based on ratio
                rand=$(python3 -c "import random; print('approve' if random.random() < ${APPROVE_RATIO} else 'reject')")
                if [ "$rand" = "approve" ]; then
                    outcome=$(approve_challenge "$id")
                    if [[ "$outcome" == "approved" ]]; then
                        approved_count=$((approved_count+1))
                        printf "  ✓ appr  %-12s  %-22s  %s\n" "$user" "$host" "${id:0:8}"
                    else
                        failed_count=$((failed_count+1))
                        printf "  ✗ err   %-12s  %-22s  %s %s\n" "$user" "$host" "${id:0:8}" "$outcome"
                    fi
                else
                    outcome=$(reject_challenge "$id")
                    if [[ "$outcome" == "rejected" ]]; then
                        rejected_count=$((rejected_count+1))
                        printf "  ✗ rej   %-12s  %-22s  %s\n" "$user" "$host" "${id:0:8}"
                    else
                        failed_count=$((failed_count+1))
                        printf "  ✗ err   %-12s  %-22s  %s %s\n" "$user" "$host" "${id:0:8}" "$outcome"
                    fi
                fi
                sleep "$DELAY"
            fi
        done
    done
    echo ""
done

# ── Cleanup ────────────────────────────────────────────────────────────────────

[ -f "${COOKIE_JAR:-}" ] && rm -f "$COOKIE_JAR"

# ── Validate via getent ────────────────────────────────────────────────────────

echo "==> Validating LDAP/SSSD resolution on host containers..."
case "$STACK" in
    full-mode)
        VALIDATE_CONTAINER="integ-full-ubuntu2204"
        ;;
    lldap-dex)
        VALIDATE_CONTAINER="integ-lldap-dex-ubuntu2204"
        ;;
    vault-escrow)
        VALIDATE_CONTAINER="integ-vault-ubuntu2204"
        ;;
esac

if docker inspect "$VALIDATE_CONTAINER" >/dev/null 2>&1; then
    echo "    getent passwd alice:"
    docker exec "$VALIDATE_CONTAINER" getent passwd alice 2>&1 | sed 's/^/      /' || echo "      (not found)"
    echo "    getent group developers:"
    docker exec "$VALIDATE_CONTAINER" getent group developers 2>&1 | sed 's/^/      /' || echo "      (not found)"
    echo "    getent passwd sam:"
    docker exec "$VALIDATE_CONTAINER" getent passwd sam 2>&1 | sed 's/^/      /' || echo "      (not found)"
else
    echo "    (container ${VALIDATE_CONTAINER} not running — skipping getent validation)"
fi

# ── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Suite complete: ${STACK}"
echo ""
echo "  Total challenges:    ${total}"
echo "  Auto-approved:       ${auto_count}   (within grace period)"
echo "  Manually approved:   ${approved_count}"
echo "  Rejected:            ${rejected_count}"
echo "  Errors/failed:       ${failed_count}"
echo ""
echo "  identree dashboard:  ${IDENTREE_URL}"
echo "═══════════════════════════════════════════════════════════════"
