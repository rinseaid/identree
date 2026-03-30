#!/bin/bash
# validate.sh — smoke-test the Infisical escrow test environment.
#
# Usage:
#   ./validate.sh
#
# Exit code: 0 = all checks passed, 1 = one or more checks failed.
set -euo pipefail

INFISICAL_URL="${INFISICAL_URL:-http://localhost:8095}"
CLIENT="identree-infisical-escrow-client"
IDENTREE_URL="http://localhost:8096"
OIDC_ISSUER="http://localhost:5558/dex"
LDAP_URI="ldap://localhost:3894"
HOSTNAME_UNDER_TEST="infisical-escrow-test-host"
SECRET_NAME="BREAKGLASS_$(echo "${HOSTNAME_UNDER_TEST}" | tr '[:lower:]-' '[:upper:]_')"

PASS=0
FAIL=0

check() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS  ${name}"
        PASS=$((PASS+1))
    else
        echo "  FAIL  ${name}"
        FAIL=$((FAIL+1))
    fi
}

check_output() {
    local name="$1" expected="$2"; shift 2
    local out
    out=$("$@" 2>/dev/null || true)
    if printf '%s' "$out" | grep -qF "$expected"; then
        echo "  PASS  ${name}"
        PASS=$((PASS+1))
    else
        echo "  FAIL  ${name}  (got: ${out:0:80})"
        FAIL=$((FAIL+1))
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Infisical escrow validation"
echo "  client:    ${CLIENT}"
echo "  identree:  ${IDENTREE_URL}"
echo "  infisical: ${INFISICAL_URL}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Service health ──────────────────────────────────────────────────────────
check "identree /healthz"           curl -sf "${IDENTREE_URL}/healthz"
check "OIDC discovery reachable"    curl -sf "${OIDC_ISSUER}/.well-known/openid-configuration"
check "Infisical /api/status"       curl -sf "${INFISICAL_URL}/api/status"

# ── 2. LDAP / NSS ─────────────────────────────────────────────────────────────
check "LDAP port reachable from testclient" \
    docker exec "${CLIENT}" bash -c "echo > /dev/tcp/lldap/3890 2>/dev/null"

check_output "getent passwd alice"     "alice"     docker exec "${CLIENT}" getent passwd alice
check_output "getent passwd bob"       "bob"       docker exec "${CLIENT}" getent passwd bob
check_output "getent passwd testadmin" "testadmin" docker exec "${CLIENT}" getent passwd testadmin

check_output "getent group developers" "developers" docker exec "${CLIENT}" getent group developers
check_output "getent group admins"     "admins"     docker exec "${CLIENT}" getent group admins
check_output "alice in developers"     "alice"      docker exec "${CLIENT}" getent group developers
check_output "testadmin in admins"     "testadmin"  docker exec "${CLIENT}" getent group admins

# ── 3. PAM / identree client ──────────────────────────────────────────────────
check_output "PAM sudo uses identree" "identree" \
    docker exec "${CLIENT}" cat /etc/pam.d/sudo

check "identree client.conf exists" \
    docker exec "${CLIENT}" test -f /etc/identree/client.conf

check "static sudoers file exists" \
    docker exec "${CLIENT}" test -f /etc/sudoers.d/identree-test

# ── 4. Break-glass + Infisical escrow ─────────────────────────────────────────
check "break-glass hash file exists" \
    docker exec "${CLIENT}" test -f /etc/identree-breakglass

# Verify identree can reach Infisical internally
check "Infisical reachable from identree" \
    docker exec identree-infisical-escrow-server \
    sh -c "wget -q -O- http://infisical:8080/api/status >/dev/null"

# Verify identree escrow config has been set (env vars present)
echo ""
echo "  Checking identree escrow configuration..."
ESCROW_BACKEND=$(docker exec identree-infisical-escrow-server \
    sh -c "env | grep IDENTREE_ESCROW_BACKEND" 2>/dev/null | cut -d= -f2 || echo "")
ESCROW_AUTH_ID=$(docker exec identree-infisical-escrow-server \
    sh -c "env | grep IDENTREE_ESCROW_AUTH_ID" 2>/dev/null | cut -d= -f2 || echo "")
ESCROW_PATH=$(docker exec identree-infisical-escrow-server \
    sh -c "env | grep IDENTREE_ESCROW_PATH" 2>/dev/null | cut -d= -f2 || echo "")

if [ "$ESCROW_BACKEND" = "infisical" ]; then
    echo "  PASS  IDENTREE_ESCROW_BACKEND=infisical"
    PASS=$((PASS+1))
else
    echo "  FAIL  IDENTREE_ESCROW_BACKEND not set to infisical (got: '${ESCROW_BACKEND}')"
    FAIL=$((FAIL+1))
fi

if [ -n "$ESCROW_AUTH_ID" ]; then
    echo "  PASS  IDENTREE_ESCROW_AUTH_ID is set"
    PASS=$((PASS+1))
else
    echo "  FAIL  IDENTREE_ESCROW_AUTH_ID is empty — run setup.sh first"
    FAIL=$((FAIL+1))
fi

if [ -n "$ESCROW_PATH" ]; then
    echo "  PASS  IDENTREE_ESCROW_PATH=${ESCROW_PATH}"
    PASS=$((PASS+1))
else
    echo "  FAIL  IDENTREE_ESCROW_PATH is empty — run setup.sh first"
    FAIL=$((FAIL+1))
fi

# Check break-glass secret is visible in Infisical (via UI note — no direct API check
# without the client credentials, which vary per run). We check the identree log instead.
echo ""
echo "  Checking for Infisical escrow activity in identree logs..."
if docker logs identree-infisical-escrow-server 2>&1 | grep -qi "escrow\|breakglass\|infisical"; then
    echo "  PASS  identree logs contain escrow/infisical references"
    PASS=$((PASS+1))
else
    echo "  SKIP  No escrow log entries yet (may appear after first sudo challenge)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ${PASS} passed  /  ${FAIL} failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  To verify the secret in Infisical UI:"
echo "    http://localhost:8095 → Project 'identree-test' → Secrets → prod"
echo "    Look for: ${SECRET_NAME}"

[ "$FAIL" -eq 0 ]
