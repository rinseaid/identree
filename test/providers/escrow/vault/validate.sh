#!/bin/bash
# validate.sh — smoke-test the Vault escrow test environment.
#
# Usage:
#   ./validate.sh [--vault-addr <url>]
#
# Exit code: 0 = all checks passed, 1 = one or more checks failed.
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="identree-vault-test-token"

CLIENT="identree-vault-escrow-client"
IDENTREE_URL="http://localhost:8094"
OIDC_ISSUER="http://localhost:5557/dex"
LDAP_URI="ldap://localhost:3893"
HOSTNAME_UNDER_TEST="vault-escrow-test-host"

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
echo "  Vault escrow validation"
echo "  client:   ${CLIENT}"
echo "  identree: ${IDENTREE_URL}"
echo "  vault:    ${VAULT_ADDR}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Service health ──────────────────────────────────────────────────────────
check "identree /healthz"        curl -sf "${IDENTREE_URL}/healthz"
check "OIDC discovery reachable" curl -sf "${OIDC_ISSUER}/.well-known/openid-configuration"
check "Vault /v1/sys/health"     curl -sf "${VAULT_ADDR}/v1/sys/health"

check_output "Vault initialized+unsealed" '"initialized":true' \
    curl -sf "${VAULT_ADDR}/v1/sys/health"

# ── 2. LDAP / NSS ─────────────────────────────────────────────────────────────
check "LDAP port reachable from testclient" \
    docker exec "${CLIENT}" \
    sh -c "echo > /dev/tcp/lldap/3890 2>/dev/null"

check_output "getent passwd alice"     "alice"     docker exec "${CLIENT}" getent passwd alice
check_output "getent passwd bob"       "bob"       docker exec "${CLIENT}" getent passwd bob
check_output "getent passwd testadmin" "testadmin" docker exec "${CLIENT}" getent passwd testadmin

check_output "getent group developers" "developers" docker exec "${CLIENT}" getent group developers
check_output "getent group admins"     "admins"     docker exec "${CLIENT}" getent group admins
check_output "alice in developers"     "developers" docker exec "${CLIENT}" id alice
check_output "testadmin in admins"     "admins"     docker exec "${CLIENT}" id testadmin

# ── 3. PAM / identree client ──────────────────────────────────────────────────
check_output "PAM sudo uses identree" "identree" \
    docker exec "${CLIENT}" cat /etc/pam.d/sudo

check "identree client.conf exists" \
    docker exec "${CLIENT}" test -f /etc/identree/client.conf

check "static sudoers file exists" \
    docker exec "${CLIENT}" test -f /etc/sudoers.d/identree-test

# ── 4. Break-glass + Vault escrow ─────────────────────────────────────────────
check "break-glass hash file exists" \
    docker exec "${CLIENT}" test -f /etc/identree-breakglass

# Verify identree can reach Vault — try reading the secret/ mount list
check "Vault secret/ mount accessible from identree" \
    docker exec identree-vault-escrow-server \
    sh -c "wget -q -O- --header='X-Vault-Token: ${VAULT_TOKEN}' http://vault:8200/v1/sys/mounts >/dev/null"

# If a break-glass secret has been written (after rotate-breakglass runs at startup),
# verify it is retrievable from Vault via the host API.
VAULT_SECRET_PATH="secret/data/identree/${HOSTNAME_UNDER_TEST}"
echo ""
echo "  Checking for break-glass secret in Vault..."
VAULT_RESP=$(curl -sf "${VAULT_ADDR}/v1/${VAULT_SECRET_PATH}" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" 2>/dev/null || echo "")

if printf '%s' "$VAULT_RESP" | grep -q '"password"'; then
    echo "  PASS  break-glass secret found in Vault at ${VAULT_SECRET_PATH}"
    PASS=$((PASS+1))
else
    echo "  SKIP  break-glass secret not yet in Vault (run: docker exec identree-vault-escrow-server identree rotate-breakglass)"
    # Not a hard failure — the secret is written on first rotate-breakglass call,
    # which the entrypoint runs only if /etc/identree-breakglass doesn't exist yet.
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ${PASS} passed  /  ${FAIL} failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[ "$FAIL" -eq 0 ]
