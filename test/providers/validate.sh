#!/bin/bash
# validate.sh — smoke-test an identree provider test environment.
#
# Usage:
#   ./validate.sh <testclient-container> <identree-url> <oidc-issuer-public-url> [ldap-uri]
#
# Examples:
#   ./validate.sh identree-lldap-dex-client  http://localhost:8091 http://localhost:5556/dex        ldap://localhost:3891
#   ./validate.sh identree-keycloak-client   http://localhost:8092 http://localhost:8180/realms/identree-test ldap://localhost:3892
#   ./validate.sh identree-kanidm-client     http://localhost:8093 http://localhost:8443/oauth2/openid/identree-test ldap://localhost:3636
#
# Exit code: 0 = all checks passed, 1 = one or more checks failed.
#
# Checks performed (no human interaction required):
#   1. identree /healthz returns 200
#   2. OIDC discovery endpoint (.well-known/openid-configuration) is reachable
#   3. testclient container: getent passwd resolves test users
#   4. testclient container: getent group resolves test groups
#   5. testclient container: PAM config for sudo references identree
#   6. testclient container: identree-breakglass file exists (break-glass provisioned)
set -euo pipefail

CLIENT="${1:?Usage: $0 <testclient-container> <identree-url> <oidc-issuer-url> [ldap-uri]}"
IDENTREE_URL="${2:?}"
OIDC_ISSUER="${3:?}"
LDAP_URI="${4:-}"

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
echo "  Provider validation"
echo "  client:  ${CLIENT}"
echo "  identree: ${IDENTREE_URL}"
echo "  OIDC:    ${OIDC_ISSUER}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. identree health ─────────────────────────────────────────────────────────
check "identree /healthz" curl -sf "${IDENTREE_URL}/healthz"

# ── 2. OIDC discovery ─────────────────────────────────────────────────────────
# The discovery URL format varies by provider:
#   Dex:      <issuer>/.well-known/openid-configuration
#   Keycloak: <issuer>/.well-known/openid-configuration
#   Kanidm:   <issuer>/.well-known/openid-configuration
check "OIDC discovery endpoint reachable" \
    curl -sf "${OIDC_ISSUER}/.well-known/openid-configuration"

check_output "OIDC issuer field matches" \
    "\"issuer\"" \
    curl -sf "${OIDC_ISSUER}/.well-known/openid-configuration"

# ── 3. LDAP connectivity (if URI given) ────────────────────────────────────────
# Uses bash /dev/tcp for pure TCP check (works without nc).
# Tries both the given host and host.docker.internal (macOS Docker Desktop
# maps 127.0.0.1-bound host ports via that alias).
if [ -n "$LDAP_URI" ]; then
    LDAP_PORT=$(echo "${LDAP_URI}" | sed 's|ldap://||' | cut -d: -f2)
    LDAP_HOST=$(echo "${LDAP_URI}" | sed 's|ldap://||' | cut -d: -f1)
    check "LDAP port reachable from testclient" \
        docker exec "${CLIENT}" \
        bash -c "echo > /dev/tcp/${LDAP_HOST}/${LDAP_PORT} 2>/dev/null || echo > /dev/tcp/host.docker.internal/${LDAP_PORT} 2>/dev/null"
fi

# ── 4. NSS user resolution ────────────────────────────────────────────────────
check_output "getent passwd alice"     "alice"     docker exec "${CLIENT}" getent passwd alice
check_output "getent passwd bob"       "bob"       docker exec "${CLIENT}" getent passwd bob
check_output "getent passwd testadmin" "testadmin" docker exec "${CLIENT}" getent passwd testadmin

# ── 5. NSS group resolution ───────────────────────────────────────────────────
check_output "getent group developers" "developers" docker exec "${CLIENT}" getent group developers
check_output "getent group admins"     "admins"     docker exec "${CLIENT}" getent group admins

# ── 6. Group membership ───────────────────────────────────────────────────────
check_output "alice in developers"     "alice"     docker exec "${CLIENT}" getent group developers
check_output "bob in developers"       "bob"       docker exec "${CLIENT}" getent group developers
check_output "testadmin in admins"     "testadmin" docker exec "${CLIENT}" getent group admins

# ── 7. PAM configuration ──────────────────────────────────────────────────────
check_output "PAM sudo uses identree" "identree" \
    docker exec "${CLIENT}" cat /etc/pam.d/sudo

# ── 8. Break-glass provisioned ────────────────────────────────────────────────
check "break-glass hash file exists" \
    docker exec "${CLIENT}" test -f /etc/identree-breakglass

# ── 9. identree client config ─────────────────────────────────────────────────
check "identree client.conf exists" \
    docker exec "${CLIENT}" test -f /etc/identree/client.conf

# ── 10. Static sudoers (bridge mode) ─────────────────────────────────────────
check "static sudoers file exists" \
    docker exec "${CLIENT}" test -f /etc/sudoers.d/identree-test

# ── Summary ───────────────────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ${PASS} passed  /  ${FAIL} failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Note: the PAM challenge/approval flow (sudo → identree → browser approve)
# requires a human in the loop and is not validated here.
# To test manually: docker exec -it <testclient> bash  →  sudo whoami

[ "$FAIL" -eq 0 ]
