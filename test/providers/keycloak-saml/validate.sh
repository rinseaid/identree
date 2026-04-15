#!/bin/bash
# validate.sh — verify the Keycloak SAML test environment is working.
# Checks:
#   1. identree healthz is up
#   2. SAML SP metadata is served at /saml/metadata
#   3. /saml/login redirects to Keycloak (302 to IdP SSO URL)
#   4. /sessions/login redirects to /saml/login in SAML mode
#   5. PAM challenge flow works (shared secret auth)
set -euo pipefail

IDENTREE_URL="${IDENTREE_URL:-http://localhost:8101}"
SHARED_SECRET="${SHARED_SECRET:-test-shared-secret-keycloak-saml-12345}"
CLIENT_CONTAINER="${CLIENT_CONTAINER:-identree-keycloak-saml-client}"

passed=0
failed=0

pass() { echo "  PASS: $1"; passed=$((passed+1)); }
fail() { echo "  FAIL: $1"; failed=$((failed+1)); }

echo "==> Validating Keycloak SAML test environment"
echo ""

# 1. healthz
echo "--- healthz ---"
if curl -sf "${IDENTREE_URL}/healthz" >/dev/null 2>&1; then
    pass "healthz returns 200"
else
    fail "healthz not reachable"
fi

# 2. SAML SP metadata
echo "--- SAML SP metadata ---"
METADATA=$(curl -sf "${IDENTREE_URL}/saml/metadata" 2>/dev/null || echo "")
if echo "$METADATA" | grep -q "EntityDescriptor"; then
    pass "SP metadata contains EntityDescriptor"
else
    fail "SP metadata missing or invalid"
fi
if echo "$METADATA" | grep -q "AssertionConsumerService"; then
    pass "SP metadata contains ACS endpoint"
else
    fail "SP metadata missing ACS endpoint"
fi

# 3. /saml/login redirects to IdP
echo "--- SAML login redirect ---"
LOGIN_RESP=$(curl -si "${IDENTREE_URL}/saml/login" 2>/dev/null || echo "")
if echo "$LOGIN_RESP" | grep -qi "302\|location:"; then
    pass "/saml/login returns redirect"
else
    fail "/saml/login does not redirect"
fi
if echo "$LOGIN_RESP" | grep -qi "SAMLRequest"; then
    pass "Redirect contains SAMLRequest parameter"
else
    fail "Redirect missing SAMLRequest parameter"
fi

# 4. /sessions/login redirects to /saml/login in SAML mode
echo "--- sessions/login redirect ---"
SESSIONS_RESP=$(curl -si "${IDENTREE_URL}/sessions/login" 2>/dev/null || echo "")
if echo "$SESSIONS_RESP" | grep -qi "saml/login"; then
    pass "/sessions/login redirects to /saml/login"
else
    fail "/sessions/login does not redirect to SAML"
fi

# 5. PAM challenge flow
echo "--- PAM challenge flow ---"
CHALLENGE_RESP=$(curl -sf -X POST "${IDENTREE_URL}/api/challenge" \
    -H "Content-Type: application/json" \
    -H "X-Shared-Secret: ${SHARED_SECRET}" \
    -d '{"username":"alice","hostname":"keycloak-saml-test-host"}' 2>/dev/null || echo "")
if echo "$CHALLENGE_RESP" | grep -q '"challenge_id"'; then
    pass "PAM challenge created successfully"
else
    fail "PAM challenge creation failed: ${CHALLENGE_RESP}"
fi

echo ""
echo "==> Results: ${passed} passed, ${failed} failed"
[ "$failed" -eq 0 ] || exit 1
