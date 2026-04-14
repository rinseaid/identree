#!/bin/bash
# validate.sh — validate the mTLS test environment.
#
# Tests:
#   1. identree /healthz reachable over HTTPS
#   2. provision endpoint returns mTLS cert fields
#   3. mTLS auth: create challenge using client cert (no shared secret)
#   4. mTLS auth: poll challenge using client cert (no shared secret)
#   5. challenge hostname matches cert CN
#   6. shared-secret-only request is rejected when mTLS expects cert
set -euo pipefail

CLIENT="identree-mtls-client"
IDENTREE_HOST_URL="https://localhost:8094"
SHARED_SECRET="mtls-test-shared-secret-1234567890abc"
HOSTNAME="mtls-test-host-01"

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
        echo "  FAIL  ${name}  (expected '${expected}', got: ${out:0:200})"
        FAIL=$((FAIL+1))
    fi
}

echo "================================================================"
echo "  mTLS validation"
echo "  identree: ${IDENTREE_HOST_URL}"
echo "  client:   ${CLIENT}"
echo "================================================================"

# ── 1. Health check over HTTPS ───────────────────────────────────────────────
check "identree /healthz (HTTPS)" curl -skf "${IDENTREE_HOST_URL}/healthz"

# ── 2. Provision endpoint returns mTLS fields ────────────────────────────────
PROV_JSON=$(curl -sk \
    -H "X-Shared-Secret: ${SHARED_SECRET}" \
    -H "X-Hostname: ${HOSTNAME}" \
    "${IDENTREE_HOST_URL}/api/client/provision" 2>/dev/null || echo "{}")

check_output "provision returns client_cert" "BEGIN CERTIFICATE" \
    echo "$PROV_JSON"

check_output "provision returns client_key" "BEGIN EC PRIVATE KEY" \
    echo "$PROV_JSON"

check_output "provision returns ca_cert" "ca_cert" \
    echo "$PROV_JSON"

# ── 3. Create challenge using mTLS (from inside testclient) ─────────────────
# The testclient has the client cert installed by setup.sh.
# Use curl with --cert/--key/--cacert to authenticate via mTLS.
echo ""
echo "  -- mTLS challenge flow --"

# Create a challenge using mTLS client cert (NO shared secret header)
CHALLENGE_JSON=$(docker exec "$CLIENT" curl -s \
    --cert /etc/identree/client.crt \
    --key /etc/identree/client.key \
    --cacert /etc/identree/server-ca.crt \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"hostname\":\"${HOSTNAME}\",\"username\":\"testuser\",\"tty\":\"pts/0\",\"pam_service\":\"sudo\"}" \
    "https://identree:8090/api/challenge" 2>/dev/null || echo "{}")

# Check if we got a challenge ID back
CHALLENGE_ID=$(echo "$CHALLENGE_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('challenge_id','') or d.get('id',''))" 2>/dev/null || echo "")

if [ -n "$CHALLENGE_ID" ] && [ "$CHALLENGE_ID" != "null" ]; then
    echo "  PASS  mTLS challenge creation (id=${CHALLENGE_ID:0:16}...)"
    PASS=$((PASS+1))
else
    echo "  FAIL  mTLS challenge creation (response: ${CHALLENGE_JSON:0:200})"
    FAIL=$((FAIL+1))
fi

# ── 4. Poll challenge using mTLS ────────────────────────────────────────────
if [ -n "$CHALLENGE_ID" ] && [ "$CHALLENGE_ID" != "null" ]; then
    POLL_JSON=$(docker exec "$CLIENT" curl -s \
        --cert /etc/identree/client.crt \
        --key /etc/identree/client.key \
        --cacert /etc/identree/server-ca.crt \
        "https://identree:8090/api/challenge/${CHALLENGE_ID}?hostname=${HOSTNAME}" 2>/dev/null || echo "{}")

    POLL_STATUS=$(echo "$POLL_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")

    if [ "$POLL_STATUS" = "pending" ]; then
        echo "  PASS  mTLS poll returns pending status"
        PASS=$((PASS+1))
    else
        echo "  FAIL  mTLS poll (expected 'pending', got: ${POLL_JSON:0:200})"
        FAIL=$((FAIL+1))
    fi
else
    echo "  SKIP  mTLS poll (no challenge ID)"
fi

# ── 5. Verify cert CN overrides query hostname ───────────────────────────────
# When mTLS is active, the server uses the cert CN as the authoritative
# hostname, ignoring the query string. A poll with hostname=wrong-host-99
# should STILL succeed because the cert CN (mtls-test-host-01) matches.
if [ -n "$CHALLENGE_ID" ] && [ "$CHALLENGE_ID" != "null" ]; then
    OVERRIDE_CODE=$(docker exec "$CLIENT" curl -s -o /dev/null -w '%{http_code}' \
        --cert /etc/identree/client.crt \
        --key /etc/identree/client.key \
        --cacert /etc/identree/server-ca.crt \
        "https://identree:8090/api/challenge/${CHALLENGE_ID}?hostname=wrong-host-99" 2>/dev/null || echo "000")

    if [ "$OVERRIDE_CODE" = "200" ]; then
        echo "  PASS  cert CN overrides query hostname (HTTP 200 — cert CN authoritative)"
        PASS=$((PASS+1))
    else
        echo "  FAIL  cert CN override (expected 200, got ${OVERRIDE_CODE})"
        FAIL=$((FAIL+1))
    fi
else
    echo "  SKIP  hostname override check (no challenge ID)"
fi

# ── 6. Request WITHOUT client cert is rejected ──────────────────────────────
# When mTLS is enabled, the server requires a valid client cert for API endpoints.
# A request with only shared secret (no cert) should be rejected.
NO_CERT_RESP=$(docker exec "$CLIENT" curl -s -o /dev/null -w '%{http_code}' \
    --cacert /etc/identree/server-ca.crt \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Shared-Secret: ${SHARED_SECRET}" \
    -d "{\"hostname\":\"${HOSTNAME}\",\"username\":\"testuser\",\"tty\":\"pts/0\",\"pam_service\":\"sudo\"}" \
    "https://identree:8090/api/challenge" 2>/dev/null || echo "000")

if [ "$NO_CERT_RESP" = "401" ]; then
    echo "  PASS  no-cert request rejected (HTTP 401)"
    PASS=$((PASS+1))
else
    echo "  FAIL  no-cert request not rejected (expected 401, got ${NO_CERT_RESP})"
    FAIL=$((FAIL+1))
fi

# ── 7. Client config uses mTLS ──────────────────────────────────────────────
check_output "client.conf has IDENTREE_CLIENT_CERT" "IDENTREE_CLIENT_CERT" \
    docker exec "$CLIENT" cat /etc/identree/client.conf

check_output "client.conf has IDENTREE_CA_CERT" "IDENTREE_CA_CERT" \
    docker exec "$CLIENT" cat /etc/identree/client.conf

check_output "client.conf uses HTTPS" "https://" \
    docker exec "$CLIENT" cat /etc/identree/client.conf

# ── 8. Client cert files exist ───────────────────────────────────────────────
check "client cert file exists" \
    docker exec "$CLIENT" test -f /etc/identree/client.crt

check "client key file exists" \
    docker exec "$CLIENT" test -f /etc/identree/client.key

check "CA cert file exists" \
    docker exec "$CLIENT" test -f /etc/identree/ca.crt

# ── 9. LDAPS connectivity with mTLS client cert ─────────────────────────────
echo ""
echo "  -- LDAPS/mTLS --"

# Test LDAPS search using the client certificate (from inside testclient).
# The testclient has openldap-utils (ldapsearch) and the client cert installed.
# Use LDAPTLS_CERT/KEY/CACERT to pass the mTLS client cert to ldapsearch.
LDAPS_SEARCH_RC=$(docker exec "$CLIENT" bash -c '
    LDAPTLS_CERT=/etc/identree/client.crt \
    LDAPTLS_KEY=/etc/identree/client.key \
    LDAPTLS_CACERT=/etc/identree/server-ca.crt \
    ldapsearch -x \
        -H ldaps://identree:3636 \
        -D "uid=mtls-test-host-01,ou=identree-hosts,dc=test,dc=local" \
        -w unused \
        -b "dc=test,dc=local" \
        -s base "(objectClass=*)" dn 2>&1
' && echo "OK" || echo "FAIL")

if echo "$LDAPS_SEARCH_RC" | grep -q "OK\|dn:"; then
    echo "  PASS  LDAPS search with mTLS client cert"
    PASS=$((PASS+1))
else
    echo "  FAIL  LDAPS search with mTLS client cert (output: ${LDAPS_SEARCH_RC:0:200})"
    FAIL=$((FAIL+1))
fi

# ── 10. LDAPS rejects connections without client cert ────────────────────────
LDAPS_NOCERT_RC=$(docker exec "$CLIENT" bash -c '
    LDAPTLS_CACERT=/etc/identree/server-ca.crt \
    LDAPTLS_REQCERT=allow \
    ldapsearch -x \
        -H ldaps://identree:3636 \
        -D "uid=mtls-test-host-01,ou=identree-hosts,dc=test,dc=local" \
        -w unused \
        -b "dc=test,dc=local" \
        -s base "(objectClass=*)" dn 2>&1
' && echo "OK" || echo "FAIL")

if echo "$LDAPS_NOCERT_RC" | grep -qiE "FAIL|error|Can.t contact"; then
    echo "  PASS  LDAPS rejects connection without client cert"
    PASS=$((PASS+1))
else
    echo "  FAIL  LDAPS should reject no-cert connection (output: ${LDAPS_NOCERT_RC:0:200})"
    FAIL=$((FAIL+1))
fi

# ── 11. Provision returns ldaps:// URL ──────────────────────────────────────
check_output "provision returns ldaps:// URL" "ldaps://" \
    echo "$PROV_JSON"

# ── Summary ──────────────────────────────────────────────────────────────────
echo "================================================================"
echo "  ${PASS} passed  /  ${FAIL} failed"
echo "================================================================"

[ "$FAIL" -eq 0 ]
