#!/bin/bash
# setup.sh — provision mTLS client credentials for the testclient.
#
# Run after: make test-mtls
#
# What this does:
#   1. Waits for identree to be healthy
#   2. Calls the provision endpoint with shared secret to get client cert + key + CA cert
#   3. Copies the certs into the testclient container
#   4. Reconfigures the client to use mTLS (HTTPS + client cert, no shared secret)
set -euo pipefail

CLIENT="identree-mtls-client"
SERVER="identree-mtls-server"
# Use the Docker-internal HTTPS URL for provisioning from the host via port-forward
IDENTREE_HOST_URL="https://localhost:8094"
SHARED_SECRET="mtls-test-shared-secret-1234567890abc"
HOSTNAME="mtls-test-host-01"

# ── Helpers ──────────────────────────────────────────────────────────────────

wait_for() {
    local url="$1" name="$2"
    echo "==> Waiting for ${name}..."
    for i in $(seq 1 30); do
        if curl -skf "$url" >/dev/null 2>&1; then
            echo "    ${name} ready."
            return 0
        fi
        sleep 2
    done
    echo "    TIMEOUT waiting for ${name}"
    return 1
}

# ── Wait for identree ────────────────────────────────────────────────────────
wait_for "${IDENTREE_HOST_URL}/healthz" "identree (HTTPS)"

# ── Provision: get client cert via shared secret ─────────────────────────────
echo "==> Provisioning mTLS client credentials for ${HOSTNAME}..."

PROV_JSON=$(curl -sk \
    -H "X-Shared-Secret: ${SHARED_SECRET}" \
    -H "X-Hostname: ${HOSTNAME}" \
    "${IDENTREE_HOST_URL}/api/client/provision")

# Validate response has mTLS fields
if ! echo "$PROV_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('client_cert'), 'no client_cert'" 2>/dev/null; then
    echo "ERROR: provision response missing client_cert"
    echo "Response: ${PROV_JSON:0:500}"
    exit 1
fi

echo "    Provision response received with mTLS credentials."

# ── Extract certs from JSON ──────────────────────────────────────────────────
echo "==> Extracting certificates..."

CLIENT_CERT=$(echo "$PROV_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_cert'])")
CLIENT_KEY=$(echo "$PROV_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_key'])")
CA_CERT=$(echo "$PROV_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['ca_cert'])")

# Also extract the server's TLS cert for CA trust (self-signed server cert)
# We'll grab it from the identree-config volume via the server container
SERVER_TLS_CERT=$(docker exec "$SERVER" cat /config/server.crt)

echo "    client_cert: $(echo "$CLIENT_CERT" | head -1)"
echo "    client_key:  $(echo "$CLIENT_KEY" | head -1)"
echo "    ca_cert:     $(echo "$CA_CERT" | head -1)"

# ── Write certs into testclient container ────────────────────────────────────
echo "==> Installing certificates in testclient..."

docker exec "$CLIENT" mkdir -p /etc/identree

# Write cert files (use -i flag with docker exec so stdin is passed through)
echo "$CLIENT_CERT" | docker exec -i "$CLIENT" tee /etc/identree/client.crt > /dev/null
echo "$CLIENT_KEY" | docker exec -i "$CLIENT" tee /etc/identree/client.key > /dev/null
echo "$CA_CERT" | docker exec -i "$CLIENT" tee /etc/identree/ca.crt > /dev/null
# Combined CA bundle: server TLS cert + mTLS CA (for trusting the server)
printf '%s\n%s\n' "$SERVER_TLS_CERT" "$CA_CERT" | docker exec -i "$CLIENT" tee /etc/identree/server-ca.crt > /dev/null

docker exec "$CLIENT" chmod 600 /etc/identree/client.key
docker exec "$CLIENT" chmod 644 /etc/identree/client.crt /etc/identree/ca.crt /etc/identree/server-ca.crt

echo "    Certificates installed."

# ── Reconfigure client to use mTLS ───────────────────────────────────────────
echo "==> Reconfiguring client for mTLS authentication..."

# Write new client.conf that uses HTTPS + client cert, NO shared secret
docker exec -i "$CLIENT" tee /etc/identree/client.conf > /dev/null <<'CONF'
IDENTREE_SERVER_URL=https://identree:8090
IDENTREE_CLIENT_CERT=/etc/identree/client.crt
IDENTREE_CLIENT_KEY=/etc/identree/client.key
IDENTREE_CA_CERT=/etc/identree/server-ca.crt
IDENTREE_INSECURE_ALLOW_HTTP_ESCROW=false
IDENTREE_TOKEN_CACHE_ENABLED=false
IDENTREE_BREAKGLASS_ENABLED=true
IDENTREE_BREAKGLASS_FILE=/etc/identree-breakglass
CONF

docker exec "$CLIENT" chmod 600 /etc/identree/client.conf

echo "    Client reconfigured for mTLS."

# ── Verify the client cert ───────────────────────────────────────────────────
echo "==> Verifying mTLS client cert..."
CERT_CN=$(echo "$CLIENT_CERT" | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN = //' || echo "unknown")
CERT_EXPIRY=$(echo "$CLIENT_CERT" | openssl x509 -noout -enddate 2>/dev/null | sed 's/.*=//' || echo "unknown")
echo "    CN: ${CERT_CN}"
echo "    Expires: ${CERT_EXPIRY}"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  mTLS test environment provisioned"
echo ""
echo "  Services:"
echo "    PocketID:   http://localhost:1415"
echo "    identree:   https://localhost:8094  (self-signed TLS)"
echo "    LDAP:       ldap://localhost:3394   base=dc=test,dc=local"
echo ""
echo "  mTLS credentials (in testclient: ${CLIENT}):"
echo "    client cert: /etc/identree/client.crt  (CN=${CERT_CN})"
echo "    client key:  /etc/identree/client.key"
echo "    CA cert:     /etc/identree/ca.crt"
echo "    server CA:   /etc/identree/server-ca.crt"
echo ""
echo "  Validate:"
echo "    make test-mtls-validate"
echo "================================================================"
