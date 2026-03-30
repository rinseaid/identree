#!/bin/bash
# setup.sh — configure lldap users and verify Vault for the vault-escrow test environment.
# Run after: make test-vault-escrow
#
# What this does:
#   1. Creates POSIX custom attributes in lldap (uidNumber, gidNumber, homeDirectory, loginShell)
#   2. Creates test users (alice, bob, testadmin) with POSIX attributes
#   3. Sets user passwords (via LDAP Password Modify so Dex can authenticate them)
#   4. Creates groups (developers, admins) with gidNumber
#   5. Assigns group membership
#   6. Verifies Vault is accessible and KV v2 secret/ mount is ready
#
# Requirements on host: curl, python3, docker
set -euo pipefail

LLDAP_URL="${LLDAP_URL:-http://localhost:17173}"
# ldappasswd runs inside the testclient container via docker exec, so the URI
# must use the Docker-internal service name, not the host-side port binding.
LLDAP_LDAP_INTERNAL_URI="ldap://lldap:3890"
LLDAP_ADMIN_USER="admin"
LLDAP_ADMIN_PASS="lldap-admin-pass"
LDAP_BASE="dc=test,dc=local"
CLIENT="identree-vault-escrow-client"  # testclient container (has ldap-utils)

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="identree-vault-test-token"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() {
    local url="$1" name="$2"
    echo "==> Waiting for ${name}..."
    until curl -sf "$url" >/dev/null 2>&1; do sleep 2; done
    echo "    ${name} ready."
}

get_token() {
    curl -sf "${LLDAP_URL}/auth/simple/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${LLDAP_ADMIN_USER}\",\"password\":\"${LLDAP_ADMIN_PASS}\"}" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['token'])"
}

gql() {
    curl -sf "${LLDAP_URL}/api/graphql" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$1"
}

ldap_set_password() {
    local uid="$1" pass="$2"
    docker exec "${CLIENT}" ldappasswd \
        -H "${LLDAP_LDAP_INTERNAL_URI}" \
        -D "uid=${LLDAP_ADMIN_USER},ou=people,${LDAP_BASE}" \
        -w "${LLDAP_ADMIN_PASS}" \
        -s "${pass}" \
        "uid=${uid},ou=people,${LDAP_BASE}" 2>/dev/null || \
    echo "    WARNING: could not set password for ${uid} — Dex login will fail without it."
}

# ── Wait for services ──────────────────────────────────────────────────────────
wait_for "${LLDAP_URL}/healthz" "lldap"
TOKEN=$(get_token)

# ── Create POSIX attribute schema ──────────────────────────────────────────────
echo "==> Registering POSIX attributes in lldap schema..."

for attr in uidNumber gidNumber; do
    gql "{\"query\":\"mutation { addUserAttribute(name:\\\"${attr}\\\",attributeType:INTEGER,isList:false,isVisible:true,isEditable:true) { ok } }\"}" \
        >/dev/null 2>&1 || true
done
for attr in homeDirectory loginShell; do
    gql "{\"query\":\"mutation { addUserAttribute(name:\\\"${attr}\\\",attributeType:STRING,isList:false,isVisible:true,isEditable:true) { ok } }\"}" \
        >/dev/null 2>&1 || true
done
gql '{"query":"mutation { addGroupAttribute(name:\"gidNumber\",attributeType:INTEGER,isList:false,isVisible:true,isEditable:true) { ok } }"}' \
    >/dev/null 2>&1 || true

echo "    Schema ready."

# ── Create users ───────────────────────────────────────────────────────────────

create_user() {
    local id="$1" email="$2" display="$3" first="$4" last="$5" uid="$6" gid="$7" home="$8" shell="$9"
    echo "==> Creating user: ${id}"

    gql "{\"query\":\"mutation { createUser(user:{id:\\\"${id}\\\",email:\\\"${email}\\\",displayName:\\\"${display}\\\",firstName:\\\"${first}\\\",lastName:\\\"${last}\\\"}) { id } }\"}" \
        >/dev/null 2>&1 || echo "    (user ${id} may already exist)"

    gql "{\"query\":\"mutation { updateUser(user:{id:\\\"${id}\\\",insertAttributes:[{name:\\\"uidnumber\\\",value:[\\\"${uid}\\\"]},{name:\\\"gidnumber\\\",value:[\\\"${gid}\\\"]},{name:\\\"homedirectory\\\",value:[\\\"${home}\\\"]},{name:\\\"loginshell\\\",value:[\\\"${shell}\\\"]}]}) { ok } }\"}" \
        >/dev/null 2>&1 || true
}

#                id          email                   displayName         first   last        uid    gid    home                 shell
create_user "alice"     "alice@test.local"     "Alice Liddell"     "Alice"  "Liddell"  10001  20001  "/home/alice"      "/bin/bash"
create_user "bob"       "bob@test.local"       "Bob Builder"       "Bob"    "Builder"  10002  20001  "/home/bob"        "/bin/bash"
create_user "testadmin" "admin@test.local"     "Test Admin"        "Test"   "Admin"    10003  20002  "/home/testadmin"  "/bin/bash"

# ── Create groups ──────────────────────────────────────────────────────────────
echo "==> Creating groups..."

DEV_ID=$(gql '{"query":"mutation { createGroup(name:\"developers\") { id } }"}' | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['createGroup']['id'])" 2>/dev/null || echo "")
ADM_ID=$(gql '{"query":"mutation { createGroup(name:\"admins\") { id } }"}' | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['createGroup']['id'])" 2>/dev/null || echo "")

if [ -z "$DEV_ID" ]; then
    DEV_ID=$(gql '{"query":"{ groups { id name } }"}' | \
        python3 -c "import sys,json; gs=json.load(sys.stdin)['data']['groups']; print(next((g['id'] for g in gs if g['name']=='developers'), ''))" 2>/dev/null || echo "")
fi
if [ -z "$ADM_ID" ]; then
    ADM_ID=$(gql '{"query":"{ groups { id name } }"}' | \
        python3 -c "import sys,json; gs=json.load(sys.stdin)['data']['groups']; print(next((g['id'] for g in gs if g['name']=='admins'), ''))" 2>/dev/null || echo "")
fi

echo "    developers=${DEV_ID:-?}  admins=${ADM_ID:-?}"

[ -n "$DEV_ID" ] && gql "{\"query\":\"mutation { updateGroup(group:{id:${DEV_ID},insertAttributes:[{name:\\\"gidnumber\\\",value:[\\\"20001\\\"]}]}) { ok } }\"}" >/dev/null 2>&1 || true
[ -n "$ADM_ID" ] && gql "{\"query\":\"mutation { updateGroup(group:{id:${ADM_ID},insertAttributes:[{name:\\\"gidnumber\\\",value:[\\\"20002\\\"]}]}) { ok } }\"}" >/dev/null 2>&1 || true

# ── Assign group membership ────────────────────────────────────────────────────
echo "==> Assigning group membership..."

add_member() {
    local gid="$1" uid="$2"
    gql "{\"query\":\"mutation { addUserToGroup(userId:\\\"${uid}\\\",groupId:${gid}) }\"}" >/dev/null 2>&1 || true
}

[ -n "$DEV_ID" ] && add_member "$DEV_ID" "alice"
[ -n "$DEV_ID" ] && add_member "$DEV_ID" "bob"
[ -n "$ADM_ID" ] && add_member "$ADM_ID" "testadmin"

# ── Set user passwords ─────────────────────────────────────────────────────────
echo "==> Setting user passwords (requires testclient to be running)..."
ldap_set_password "alice"     "AliceTest123!"
ldap_set_password "bob"       "BobTest123!"
ldap_set_password "testadmin" "AdminTest123!"

# ── Verify Vault KV v2 ─────────────────────────────────────────────────────────
echo "==> Verifying Vault..."
wait_for "${VAULT_ADDR}/v1/sys/health" "vault"

# Verify the secret/ KV v2 mount is present (dev mode mounts it automatically)
MOUNTS=$(curl -sf "${VAULT_ADDR}/v1/sys/mounts" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" | \
    python3 -c "import sys,json; mounts=json.load(sys.stdin); print('ok' if 'secret/' in mounts else 'missing')" 2>/dev/null || echo "error")

if [ "$MOUNTS" = "ok" ]; then
    echo "    Vault KV v2 mount 'secret/' is ready."
else
    echo "    WARNING: Could not confirm Vault secret/ mount (got: ${MOUNTS})."
    echo "    identree will create secrets at secret/identree/<hostname> on first rotate-breakglass."
fi

# Write a test secret to confirm write access
curl -sf "${VAULT_ADDR}/v1/secret/data/identree-setup-test" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"data":{"status":"vault-escrow-setup-ok"}}' >/dev/null && \
    echo "    Vault write access confirmed." || \
    echo "    WARNING: Could not write test secret to Vault."

# Clean up test secret
curl -sf -X DELETE "${VAULT_ADDR}/v1/secret/metadata/identree-setup-test" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" >/dev/null 2>&1 || true

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Vault escrow test environment ready"
echo ""
echo "  Services:"
echo "    lldap admin UI:  http://localhost:17173  (admin / lldap-admin-pass)"
echo "    Dex OIDC:        http://localhost:5557/dex"
echo "    Vault UI:        http://localhost:8200   (token: identree-vault-test-token)"
echo "    identree:        http://localhost:8094"
echo "    LDAP:            ldap://localhost:3893   base=${LDAP_BASE}"
echo ""
echo "  Test users (lldap + Dex login):"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins → identree admin)"
echo ""
echo "  Escrow backend: HashiCorp Vault KV v2"
echo "    Secrets path:  secret/identree/<hostname>"
echo "    Vault token:   identree-vault-test-token"
echo ""
echo "  Validate:"
echo "    make test-vault-escrow-validate"
echo "    # After running: check Vault UI for secret at secret/identree/vault-escrow-test-host"
echo ""
echo "  Manual escrow test:"
echo "    docker exec identree-vault-escrow-server identree rotate-breakglass"
echo "    curl -sf http://localhost:8200/v1/secret/data/identree/vault-escrow-test-host \\"
echo "      -H 'X-Vault-Token: identree-vault-test-token' | python3 -m json.tool"
echo "════════════════════════════════════════════════════════════"
