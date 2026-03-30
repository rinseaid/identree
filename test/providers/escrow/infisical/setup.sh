#!/bin/bash
# setup.sh — configure lldap users and Infisical for the infisical-escrow test environment.
# Run after: make test-infisical-escrow
#
# What this does:
#   1. Creates POSIX attributes/users/groups in lldap (same as other environments)
#   2. Bootstraps the Infisical admin account (first-run only)
#   3. Creates a workspace (project) named "identree-test"
#   4. Creates a machine identity with Universal Auth
#   5. Adds the identity to the workspace with "developer" role
#   6. Generates a client secret
#   7. Restarts identree with INFISICAL_CLIENT_ID, INFISICAL_CLIENT_SECRET, INFISICAL_ESCROW_PATH
#
# Requirements on host: curl, python3, docker
set -euo pipefail

INFISICAL_URL="${INFISICAL_URL:-http://localhost:8095}"
INFISICAL_INTERNAL_URL="http://infisical:8080"  # used by identree container

LLDAP_URL="${LLDAP_URL:-http://localhost:17174}"
LLDAP_LDAP_URI="${LLDAP_LDAP_URI:-ldap://localhost:3894}"
LLDAP_ADMIN_USER="admin"
LLDAP_ADMIN_PASS="lldap-admin-pass"
LDAP_BASE="dc=test,dc=local"
CLIENT="identree-infisical-escrow-client"

ADMIN_EMAIL="admin@test.local"
ADMIN_PASS="AdminTest123!"

COMPOSE_FILE="test/providers/escrow/infisical/docker-compose.yml"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() {
    local url="$1" name="$2"
    echo "==> Waiting for ${name}..."
    until curl -sf "$url" >/dev/null 2>&1; do sleep 3; done
    echo "    ${name} ready."
}

jq_val() {
    # Minimal JSON field extractor using python3 (no jq dependency).
    # Usage: jq_val <field> <<< "$json"
    local field="$1"
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d$(echo "$field" | sed "s/\./']['/g" | sed "s/^/['/" | sed "s/$/']/" | sed "s/\['\([0-9]\+\)'\]/[\1]/g"))"
}

# ── lldap setup ────────────────────────────────────────────────────────────────

wait_for "${LLDAP_URL}/healthz" "lldap"

get_lldap_token() {
    curl -sf "${LLDAP_URL}/auth/simple/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${LLDAP_ADMIN_USER}\",\"password\":\"${LLDAP_ADMIN_PASS}\"}" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['token'])"
}

TOKEN=$(get_lldap_token)

gql() {
    curl -sf "${LLDAP_URL}/api/graphql" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$1"
}

ldap_set_password() {
    local uid="$1" pass="$2"
    docker exec "${CLIENT}" ldappasswd \
        -H "${LLDAP_LDAP_URI}" \
        -D "uid=${LLDAP_ADMIN_USER},ou=people,${LDAP_BASE}" \
        -w "${LLDAP_ADMIN_PASS}" \
        -s "${pass}" \
        "uid=${uid},ou=people,${LDAP_BASE}" 2>/dev/null || \
    echo "    WARNING: could not set password for ${uid}"
}

echo "==> Registering POSIX attributes in lldap..."
for attr in uidNumber gidNumber; do
    gql "{\"query\":\"mutation { addCustomUserAttribute(attribute:{name:\\\"${attr}\\\",attributeType:INTEGER,isList:false}) }\"}" \
        >/dev/null 2>&1 || true
done
for attr in homeDirectory loginShell; do
    gql "{\"query\":\"mutation { addCustomUserAttribute(attribute:{name:\\\"${attr}\\\",attributeType:TEXT,isList:false}) }\"}" \
        >/dev/null 2>&1 || true
done
gql '{"query":"mutation { addCustomGroupAttribute(attribute:{name:\"gidNumber\",attributeType:INTEGER,isList:false}) }"}' \
    >/dev/null 2>&1 || true

create_user() {
    local id="$1" email="$2" display="$3" first="$4" last="$5" uid="$6" gid="$7" home="$8" shell="$9"
    echo "==> Creating user: ${id}"
    gql "{\"query\":\"mutation { createUser(user:{id:\\\"${id}\\\",email:\\\"${email}\\\",displayName:\\\"${display}\\\",firstName:\\\"${first}\\\",lastName:\\\"${last}\\\"}) { id } }\"}" \
        >/dev/null 2>&1 || echo "    (may already exist)"
    gql "{\"query\":\"mutation { updateUser(user:{id:\\\"${id}\\\",attributes:[{name:\\\"uidNumber\\\",value:[\\\"${uid}\\\"]},{name:\\\"gidNumber\\\",value:[\\\"${gid}\\\"]},{name:\\\"homeDirectory\\\",value:[\\\"${home}\\\"]},{name:\\\"loginShell\\\",value:[\\\"${shell}\\\"]}]}) { id } }\"}" \
        >/dev/null 2>&1 || true
}

create_user "alice"     "alice@test.local"  "Alice Liddell" "Alice" "Liddell" 10001 20001 "/home/alice"     "/bin/bash"
create_user "bob"       "bob@test.local"    "Bob Builder"   "Bob"   "Builder" 10002 20001 "/home/bob"       "/bin/bash"
create_user "testadmin" "admin@test.local"  "Test Admin"    "Test"  "Admin"   10003 20002 "/home/testadmin" "/bin/bash"

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

[ -n "$DEV_ID" ] && gql "{\"query\":\"mutation { updateGroup(group:{id:${DEV_ID},attributes:[{name:\\\"gidNumber\\\",value:[\\\"20001\\\"]}]}) { id } }\"}" >/dev/null 2>&1 || true
[ -n "$ADM_ID" ] && gql "{\"query\":\"mutation { updateGroup(group:{id:${ADM_ID},attributes:[{name:\\\"gidNumber\\\",value:[\\\"20002\\\"]}]}) { id } }\"}" >/dev/null 2>&1 || true

add_member() {
    gql "{\"query\":\"mutation { addUserToGroup(userId:\\\"$2\\\",groupId:$1) }\"}" >/dev/null 2>&1 || true
}
[ -n "$DEV_ID" ] && add_member "$DEV_ID" "alice"
[ -n "$DEV_ID" ] && add_member "$DEV_ID" "bob"
[ -n "$ADM_ID" ] && add_member "$ADM_ID" "testadmin"

echo "==> Setting user passwords..."
ldap_set_password "alice"     "AliceTest123!"
ldap_set_password "bob"       "BobTest123!"
ldap_set_password "testadmin" "AdminTest123!"

# ── Infisical setup ────────────────────────────────────────────────────────────

wait_for "${INFISICAL_URL}/api/status" "Infisical"

# Give Infisical a moment to finish initializing after /api/status first responds
sleep 3

echo "==> Bootstrapping Infisical admin account..."

# POST /api/v1/admin/bootstrap — creates the first admin user without email verification.
# Returns a token + organization. Idempotent: if admin already exists, falls through to login.
BOOTSTRAP_RESP=$(curl -sf "${INFISICAL_URL}/api/v1/admin/bootstrap" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASS}\",\"firstName\":\"Test\",\"lastName\":\"Admin\"}" \
    2>/dev/null || echo "")

if [ -n "$BOOTSTRAP_RESP" ] && echo "$BOOTSTRAP_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'token' in d else 1)" 2>/dev/null; then
    ADMIN_TOKEN=$(echo "$BOOTSTRAP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
    ORG_ID=$(echo "$BOOTSTRAP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['organization']['id'])")
    echo "    Admin bootstrapped. Org ID: ${ORG_ID}"
else
    # Bootstrap already done or returned unexpected response — try logging in.
    echo "    Bootstrap skipped (already done?). Logging in..."
    LOGIN_RESP=$(curl -sf "${INFISICAL_URL}/api/v3/auth/login1" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${ADMIN_EMAIL}\",\"clientProof\":\"\"}" 2>/dev/null || echo "")
    # Fall back to v1 login for older Infisical versions
    if echo "$LOGIN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'token' in d else 1)" 2>/dev/null; then
        ADMIN_TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
    else
        echo "ERROR: Could not bootstrap or log in to Infisical."
        echo "       Response: ${BOOTSTRAP_RESP:-${LOGIN_RESP}}"
        exit 1
    fi
    ORG_ID=$(curl -sf "${INFISICAL_URL}/api/v2/organizations" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" | \
        python3 -c "import sys,json; orgs=json.load(sys.stdin)['organizations']; print(orgs[0]['id'])" 2>/dev/null || echo "")
fi

echo "==> Creating workspace 'identree-test'..."
WS_RESP=$(curl -sf "${INFISICAL_URL}/api/v2/workspace" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"workspaceName\":\"identree-test\",\"organizationId\":\"${ORG_ID}\"}" \
    2>/dev/null || echo "")

WORKSPACE_ID=$(echo "$WS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('workspace',d).get('id',''))" 2>/dev/null || echo "")

if [ -z "$WORKSPACE_ID" ]; then
    # Workspace may already exist — fetch it
    WORKSPACE_ID=$(curl -sf "${INFISICAL_URL}/api/v2/organizations/${ORG_ID}/workspaces" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" | \
        python3 -c "import sys,json; ws=json.load(sys.stdin)['workspaces']; print(next((w['id'] for w in ws if w['name']=='identree-test'), ''))" 2>/dev/null || echo "")
fi

if [ -z "$WORKSPACE_ID" ]; then
    echo "ERROR: Could not create or find workspace 'identree-test'."
    exit 1
fi
echo "    Workspace ID: ${WORKSPACE_ID}"

echo "==> Creating machine identity 'identree-escrow'..."
IDENTITY_RESP=$(curl -sf "${INFISICAL_URL}/api/v1/identities" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"identree-escrow\",\"organizationId\":\"${ORG_ID}\",\"role\":\"member\"}" \
    2>/dev/null || echo "")

IDENTITY_ID=$(echo "$IDENTITY_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('identity',d).get('id',''))" 2>/dev/null || echo "")

if [ -z "$IDENTITY_ID" ]; then
    # May already exist
    IDENTITY_ID=$(curl -sf "${INFISICAL_URL}/api/v1/identities?organizationId=${ORG_ID}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" | \
        python3 -c "import sys,json; ids=json.load(sys.stdin).get('identities',[]); print(next((i['id'] for i in ids if i['name']=='identree-escrow'), ''))" 2>/dev/null || echo "")
fi

if [ -z "$IDENTITY_ID" ]; then
    echo "ERROR: Could not create or find identity 'identree-escrow'."
    exit 1
fi
echo "    Identity ID: ${IDENTITY_ID}"

echo "==> Configuring Universal Auth on identity..."
curl -sf "${INFISICAL_URL}/api/v1/auth/universal-auth/identities/${IDENTITY_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"accessTokenTTL":86400,"accessTokenMaxTTL":86400,"clientSecretTrustedIps":[{"ipAddress":"0.0.0.0/0"},{"ipAddress":"::/0"}],"accessTokenTrustedIps":[{"ipAddress":"0.0.0.0/0"},{"ipAddress":"::/0"}]}' \
    >/dev/null 2>&1 || true

echo "==> Generating client secret..."
SECRET_RESP=$(curl -sf "${INFISICAL_URL}/api/v1/auth/universal-auth/identities/${IDENTITY_ID}/client-secrets" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"description":"identree-escrow-test"}' \
    2>/dev/null || echo "")

CLIENT_ID=$(echo "$SECRET_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); \
    ua=d.get('universalAuthClientSecret', d); print(ua.get('identityId', ua.get('clientId','')))" 2>/dev/null || echo "")
CLIENT_SECRET=$(echo "$SECRET_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); \
    ua=d.get('universalAuthClientSecret', d); print(ua.get('clientSecret',''))" 2>/dev/null || echo "")

# CLIENT_ID for Universal Auth is the identity ID itself; secret is returned once.
# Some Infisical versions return clientId separately; fall back to IDENTITY_ID.
if [ -z "$CLIENT_ID" ]; then
    CLIENT_ID="$IDENTITY_ID"
fi

if [ -z "$CLIENT_SECRET" ]; then
    echo "ERROR: Could not retrieve client secret from Infisical."
    echo "       Response: ${SECRET_RESP}"
    exit 1
fi
echo "    client_id: ${CLIENT_ID}"

echo "==> Adding identity to workspace with developer role..."
curl -sf "${INFISICAL_URL}/api/v1/workspace/${WORKSPACE_ID}/identity-memberships/${IDENTITY_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"role":"member"}' \
    >/dev/null 2>&1 || true

# ESCROW_PATH = {workspaceId}/{environment}
ESCROW_PATH="${WORKSPACE_ID}/prod"

# ── Restart identree with Infisical credentials ────────────────────────────────
echo "==> Restarting identree with Infisical escrow credentials..."
INFISICAL_CLIENT_ID="${CLIENT_ID}" \
INFISICAL_CLIENT_SECRET="${CLIENT_SECRET}" \
INFISICAL_ESCROW_PATH="${ESCROW_PATH}" \
docker compose -f "${COMPOSE_FILE}" up -d identree

echo "    Waiting for identree to be healthy..."
timeout 60 bash -c 'until curl -sf http://localhost:8096/healthz >/dev/null 2>&1; do sleep 3; done'
echo "    identree ready."

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Infisical escrow test environment ready"
echo ""
echo "  Services:"
echo "    lldap admin UI:  http://localhost:17174  (admin / lldap-admin-pass)"
echo "    Dex OIDC:        http://localhost:5558/dex"
echo "    Infisical UI:    http://localhost:8095   (${ADMIN_EMAIL} / ${ADMIN_PASS})"
echo "    identree:        http://localhost:8096"
echo "    LDAP:            ldap://localhost:3894   base=${LDAP_BASE}"
echo ""
echo "  Infisical escrow:"
echo "    Workspace ID:  ${WORKSPACE_ID}"
echo "    Environment:   prod"
echo "    Secret name:   BREAKGLASS_INFISICAL_ESCROW_TEST_HOST"
echo "    client_id:     ${CLIENT_ID}"
echo "    client_secret: ${CLIENT_SECRET}"
echo ""
echo "  Test users:"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins → identree admin)"
echo ""
echo "  Validate:"
echo "    make test-infisical-escrow-validate"
echo ""
echo "  Manual escrow check:"
echo "    # After rotate-breakglass runs, open Infisical UI and look under:"
echo "    # Project 'identree-test' → Secrets → prod → BREAKGLASS_INFISICAL_ESCROW_TEST_HOST"
echo "════════════════════════════════════════════════════════════"
