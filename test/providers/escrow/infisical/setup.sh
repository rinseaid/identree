#!/bin/bash
# setup.sh — configure lldap users and Infisical for the infisical-escrow test environment.
# Run after: make test-infisical-escrow
#
# What this does:
#   1. Creates POSIX attributes/users/groups in lldap (same as other environments)
#   2. Bootstraps the Infisical admin account (first-run only)
#   3. Creates a workspace (project) named "identree-test"
#   4. Creates a machine identity with Universal Auth
#   5. Adds the identity to the workspace
#   6. Generates a client secret
#   7. Restarts identree with INFISICAL_CLIENT_ID, INFISICAL_CLIENT_SECRET, INFISICAL_ESCROW_PATH
#
# Requirements on host: curl, python3, docker
set -euo pipefail

INFISICAL_URL="${INFISICAL_URL:-http://localhost:8095}"

LLDAP_URL="${LLDAP_URL:-http://localhost:17174}"
# NOTE: ldappasswd runs inside the testclient container (via docker exec), so the URI
# must use the Docker-internal service name, not the host-side port binding.
LLDAP_LDAP_INTERNAL_URI="ldap://lldap:3890"
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

py() { python3 -c "$1"; }

# ── lldap setup ────────────────────────────────────────────────────────────────

wait_for "${LLDAP_URL}/healthz" "lldap"

get_lldap_token() {
    curl -sf "${LLDAP_URL}/auth/simple/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${LLDAP_ADMIN_USER}\",\"password\":\"${LLDAP_ADMIN_PASS}\"}" | \
        py "import sys,json; print(json.load(sys.stdin)['token'])"
}

TOKEN=$(get_lldap_token)

gql() {
    curl -sf "${LLDAP_URL}/api/graphql" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$1"
}

gql_ok() {
    # Run a mutation, return exit 0 if {"data":...} in response, 1 otherwise.
    # Used for idempotent operations that may already exist.
    local resp
    resp=$(curl -sf "${LLDAP_URL}/api/graphql" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$1" 2>/dev/null || echo "")
    echo "$resp" | py "import sys,json; d=json.load(sys.stdin); exit(0 if 'errors' not in d else 1)" 2>/dev/null
}

ldap_set_password() {
    local uid="$1" pass="$2"
    # Runs inside testclient container — uses Docker-internal lldap hostname.
    docker exec "${CLIENT}" ldappasswd \
        -H "${LLDAP_LDAP_INTERNAL_URI}" \
        -D "uid=${LLDAP_ADMIN_USER},ou=people,${LDAP_BASE}" \
        -w "${LLDAP_ADMIN_PASS}" \
        -s "${pass}" \
        "uid=${uid},ou=people,${LDAP_BASE}" 2>/dev/null || \
    echo "    WARNING: could not set password for ${uid}"
}

# ── lldap schema: register POSIX attributes ────────────────────────────────────
# lldap stable uses addUserAttribute/addGroupAttribute (not addCustomUserAttribute).
# Attribute names are stored lowercase. attributeType: INTEGER or STRING (not TEXT).
# Mutations are idempotent — silently ignore "already exists" errors.
echo "==> Registering POSIX attributes in lldap..."
for attr in uidNumber gidNumber; do
    gql_ok "{\"query\":\"mutation { addUserAttribute(name:\\\"${attr}\\\",attributeType:INTEGER,isList:false,isVisible:true,isEditable:true) { ok } }\"}" \
        >/dev/null 2>&1 || true
done
for attr in homeDirectory loginShell; do
    gql_ok "{\"query\":\"mutation { addUserAttribute(name:\\\"${attr}\\\",attributeType:STRING,isList:false,isVisible:true,isEditable:true) { ok } }\"}" \
        >/dev/null 2>&1 || true
done
gql_ok '{"query":"mutation { addGroupAttribute(name:\"gidNumber\",attributeType:INTEGER,isList:false,isVisible:true,isEditable:true) { ok } }"}' \
    >/dev/null 2>&1 || true
echo "    Schema ready."

# ── Create users ───────────────────────────────────────────────────────────────
# updateUser uses insertAttributes (not attributes), and lldap stores names
# as lowercase regardless of the case used in the mutation.

create_user() {
    local id="$1" email="$2" display="$3" first="$4" last="$5" uid="$6" gid="$7" home="$8" shell="$9"
    echo "==> Creating user: ${id}"
    gql "{\"query\":\"mutation { createUser(user:{id:\\\"${id}\\\",email:\\\"${email}\\\",displayName:\\\"${display}\\\",firstName:\\\"${first}\\\",lastName:\\\"${last}\\\"}) { id } }\"}" \
        >/dev/null 2>&1 || echo "    (may already exist)"
    gql "{\"query\":\"mutation { updateUser(user:{id:\\\"${id}\\\",insertAttributes:[{name:\\\"uidnumber\\\",value:[\\\"${uid}\\\"]},{name:\\\"gidnumber\\\",value:[\\\"${gid}\\\"]},{name:\\\"homedirectory\\\",value:[\\\"${home}\\\"]},{name:\\\"loginshell\\\",value:[\\\"${shell}\\\"]}]}) { ok } }\"}" \
        >/dev/null 2>&1 || true
}

create_user "alice"     "alice@test.local"  "Alice Liddell" "Alice" "Liddell" 10001 20001 "/home/alice"     "/bin/bash"
create_user "bob"       "bob@test.local"    "Bob Builder"   "Bob"   "Builder" 10002 20001 "/home/bob"       "/bin/bash"
create_user "testadmin" "admin@test.local"  "Test Admin"    "Test"  "Admin"   10003 20002 "/home/testadmin" "/bin/bash"

# ── Create groups ──────────────────────────────────────────────────────────────
echo "==> Creating groups..."
DEV_ID=$(gql '{"query":"mutation { createGroup(name:\"developers\") { id } }"}' | \
    py "import sys,json; d=json.load(sys.stdin); print(d['data']['createGroup']['id'])" 2>/dev/null || echo "")
ADM_ID=$(gql '{"query":"mutation { createGroup(name:\"admins\") { id } }"}' | \
    py "import sys,json; d=json.load(sys.stdin); print(d['data']['createGroup']['id'])" 2>/dev/null || echo "")

if [ -z "$DEV_ID" ]; then
    DEV_ID=$(gql '{"query":"{ groups { id name } }"}' | \
        py "import sys,json; gs=json.load(sys.stdin)['data']['groups']; print(next((g['id'] for g in gs if g['name']=='developers'), ''))" 2>/dev/null || echo "")
fi
if [ -z "$ADM_ID" ]; then
    ADM_ID=$(gql '{"query":"{ groups { id name } }"}' | \
        py "import sys,json; gs=json.load(sys.stdin)['data']['groups']; print(next((g['id'] for g in gs if g['name']=='admins'), ''))" 2>/dev/null || echo "")
fi

[ -n "$DEV_ID" ] && gql "{\"query\":\"mutation { updateGroup(group:{id:${DEV_ID},insertAttributes:[{name:\\\"gidnumber\\\",value:[\\\"20001\\\"]}]}) { ok } }\"}" >/dev/null 2>&1 || true
[ -n "$ADM_ID" ] && gql "{\"query\":\"mutation { updateGroup(group:{id:${ADM_ID},insertAttributes:[{name:\\\"gidnumber\\\",value:[\\\"20002\\\"]}]}) { ok } }\"}" >/dev/null 2>&1 || true

add_member() {
    gql "{\"query\":\"mutation { addUserToGroup(userId:\\\"$2\\\",groupId:$1) { ok } }\"}" >/dev/null 2>&1 || true
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
sleep 3  # allow migrations to settle after /api/status first responds

echo "==> Bootstrapping Infisical admin account..."

# POST /api/v1/admin/bootstrap — creates the first admin without email verification.
# Required fields: email, password, firstName, lastName, organization.
# Returns: { user, organization: {id}, identity: {credentials: {token}} }
# On re-run (already bootstrapped), returns an error — fall back to cached token.
BOOTSTRAP_RESP=$(curl -s "${INFISICAL_URL}/api/v1/admin/bootstrap" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASS}\",\"firstName\":\"Test\",\"lastName\":\"Admin\",\"organization\":\"identree-test\"}" \
    2>/dev/null || echo "")

ADMIN_TOKEN=""
ORG_ID=""

if echo "$BOOTSTRAP_RESP" | py "import sys,json; d=json.load(sys.stdin); exit(0 if 'identity' in d else 1)" 2>/dev/null; then
    # Token is at identity.credentials.token (the instance admin identity token)
    ADMIN_TOKEN=$(echo "$BOOTSTRAP_RESP" | py "import sys,json; d=json.load(sys.stdin); print(d['identity']['credentials']['token'])")
    ORG_ID=$(echo "$BOOTSTRAP_RESP" | py "import sys,json; d=json.load(sys.stdin); print(d['organization']['id'])")
    echo "$ADMIN_TOKEN" > /tmp/infisical-escrow-token
    echo "    Admin bootstrapped. Org ID: ${ORG_ID}"
else
    echo "    Bootstrap unavailable (already done?). Using cached token..."
    if [ -f /tmp/infisical-escrow-token ]; then
        ADMIN_TOKEN=$(cat /tmp/infisical-escrow-token)
    else
        echo "ERROR: Infisical bootstrap failed and no cached token found."
        echo "       Bootstrap response: ${BOOTSTRAP_RESP}"
        echo "       Tear down with 'make test-infisical-escrow-down' and retry."
        exit 1
    fi
fi

# Fetch org ID if bootstrap didn't return it
if [ -z "$ORG_ID" ]; then
    ORG_ID=$(curl -sf "${INFISICAL_URL}/api/v2/organizations" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" | \
        py "import sys,json; orgs=json.load(sys.stdin)['organizations']; print(orgs[0]['id'])" 2>/dev/null || echo "")
fi
[ -z "$ORG_ID" ] && { echo "ERROR: Could not determine org ID."; exit 1; }

echo "==> Creating workspace 'identree-test'..."
# Note: Infisical uses projectName (not workspaceName); response wraps result in 'project'.
WS_RESP=$(curl -s "${INFISICAL_URL}/api/v2/workspace" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"projectName\":\"identree-test\",\"organizationId\":\"${ORG_ID}\"}" \
    2>/dev/null || echo "")

WORKSPACE_ID=$(echo "$WS_RESP" | py "import sys,json; d=json.load(sys.stdin); print((d.get('project') or d).get('id',''))" 2>/dev/null || echo "")

if [ -z "$WORKSPACE_ID" ]; then
    # Workspace may already exist
    WORKSPACE_ID=$(curl -sf "${INFISICAL_URL}/api/v2/organizations/${ORG_ID}/workspaces" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" | \
        py "import sys,json; ws=json.load(sys.stdin)['workspaces']; \
            print(next((w['id'] for w in ws if w['name']=='identree-test'), ws[0]['id'] if ws else ''))" 2>/dev/null || echo "")
fi
[ -z "$WORKSPACE_ID" ] && { echo "ERROR: Could not create or find workspace."; echo "Response: ${WS_RESP}"; exit 1; }
echo "    Workspace ID: ${WORKSPACE_ID}"

echo "==> Creating machine identity 'identree-escrow'..."
IDENTITY_RESP=$(curl -s "${INFISICAL_URL}/api/v1/identities" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"identree-escrow\",\"organizationId\":\"${ORG_ID}\",\"role\":\"member\"}" \
    2>/dev/null || echo "")

IDENTITY_ID=$(echo "$IDENTITY_RESP" | py "import sys,json; d=json.load(sys.stdin); print((d.get('identity') or d).get('id',''))" 2>/dev/null || echo "")

if [ -z "$IDENTITY_ID" ]; then
    # Identity may already exist
    IDENTITY_ID=$(curl -sf "${INFISICAL_URL}/api/v1/identities?organizationId=${ORG_ID}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" | \
        py "import sys,json; ids=json.load(sys.stdin).get('identities',[]); print(next((i['id'] for i in ids if i['name']=='identree-escrow'), ''))" 2>/dev/null || echo "")
fi
[ -z "$IDENTITY_ID" ] && { echo "ERROR: Could not create machine identity."; echo "Response: ${IDENTITY_RESP}"; exit 1; }
echo "    Identity ID: ${IDENTITY_ID}"

echo "==> Configuring Universal Auth on identity..."
# Returns identityUniversalAuth.clientId — this is the CLIENT_ID for auth, NOT the identity ID.
UA_RESP=$(curl -s -X POST "${INFISICAL_URL}/api/v1/auth/universal-auth/identities/${IDENTITY_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"accessTokenTTL":86400,"accessTokenMaxTTL":86400,"clientSecretTrustedIps":[{"ipAddress":"0.0.0.0/0"},{"ipAddress":"::/0"}],"accessTokenTrustedIps":[{"ipAddress":"0.0.0.0/0"},{"ipAddress":"::/0"}]}' \
    2>/dev/null || echo "")

CLIENT_ID=$(echo "$UA_RESP" | py "import sys,json; d=json.load(sys.stdin); \
    print((d.get('identityUniversalAuth') or d).get('clientId',''))" 2>/dev/null || echo "")

if [ -z "$CLIENT_ID" ]; then
    # Universal Auth may already be configured — fetch the existing clientId
    CLIENT_ID=$(curl -sf "${INFISICAL_URL}/api/v1/auth/universal-auth/identities/${IDENTITY_ID}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" | \
        py "import sys,json; d=json.load(sys.stdin); print((d.get('identityUniversalAuth') or d).get('clientId',''))" 2>/dev/null || echo "")
fi
[ -z "$CLIENT_ID" ] && { echo "ERROR: Could not get Universal Auth clientId."; echo "Response: ${UA_RESP}"; exit 1; }
echo "    Universal Auth clientId: ${CLIENT_ID}"

echo "==> Generating client secret..."
# clientSecret is at the top level of the response (returned once at creation).
SECRET_RESP=$(curl -s -X POST "${INFISICAL_URL}/api/v1/auth/universal-auth/identities/${IDENTITY_ID}/client-secrets" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"description":"identree-escrow-test","numUsesLimit":0}' \
    2>/dev/null || echo "")

CLIENT_SECRET=$(echo "$SECRET_RESP" | py "import sys,json; d=json.load(sys.stdin); print(d.get('clientSecret',''))" 2>/dev/null || echo "")
[ -z "$CLIENT_SECRET" ] && { echo "ERROR: Could not retrieve client secret."; echo "Response: ${SECRET_RESP}"; exit 1; }

echo "==> Adding identity to workspace..."
# Endpoint: POST /api/v2/workspace/{projectId}/identity-memberships/{identityId}
curl -s -X POST "${INFISICAL_URL}/api/v2/workspace/${WORKSPACE_ID}/identity-memberships/${IDENTITY_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"role":"member"}' \
    >/dev/null 2>&1 || true  # idempotent — ignore "already exists" errors

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

# Re-run rotate-breakglass now that identree has real Infisical credentials.
# The initial run in entrypoint.sh used the local escrow backend (Infisical
# credentials weren't set yet), so the secret was never written to Infisical.
echo "==> Running rotate-breakglass to write secret to Infisical..."
docker exec "${CLIENT}" identree rotate-breakglass && echo "    Break-glass secret written to Infisical." || \
    echo "    WARNING: rotate-breakglass failed — check identree logs."

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
echo "  Manual escrow check (after rotate-breakglass runs):"
echo "    Infisical UI → Project 'identree-test' → Secrets → prod"
echo "    Look for: BREAKGLASS_INFISICAL_ESCROW_TEST_HOST"
echo "════════════════════════════════════════════════════════════"
