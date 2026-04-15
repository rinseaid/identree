#!/bin/bash
# setup.sh — configure Keycloak + lldap for the Keycloak SAML test environment.
# Run after: make test-keycloak-saml
#
# What this does:
#   1. Creates test users/groups in lldap (for sssd NSS/POSIX resolution)
#   2. Creates the identree-test realm in Keycloak
#   3. Creates test users (alice, bob, testadmin) in Keycloak with passwords
#   4. Creates groups (developers, admins) in Keycloak
#   5. Assigns group membership in Keycloak
#   6. Creates a SAML client in Keycloak (entity ID = identree, ACS URL = /saml/acs)
#   7. Adds SAML attribute mappers for username and groups
#   8. Restarts identree to pick up the SAML IdP metadata
#
# Users are created independently in both lldap (POSIX) and Keycloak (SAML).
# They share usernames, so the SAML-validated username matches the LDAP user.
set -euo pipefail

LLDAP_URL="${LLDAP_URL:-http://localhost:17173}"
LLDAP_LDAP_INTERNAL_URI="ldap://lldap:3890"
LLDAP_ADMIN_PASS="lldap-admin-pass"
LDAP_BASE="dc=test,dc=local"
LLDAP_CLIENT="identree-keycloak-saml-client"

KC_URL="${KC_URL:-http://localhost:8181}"
KC_REALM="identree-test"
KC_ADMIN_USER="admin"
KC_ADMIN_PASS="admin"
KC_SAML_CLIENT_ID="http://localhost:8101"

COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() { echo "==> Waiting for ${2}..."; until curl -sf "$1" >/dev/null 2>&1; do sleep 2; done; echo "    ${2} ready."; }

lldap_token() {
    curl -sf "${LLDAP_URL}/auth/simple/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"${LLDAP_ADMIN_PASS}\"}" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['token'])"
}

lldap_gql() {
    curl -sf "${LLDAP_URL}/api/graphql" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${LLDAP_TOKEN}" \
        -d "$1"
}

kc_admin_token() {
    curl -sf "${KC_URL}/realms/master/protocol/openid-connect/token" \
        -d "grant_type=password&client_id=admin-cli&username=${KC_ADMIN_USER}&password=${KC_ADMIN_PASS}" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
}

kc() {
    local method="$1" path="$2"; shift 2
    curl -sf -X "$method" \
        -H "Authorization: Bearer ${KC_TOKEN}" \
        -H "Content-Type: application/json" \
        "${KC_URL}${path}" "$@"
}

ldap_set_password() {
    local uid="$1" pass="$2"
    docker exec "${LLDAP_CLIENT}" ldappasswd \
        -H "${LLDAP_LDAP_INTERNAL_URI}" \
        -D "uid=admin,ou=people,${LDAP_BASE}" \
        -w "${LLDAP_ADMIN_PASS}" \
        -s "${pass}" \
        "uid=${uid},ou=people,${LDAP_BASE}" 2>/dev/null || \
    echo "    WARNING: could not set lldap password for ${uid}"
}

# ── Wait for services ──────────────────────────────────────────────────────────
wait_for "${LLDAP_URL}/healthz" "lldap"
wait_for "${KC_URL}/realms/master" "Keycloak"

# ── lldap: POSIX attributes + users + groups ───────────────────────────────────
echo "==> Setting up lldap..."
LLDAP_TOKEN=$(lldap_token)

echo "    Registering POSIX attributes..."
for attr in uidNumber gidNumber; do
    lldap_gql "{\"query\":\"mutation { addUserAttribute(name:\\\"${attr}\\\",attributeType:INTEGER,isList:false,isVisible:true,isEditable:true) { ok } }\"}" \
        >/dev/null 2>&1 || true
done
for attr in homeDirectory loginShell; do
    lldap_gql "{\"query\":\"mutation { addUserAttribute(name:\\\"${attr}\\\",attributeType:STRING,isList:false,isVisible:true,isEditable:true) { ok } }\"}" \
        >/dev/null 2>&1 || true
done
lldap_gql '{"query":"mutation { addGroupAttribute(name:\"gidNumber\",attributeType:INTEGER,isList:false,isVisible:true,isEditable:true) { ok } }"}' \
    >/dev/null 2>&1 || true

create_lldap_user() {
    local id="$1" email="$2" display="$3" first="$4" last="$5" uid="$6" gid="$7" home="$8" shell="$9"
    lldap_gql "{\"query\":\"mutation { createUser(user:{id:\\\"${id}\\\",email:\\\"${email}\\\",displayName:\\\"${display}\\\",firstName:\\\"${first}\\\",lastName:\\\"${last}\\\"}) { id } }\"}" \
        >/dev/null 2>&1 || true
    lldap_gql "{\"query\":\"mutation { updateUser(user:{id:\\\"${id}\\\",insertAttributes:[{name:\\\"uidnumber\\\",value:[\\\"${uid}\\\"]},{name:\\\"gidnumber\\\",value:[\\\"${gid}\\\"]},{name:\\\"homedirectory\\\",value:[\\\"${home}\\\"]},{name:\\\"loginshell\\\",value:[\\\"${shell}\\\"]}]}) { ok } }\"}" \
        >/dev/null 2>&1 || true
    echo "    lldap user: ${id}"
}

create_lldap_user "alice"     "alice@test.local"  "Alice Liddell"  "Alice"  "Liddell"  10001  20001  "/home/alice"      "/bin/bash"
create_lldap_user "bob"       "bob@test.local"    "Bob Builder"    "Bob"    "Builder"  10002  20001  "/home/bob"        "/bin/bash"
create_lldap_user "testadmin" "admin@test.local"  "Test Admin"     "Test"   "Admin"    10003  20002  "/home/testadmin"  "/bin/bash"

echo "    Creating lldap groups..."
DEV_ID=$(lldap_gql '{"query":"mutation { createGroup(name:\"developers\") { id } }"}' | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['data']['createGroup']['id'])" 2>/dev/null || echo "")
ADM_ID=$(lldap_gql '{"query":"mutation { createGroup(name:\"admins\") { id } }"}' | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['data']['createGroup']['id'])" 2>/dev/null || echo "")

if [ -z "$DEV_ID" ]; then
    DEV_ID=$(lldap_gql '{"query":"{ groups { id name } }"}' | \
        python3 -c "import sys,json; gs=json.load(sys.stdin)['data']['groups']; print(next((g['id'] for g in gs if g['name']=='developers'), ''))" 2>/dev/null || echo "")
fi
if [ -z "$ADM_ID" ]; then
    ADM_ID=$(lldap_gql '{"query":"{ groups { id name } }"}' | \
        python3 -c "import sys,json; gs=json.load(sys.stdin)['data']['groups']; print(next((g['id'] for g in gs if g['name']=='admins'), ''))" 2>/dev/null || echo "")
fi

[ -n "$DEV_ID" ] && lldap_gql "{\"query\":\"mutation { updateGroup(group:{id:${DEV_ID},insertAttributes:[{name:\\\"gidnumber\\\",value:[\\\"20001\\\"]}]}) { ok } }\"}" >/dev/null 2>&1 || true
[ -n "$ADM_ID" ] && lldap_gql "{\"query\":\"mutation { updateGroup(group:{id:${ADM_ID},insertAttributes:[{name:\\\"gidnumber\\\",value:[\\\"20002\\\"]}]}) { ok } }\"}" >/dev/null 2>&1 || true

[ -n "$DEV_ID" ] && lldap_gql "{\"query\":\"mutation { addUserToGroup(userId:\\\"alice\\\",groupId:${DEV_ID}) }\"}" >/dev/null 2>&1 || true
[ -n "$DEV_ID" ] && lldap_gql "{\"query\":\"mutation { addUserToGroup(userId:\\\"bob\\\",groupId:${DEV_ID}) }\"}" >/dev/null 2>&1 || true
[ -n "$ADM_ID" ] && lldap_gql "{\"query\":\"mutation { addUserToGroup(userId:\\\"testadmin\\\",groupId:${ADM_ID}) }\"}" >/dev/null 2>&1 || true

echo "    lldap setup complete."

# ── Keycloak: realm + users + groups + SAML client ──────────────────────────
echo "==> Setting up Keycloak..."
KC_TOKEN=$(kc_admin_token)

echo "    Creating realm ${KC_REALM}..."
kc POST /admin/realms -d "{\"realm\":\"${KC_REALM}\",\"enabled\":true,\"registrationAllowed\":false}" \
    >/dev/null 2>&1 || echo "    (realm may already exist)"

echo "    Creating Keycloak groups..."
KC_DEV_ID=$(kc POST "/admin/realms/${KC_REALM}/groups" -d '{"name":"developers"}' 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
KC_ADM_ID=$(kc POST "/admin/realms/${KC_REALM}/groups" -d '{"name":"admins"}' 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

if [ -z "$KC_DEV_ID" ]; then
    KC_DEV_ID=$(kc GET "/admin/realms/${KC_REALM}/groups?search=developers" | \
        python3 -c "import sys,json; gs=json.load(sys.stdin); print(gs[0]['id'] if gs else '')" 2>/dev/null || echo "")
fi
if [ -z "$KC_ADM_ID" ]; then
    KC_ADM_ID=$(kc GET "/admin/realms/${KC_REALM}/groups?search=admins" | \
        python3 -c "import sys,json; gs=json.load(sys.stdin); print(gs[0]['id'] if gs else '')" 2>/dev/null || echo "")
fi

echo "    KC groups: developers=${KC_DEV_ID:-?}  admins=${KC_ADM_ID:-?}"

create_kc_user() {
    local username="$1" first="$2" last="$3" email="$4" pass="$5" group_id="$6"
    echo "    Creating Keycloak user: ${username}"
    local user_id
    user_id=$(kc POST "/admin/realms/${KC_REALM}/users" \
        -d "{\"username\":\"${username}\",\"firstName\":\"${first}\",\"lastName\":\"${last}\",\"email\":\"${email}\",\"enabled\":true,\"credentials\":[{\"type\":\"password\",\"value\":\"${pass}\",\"temporary\":false}]}" \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

    if [ -z "$user_id" ]; then
        user_id=$(kc GET "/admin/realms/${KC_REALM}/users?username=${username}" | \
            python3 -c "import sys,json; us=json.load(sys.stdin); print(us[0]['id'] if us else '')" 2>/dev/null || echo "")
    fi

    [ -n "$user_id" ] && [ -n "$group_id" ] && \
        kc PUT "/admin/realms/${KC_REALM}/users/${user_id}/groups/${group_id}" -d '{}' \
        >/dev/null 2>&1 || true
}

create_kc_user "alice"     "Alice"  "Liddell"  "alice@test.local"  "AliceTest123!"  "${KC_DEV_ID:-}"
create_kc_user "bob"       "Bob"    "Builder"  "bob@test.local"    "BobTest123!"    "${KC_DEV_ID:-}"
create_kc_user "testadmin" "Test"   "Admin"    "admin@test.local"  "AdminTest123!"  "${KC_ADM_ID:-}"

# ── Create SAML client ──────────────────────────────────────────────────────
echo "    Creating SAML client ${KC_SAML_CLIENT_ID}..."
kc POST "/admin/realms/${KC_REALM}/clients" -d "{
    \"clientId\": \"${KC_SAML_CLIENT_ID}\",
    \"name\": \"identree-saml\",
    \"enabled\": true,
    \"protocol\": \"saml\",
    \"frontchannelLogout\": true,
    \"attributes\": {
        \"saml.assertion.signature\": \"true\",
        \"saml.server.signature\": \"true\",
        \"saml.client.signature\": \"false\",
        \"saml.force.post.binding\": \"true\",
        \"saml_assertion_consumer_url_post\": \"http://localhost:8101/saml/acs\",
        \"saml_single_logout_service_url_post\": \"http://localhost:8101/saml/slo\",
        \"saml_name_id_format\": \"username\"
    },
    \"redirectUris\": [
        \"http://localhost:8101/saml/acs\"
    ],
    \"adminUrl\": \"http://localhost:8101\"
}" >/dev/null 2>&1 || echo "    (SAML client may already exist)"

# Get internal client UUID
KC_CLIENT_UUID=$(kc GET "/admin/realms/${KC_REALM}/clients?clientId=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${KC_SAML_CLIENT_ID}'))")" | \
    python3 -c "import sys,json; cs=json.load(sys.stdin); print(cs[0]['id'] if cs else '')" 2>/dev/null || echo "")

if [ -z "$KC_CLIENT_UUID" ]; then
    echo "ERROR: Could not find SAML client in Keycloak. Did setup fail?"
    exit 1
fi

echo "    SAML client UUID: ${KC_CLIENT_UUID}"

# ── Add SAML protocol mappers ──────────────────────────────────────────────
echo "    Adding SAML username attribute mapper..."
kc POST "/admin/realms/${KC_REALM}/clients/${KC_CLIENT_UUID}/protocol-mappers/models" -d '{
    "name": "username",
    "protocol": "saml",
    "protocolMapper": "saml-user-property-idp-mapper",
    "config": {
        "user.attribute": "username",
        "friendly.name": "username",
        "attribute.name": "username",
        "attribute.nameformat": "Basic"
    }
}' >/dev/null 2>&1 || true

echo "    Adding SAML groups attribute mapper..."
kc POST "/admin/realms/${KC_REALM}/clients/${KC_CLIENT_UUID}/protocol-mappers/models" -d '{
    "name": "groups",
    "protocol": "saml",
    "protocolMapper": "saml-group-membership-mapper",
    "config": {
        "full.path": "false",
        "friendly.name": "groups",
        "attribute.name": "groups",
        "attribute.nameformat": "Basic",
        "single": "false"
    }
}' >/dev/null 2>&1 || true

# ── Restart identree ────────────────────────────────────────────────────────
echo "==> Restarting identree to pick up SAML metadata..."
docker compose -f "${COMPOSE_FILE}" up -d --no-deps identree

echo "==> Waiting for identree to be healthy..."
until curl -sf http://localhost:8101/healthz >/dev/null 2>&1; do sleep 3; done
echo "    identree ready."

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Keycloak SAML test environment ready"
echo ""
echo "  Services:"
echo "    lldap admin UI:  http://localhost:17173  (admin / lldap-admin-pass)"
echo "    Keycloak:        http://localhost:8181   (admin / admin)"
echo "    identree (SAML): http://localhost:8101"
echo "    LDAP:            ldap://localhost:3893   base=${LDAP_BASE}"
echo ""
echo "  SAML configuration:"
echo "    SP Entity ID:    ${KC_SAML_CLIENT_ID}"
echo "    ACS URL:         http://localhost:8101/saml/acs"
echo "    IdP Metadata:    http://localhost:8181/realms/${KC_REALM}/protocol/saml/descriptor"
echo "    SP Metadata:     http://localhost:8101/saml/metadata"
echo ""
echo "  Test users (Keycloak login):"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins -> identree admin)"
echo ""
echo "  Validate:"
echo "    make test-keycloak-saml-validate"
echo "════════════════════════════════════════════════════════════"
