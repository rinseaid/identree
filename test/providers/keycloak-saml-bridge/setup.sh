#!/bin/bash
# setup.sh -- configure the SAML-to-OIDC bridge test environment.
#
# Architecture:
#   keycloak-idp    (port 8183) = "Enterprise SAML IdP" with users
#   keycloak-bridge (port 8184) = SAML-to-OIDC bridge
#   identree        (port 8095) = connects to bridge via OIDC
#
# Steps:
#   1. Create users/groups in lldap (POSIX resolution)
#   2. Create realm + users + groups + SAML client descriptor on keycloak-idp
#   3. Create realm + SAML identity provider + OIDC client on keycloak-bridge
#   4. Output BRIDGE_CLIENT_SECRET for identree
set -euo pipefail

LLDAP_URL="${LLDAP_URL:-http://localhost:17175}"
LLDAP_LDAP_INTERNAL_URI="ldap://lldap:3890"
LLDAP_ADMIN_PASS="lldap-admin-pass"
LDAP_BASE="dc=test,dc=local"
LLDAP_CLIENT="identree-saml-bridge-client"

IDP_URL="${IDP_URL:-http://localhost:8183}"
IDP_INTERNAL_URL="http://keycloak-idp:8080"
BRIDGE_URL="${BRIDGE_URL:-http://localhost:8184}"
BRIDGE_INTERNAL_URL="http://keycloak-bridge:8080"

IDP_REALM="enterprise"
BRIDGE_REALM="bridge"
KC_ADMIN_USER="admin"
KC_ADMIN_PASS="admin"

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
    local url="$1"
    curl -sf "${url}/realms/master/protocol/openid-connect/token" \
        -d "grant_type=password&client_id=admin-cli&username=${KC_ADMIN_USER}&password=${KC_ADMIN_PASS}" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
}

kc() {
    local token="$1" method="$2" url="$3" path="$4"; shift 4
    curl -sf -X "$method" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        "${url}${path}" "$@"
}

# ── Wait for services ─────────────────────────────────────────────────────────
wait_for "${LLDAP_URL}/healthz" "lldap"
wait_for "${IDP_URL}/realms/master" "Keycloak IdP"
wait_for "${BRIDGE_URL}/realms/master" "Keycloak Bridge"

# ── lldap: users + groups ─────────────────────────────────────────────────────
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

# ── Keycloak IdP: realm + users + groups + SAML client ────────────────────────
echo "==> Setting up Keycloak IdP (enterprise SAML IdP)..."
IDP_TOKEN=$(kc_admin_token "${IDP_URL}")

echo "    Creating realm ${IDP_REALM}..."
kc "$IDP_TOKEN" POST "${IDP_URL}" "/admin/realms" \
    -d "{\"realm\":\"${IDP_REALM}\",\"enabled\":true}" >/dev/null 2>&1 || true

echo "    Creating IdP groups..."
kc "$IDP_TOKEN" POST "${IDP_URL}" "/admin/realms/${IDP_REALM}/groups" -d '{"name":"developers"}' >/dev/null 2>&1 || true
kc "$IDP_TOKEN" POST "${IDP_URL}" "/admin/realms/${IDP_REALM}/groups" -d '{"name":"admins"}' >/dev/null 2>&1 || true

IDP_DEV_ID=$(kc "$IDP_TOKEN" GET "${IDP_URL}" "/admin/realms/${IDP_REALM}/groups?search=developers" | \
    python3 -c "import sys,json; gs=json.load(sys.stdin); print(gs[0]['id'] if gs else '')" 2>/dev/null || echo "")
IDP_ADM_ID=$(kc "$IDP_TOKEN" GET "${IDP_URL}" "/admin/realms/${IDP_REALM}/groups?search=admins" | \
    python3 -c "import sys,json; gs=json.load(sys.stdin); print(gs[0]['id'] if gs else '')" 2>/dev/null || echo "")

create_idp_user() {
    local username="$1" first="$2" last="$3" email="$4" pass="$5" group_id="$6"
    echo "    Creating IdP user: ${username}"
    kc "$IDP_TOKEN" POST "${IDP_URL}" "/admin/realms/${IDP_REALM}/users" \
        -d "{\"username\":\"${username}\",\"firstName\":\"${first}\",\"lastName\":\"${last}\",\"email\":\"${email}\",\"enabled\":true,\"credentials\":[{\"type\":\"password\",\"value\":\"${pass}\",\"temporary\":false}]}" \
        >/dev/null 2>&1 || true

    local user_id
    user_id=$(kc "$IDP_TOKEN" GET "${IDP_URL}" "/admin/realms/${IDP_REALM}/users?username=${username}" | \
        python3 -c "import sys,json; us=json.load(sys.stdin); print(us[0]['id'] if us else '')" 2>/dev/null || echo "")

    [ -n "$user_id" ] && [ -n "$group_id" ] && \
        kc "$IDP_TOKEN" PUT "${IDP_URL}" "/admin/realms/${IDP_REALM}/users/${user_id}/groups/${group_id}" -d '{}' \
        >/dev/null 2>&1 || true
}

create_idp_user "alice"     "Alice"  "Liddell"  "alice@test.local"  "AliceTest123!"  "${IDP_DEV_ID:-}"
create_idp_user "bob"       "Bob"    "Builder"  "bob@test.local"    "BobTest123!"    "${IDP_DEV_ID:-}"
create_idp_user "testadmin" "Test"   "Admin"    "admin@test.local"  "AdminTest123!"  "${IDP_ADM_ID:-}"

# Create a SAML client on the IdP for the bridge.
# The bridge's SAML entity ID will be: http://keycloak-bridge:8080/realms/bridge
# The bridge's ACS URL: http://keycloak-bridge:8080/realms/bridge/broker/enterprise-saml/endpoint
echo "    Creating SAML client on IdP for bridge..."
kc "$IDP_TOKEN" POST "${IDP_URL}" "/admin/realms/${IDP_REALM}/clients" -d "{
    \"clientId\": \"${BRIDGE_INTERNAL_URL}/realms/${BRIDGE_REALM}\",
    \"name\": \"keycloak-bridge\",
    \"enabled\": true,
    \"protocol\": \"saml\",
    \"frontchannelLogout\": true,
    \"attributes\": {
        \"saml.assertion.signature\": \"true\",
        \"saml.server.signature\": \"true\",
        \"saml_name_id_format\": \"username\",
        \"saml.force.post.binding\": \"true\"
    },
    \"redirectUris\": [
        \"${BRIDGE_INTERNAL_URL}/realms/${BRIDGE_REALM}/broker/enterprise-saml/endpoint\",
        \"${BRIDGE_URL}/realms/${BRIDGE_REALM}/broker/enterprise-saml/endpoint\"
    ]
}" >/dev/null 2>&1 || echo "    (SAML client may already exist)"

# Add groups attribute mapper to the SAML client so group membership appears in assertions.
IDP_SAML_CLIENT_UUID=$(kc "$IDP_TOKEN" GET "${IDP_URL}" "/admin/realms/${IDP_REALM}/clients?clientId=${BRIDGE_INTERNAL_URL}/realms/${BRIDGE_REALM}" | \
    python3 -c "import sys,json; cs=json.load(sys.stdin); print(cs[0]['id'] if cs else '')" 2>/dev/null || echo "")

if [ -n "$IDP_SAML_CLIENT_UUID" ]; then
    echo "    Adding groups mapper to SAML client..."
    kc "$IDP_TOKEN" POST "${IDP_URL}" "/admin/realms/${IDP_REALM}/clients/${IDP_SAML_CLIENT_UUID}/protocol-mappers/models" -d '{
        "name": "groups",
        "protocol": "saml",
        "protocolMapper": "saml-group-membership-mapper",
        "consentRequired": false,
        "config": {
            "full.path": "false",
            "single": "false",
            "attribute.nameformat": "Basic",
            "friendly.name": "groups",
            "attribute.name": "groups"
        }
    }' >/dev/null 2>&1 || true
fi

echo "    IdP setup complete."

# ── Keycloak Bridge: realm + SAML identity provider + OIDC client ─────────────
echo "==> Setting up Keycloak Bridge (SAML-to-OIDC)..."
BRIDGE_TOKEN=$(kc_admin_token "${BRIDGE_URL}")

echo "    Creating realm ${BRIDGE_REALM}..."
kc "$BRIDGE_TOKEN" POST "${BRIDGE_URL}" "/admin/realms" \
    -d "{\"realm\":\"${BRIDGE_REALM}\",\"enabled\":true}" >/dev/null 2>&1 || true

# Add SAML identity provider pointing at keycloak-idp.
echo "    Adding SAML identity provider..."
# Fetch IdP SAML metadata descriptor URL
IDP_SAML_DESCRIPTOR_URL="${IDP_INTERNAL_URL}/realms/${IDP_REALM}/protocol/saml/descriptor"

kc "$BRIDGE_TOKEN" POST "${BRIDGE_URL}" "/admin/realms/${BRIDGE_REALM}/identity-provider/instances" -d "{
    \"alias\": \"enterprise-saml\",
    \"displayName\": \"Enterprise SAML IdP\",
    \"providerId\": \"saml\",
    \"enabled\": true,
    \"trustEmail\": true,
    \"storeToken\": false,
    \"firstBrokerLoginFlowAlias\": \"first broker login\",
    \"config\": {
        \"singleSignOnServiceUrl\": \"${IDP_INTERNAL_URL}/realms/${IDP_REALM}/protocol/saml\",
        \"singleLogoutServiceUrl\": \"${IDP_INTERNAL_URL}/realms/${IDP_REALM}/protocol/saml\",
        \"nameIDPolicyFormat\": \"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\",
        \"entityId\": \"${BRIDGE_INTERNAL_URL}/realms/${BRIDGE_REALM}\",
        \"postBindingResponse\": \"true\",
        \"postBindingAuthnRequest\": \"true\",
        \"wantAssertionsSigned\": \"true\",
        \"syncMode\": \"FORCE\"
    }
}" >/dev/null 2>&1 || echo "    (SAML IdP may already exist)"

# Add groups attribute mapper to the SAML identity provider.
echo "    Adding groups attribute mapper to SAML IdP..."
kc "$BRIDGE_TOKEN" POST "${BRIDGE_URL}" "/admin/realms/${BRIDGE_REALM}/identity-provider/instances/enterprise-saml/mappers" -d '{
    "name": "groups",
    "identityProviderAlias": "enterprise-saml",
    "identityProviderMapper": "saml-user-attribute-idp-mapper",
    "config": {
        "syncMode": "FORCE",
        "user.attribute": "groups",
        "attribute.name": "groups",
        "are.attribute.values.regex": "false"
    }
}' >/dev/null 2>&1 || true

# Add a username mapper so the bridge uses the SAML NameID as the username.
echo "    Adding username mapper..."
kc "$BRIDGE_TOKEN" POST "${BRIDGE_URL}" "/admin/realms/${BRIDGE_REALM}/identity-provider/instances/enterprise-saml/mappers" -d '{
    "name": "username",
    "identityProviderAlias": "enterprise-saml",
    "identityProviderMapper": "saml-username-idp-mapper",
    "config": {
        "syncMode": "FORCE",
        "template": "${ALIAS}.${ATTRIBUTE.username}"
    }
}' >/dev/null 2>&1 || true

# Create OIDC client for identree on the bridge.
echo "    Creating OIDC client for identree..."
kc "$BRIDGE_TOKEN" POST "${BRIDGE_URL}" "/admin/realms/${BRIDGE_REALM}/clients" -d '{
    "clientId": "identree",
    "name": "identree",
    "enabled": true,
    "protocol": "openid-connect",
    "publicClient": false,
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": false,
    "serviceAccountsEnabled": false,
    "redirectUris": [
        "http://identree:8090/callback",
        "http://localhost:8095/callback"
    ],
    "webOrigins": ["http://localhost:8095"]
}' >/dev/null 2>&1 || echo "    (OIDC client may already exist)"

# Get client UUID and secret.
BRIDGE_CLIENT_UUID=$(kc "$BRIDGE_TOKEN" GET "${BRIDGE_URL}" "/admin/realms/${BRIDGE_REALM}/clients?clientId=identree" | \
    python3 -c "import sys,json; cs=json.load(sys.stdin); print(cs[0]['id'] if cs else '')" 2>/dev/null || echo "")

if [ -z "$BRIDGE_CLIENT_UUID" ]; then
    echo "ERROR: Could not find OIDC client on bridge. Did setup fail?"
    exit 1
fi

CLIENT_SECRET=$(kc "$BRIDGE_TOKEN" GET "${BRIDGE_URL}" "/admin/realms/${BRIDGE_REALM}/clients/${BRIDGE_CLIENT_UUID}/client-secret" | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('value',''))" 2>/dev/null || echo "")

if [ -z "$CLIENT_SECRET" ]; then
    CLIENT_SECRET=$(kc "$BRIDGE_TOKEN" POST "${BRIDGE_URL}" "/admin/realms/${BRIDGE_REALM}/clients/${BRIDGE_CLIENT_UUID}/client-secret" -d '{}' | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('value',''))" 2>/dev/null || echo "")
fi

# Add groups claim mapper to the OIDC client.
echo "    Adding groups claim mapper to OIDC client..."
kc "$BRIDGE_TOKEN" POST "${BRIDGE_URL}" "/admin/realms/${BRIDGE_REALM}/clients/${BRIDGE_CLIENT_UUID}/protocol-mappers/models" -d '{
    "name": "groups",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-group-membership-mapper",
    "consentRequired": false,
    "config": {
        "full.path": "false",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "userinfo.token.claim": "true",
        "claim.name": "groups",
        "multivalued": "true"
    }
}' >/dev/null 2>&1 || true

echo "    Bridge setup complete."

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  Keycloak SAML-to-OIDC bridge test environment ready"
echo ""
echo "  Architecture:"
echo "    keycloak-idp    (8183) -- Enterprise SAML IdP (has users)"
echo "    keycloak-bridge (8184) -- SAML-to-OIDC bridge"
echo "    identree        (8095) -- connects to bridge via OIDC"
echo ""
echo "  OIDC client credentials (from bridge):"
echo "    client_id:     identree"
echo "    client_secret: ${CLIENT_SECRET}"
echo ""
echo "  Restart identree with the client secret:"
echo ""
echo "    BRIDGE_CLIENT_SECRET=${CLIENT_SECRET} \\"
echo "    docker compose -f test/providers/keycloak-saml-bridge/docker-compose.yml up -d identree"
echo ""
echo "  Test users (login via IdP, federated through SAML bridge):"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins)"
echo ""
echo "  Login flow: browser -> identree -> bridge (OIDC) -> IdP (SAML) -> user authenticates"
echo "================================================================"
