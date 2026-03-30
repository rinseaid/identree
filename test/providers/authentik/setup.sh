#!/bin/bash
# setup.sh — configure Authentik for the identree Authentik test environment.
# Run after: make test-authentik
#
# What this does:
#   1. Waits for Authentik to be healthy
#   2. Creates groups: developers, admins
#   3. Creates users: alice, bob, testadmin with POSIX attributes and passwords
#   4. Creates LDAP service account (for SSSD bind)
#   5. Creates OIDC provider + application (fixed client secret)
#   6. Creates LDAP provider + application + outpost
#   7. Retrieves the outpost service account token
#   8. Restarts authentik-ldap and identree with correct credentials
#
# Requirements: curl, python3, docker
set -euo pipefail

AK_URL="${AK_URL:-http://localhost:9000}"
AK_TOKEN="identree-authentik-test-token"
COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

OIDC_CLIENT_SECRET="identree-authentik-oidc-secret"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() {
    local url="$1" name="$2"
    echo "==> Waiting for ${name}..."
    until curl -sf "$url" >/dev/null 2>&1; do sleep 3; done
    echo "    ${name} ready."
}

ak() {
    local method="$1" path="$2"; shift 2
    curl -sf -X "$method" \
        -H "Authorization: Bearer ${AK_TOKEN}" \
        -H "Content-Type: application/json" \
        "${AK_URL}/api/v3${path}" "$@"
}

py() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }

# ── Wait for Authentik ─────────────────────────────────────────────────────────
wait_for "${AK_URL}/-/health/live/" "authentik"
# Give the worker time to run migrations and create default objects
echo "==> Waiting for Authentik worker (migrations + default flows)..."
until ak GET /flows/instances/ 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if len(d.get('results',[]))>0 else 1)" 2>/dev/null; do
    sleep 5
done
echo "    Authentik API ready."

# ── Fetch default flows ────────────────────────────────────────────────────────
echo "==> Fetching default flows..."

# Authorization flow (for OIDC provider)
AUTH_FLOW_PK=$(ak GET "/flows/instances/?designation=authorization&ordering=slug" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

# Authentication flow (for LDAP bind_flow — handles LDAP bind auth)
AUTHN_FLOW_PK=$(ak GET "/flows/instances/?designation=authentication&ordering=slug" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

# Invalidation flow (required since Authentik 2024.x)
INVAL_FLOW_PK=$(ak GET "/flows/instances/?designation=invalidation&ordering=slug" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

if [ -z "$AUTH_FLOW_PK" ] || [ -z "$AUTHN_FLOW_PK" ] || [ -z "$INVAL_FLOW_PK" ]; then
    echo "ERROR: Could not find default flows. Is the Authentik worker done with migrations?"
    exit 1
fi
echo "    authorization flow: ${AUTH_FLOW_PK}"
echo "    authentication flow: ${AUTHN_FLOW_PK}"
echo "    invalidation flow:   ${INVAL_FLOW_PK}"

# ── Create groups ──────────────────────────────────────────────────────────────
echo "==> Creating groups..."

DEV_PK=$(ak POST /core/groups/ -d '{"name":"developers","is_superuser":false,"attributes":{"gidNumber":20001}}' | \
    py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$DEV_PK" ] && DEV_PK=$(ak GET "/core/groups/?name=developers" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
[ -n "$DEV_PK" ] && ak PATCH "/core/groups/${DEV_PK}/" \
    -d '{"attributes":{"gidNumber":20001}}' >/dev/null 2>&1 || true

ADM_PK=$(ak POST /core/groups/ -d '{"name":"admins","is_superuser":false,"attributes":{"gidNumber":20002}}' | \
    py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$ADM_PK" ] && ADM_PK=$(ak GET "/core/groups/?name=admins" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
[ -n "$ADM_PK" ] && ak PATCH "/core/groups/${ADM_PK}/" \
    -d '{"attributes":{"gidNumber":20002}}' >/dev/null 2>&1 || true

echo "    developers=${DEV_PK:-?}  admins=${ADM_PK:-?}"

# ── Create LDAP service account ────────────────────────────────────────────────
echo "==> Creating LDAP service account..."

SVC_PK=$(ak POST /core/users/ -d '{
    "username": "ldapservice",
    "name": "LDAP Service Account",
    "type": "service_account",
    "is_active": true,
    "attributes": {}
}' | py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$SVC_PK" ] && SVC_PK=$(ak GET "/core/users/?username=ldapservice" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

[ -n "$SVC_PK" ] && ak POST "/core/users/${SVC_PK}/set_password/" \
    -d '{"password":"LdapService123!"}' >/dev/null 2>&1 || true
echo "    ldapservice pk=${SVC_PK:-?}"

# ── Grant ldapservice LDAP search permissions ──────────────────────────────────
# In Authentik, only superusers (or members of is_superuser=true groups) can
# enumerate all users via LDAP. Add ldapservice to authentik Admins so it can
# perform directory-wide searches that SSSD requires.
echo "==> Granting ldapservice LDAP search permissions..."
ADMINS_GROUP_PK=$(ak GET "/core/groups/?name=authentik+Admins" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
if [ -n "$ADMINS_GROUP_PK" ] && [ -n "$SVC_PK" ]; then
    ak POST "/core/groups/${ADMINS_GROUP_PK}/add_user/" \
        -d "{\"pk\": ${SVC_PK}}" >/dev/null 2>&1 || true
    echo "    ldapservice added to authentik Admins (pk=${ADMINS_GROUP_PK})"
else
    echo "    WARNING: could not find authentik Admins group or ldapservice pk"
fi

# ── Create users ───────────────────────────────────────────────────────────────

create_user() {
    local username="$1" name="$2" email="$3" uid="$4" gid="$5" home="$6" shell="$7" group_pk="$8" password="$9"
    echo "==> Creating user: ${username}"

    local pk
    pk=$(ak POST /core/users/ -d "{
        \"username\": \"${username}\",
        \"name\": \"${name}\",
        \"email\": \"${email}\",
        \"type\": \"internal\",
        \"is_active\": true,
        \"attributes\": {
            \"uidNumber\": ${uid},
            \"gidNumber\": ${gid},
            \"homeDirectory\": \"${home}\",
            \"loginShell\": \"${shell}\"
        }
    }" | py "print(d.get('pk',''))" 2>/dev/null || echo "")

    if [ -z "$pk" ]; then
        pk=$(ak GET "/core/users/?username=${username}" | \
            py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
    fi

    if [ -n "$pk" ]; then
        ak POST "/core/users/${pk}/set_password/" -d "{\"password\": \"${password}\"}" >/dev/null 2>&1 || true
        [ -n "$group_pk" ] && ak POST "/core/groups/${group_pk}/add_user/" \
            -d "{\"pk\": ${pk}}" >/dev/null 2>&1 || true
        echo "    ${username} pk=${pk}"
    else
        echo "    WARNING: could not create/find ${username}"
    fi
}

create_user "alice"     "Alice Liddell" "alice@test.local"  10001 20001 "/home/alice"      "/bin/bash" "${DEV_PK:-}" "AliceTest123!"
create_user "bob"       "Bob Builder"   "bob@test.local"    10002 20001 "/home/bob"        "/bin/bash" "${DEV_PK:-}" "BobTest123!"
create_user "testadmin" "Test Admin"    "admin@test.local"  10003 20002 "/home/testadmin"  "/bin/bash" "${ADM_PK:-}" "AdminTest123!"

# ── Fetch scope mappings for OIDC provider ─────────────────────────────────────
echo "==> Fetching OIDC scope mappings..."

SCOPE_OPENID=$(ak GET "/propertymappings/provider/scope/?managed=goauthentik.io%2Fproviders%2Foauth2%2Fscope-openid" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
SCOPE_EMAIL=$(ak GET "/propertymappings/provider/scope/?managed=goauthentik.io%2Fproviders%2Foauth2%2Fscope-email" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
SCOPE_PROFILE=$(ak GET "/propertymappings/provider/scope/?managed=goauthentik.io%2Fproviders%2Foauth2%2Fscope-profile" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

# Create a groups scope mapping so identree receives the groups claim
SCOPE_GROUPS=$(ak POST /propertymappings/provider/scope/ -d '{
    "name": "identree-groups",
    "scope_name": "groups",
    "description": "Expose group membership as groups claim",
    "expression": "return {\"groups\": [g.name for g in request.user.ak_groups.all()]}"
}' | py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$SCOPE_GROUPS" ] && SCOPE_GROUPS=$(ak GET "/propertymappings/provider/scope/?name=identree-groups" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

echo "    openid=${SCOPE_OPENID:-?}  email=${SCOPE_EMAIL:-?}  profile=${SCOPE_PROFILE:-?}  groups=${SCOPE_GROUPS:-?}"

# Build property_mappings list (skip empty)
MAPPINGS="[]"
if [ -n "$SCOPE_OPENID" ] && [ -n "$SCOPE_EMAIL" ] && [ -n "$SCOPE_PROFILE" ] && [ -n "$SCOPE_GROUPS" ]; then
    MAPPINGS="[\"${SCOPE_OPENID}\",\"${SCOPE_EMAIL}\",\"${SCOPE_PROFILE}\",\"${SCOPE_GROUPS}\"]"
fi

# ── Create OIDC provider ───────────────────────────────────────────────────────
echo "==> Creating OIDC provider..."

OIDC_PK=$(ak POST /providers/oauth2/ -d "{
    \"name\": \"identree-oidc\",
    \"authorization_flow\": \"${AUTH_FLOW_PK}\",
    \"invalidation_flow\": \"${INVAL_FLOW_PK}\",
    \"client_type\": \"confidential\",
    \"client_id\": \"identree\",
    \"client_secret\": \"${OIDC_CLIENT_SECRET}\",
    \"redirect_uris\": [
        {\"matching_mode\": \"strict\", \"url\": \"http://identree:8090/callback\"},
        {\"matching_mode\": \"strict\", \"url\": \"http://localhost:8098/callback\"}
    ],
    \"sub_mode\": \"user_username\",
    \"include_claims_in_id_token\": true,
    \"property_mappings\": ${MAPPINGS}
}" | py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$OIDC_PK" ] && OIDC_PK=$(ak GET "/providers/oauth2/?name=identree-oidc" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
echo "    OIDC provider pk=${OIDC_PK:-?}"

# Create OIDC application
ak POST /core/applications/ -d "{
    \"name\": \"identree\",
    \"slug\": \"identree\",
    \"provider\": ${OIDC_PK:-0}
}" >/dev/null 2>&1 || true

# Restart identree now that the OIDC application exists
echo "==> Restarting identree (OIDC application now exists)..."
docker compose -f "${COMPOSE_FILE}" up -d --no-deps identree

# ── Create LDAP provider ───────────────────────────────────────────────────────
echo "==> Creating LDAP provider..."

LDAP_PK=$(ak POST /providers/ldap/ -d "{
    \"name\": \"identree-ldap\",
    \"base_dn\": \"dc=test,dc=local\",
    \"authorization_flow\": \"${AUTHN_FLOW_PK}\",
    \"invalidation_flow\": \"${INVAL_FLOW_PK}\",
    \"uid_start_number\": 10000,
    \"gid_start_number\": 20000
}" | py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$LDAP_PK" ] && LDAP_PK=$(ak GET "/providers/ldap/?name=identree-ldap" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
echo "    LDAP provider pk=${LDAP_PK:-?}"

# Create LDAP application
ak POST /core/applications/ -d "{
    \"name\": \"identree-ldap\",
    \"slug\": \"identree-ldap\",
    \"provider\": ${LDAP_PK:-0}
}" >/dev/null 2>&1 || true

# ── Create LDAP outpost ────────────────────────────────────────────────────────
echo "==> Creating LDAP outpost..."

OUTPOST_PK=$(ak POST /outposts/instances/ -d "{
    \"name\": \"identree-ldap-outpost\",
    \"type\": \"ldap\",
    \"providers\": [${LDAP_PK:-0}],
    \"config\": {
        \"authentik_host\": \"http://authentik-server:9000\",
        \"authentik_host_insecure\": true
    }
}" | py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$OUTPOST_PK" ] && OUTPOST_PK=$(ak GET "/outposts/instances/?name=identree-ldap-outpost" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
echo "    outpost pk=${OUTPOST_PK:-?}"

if [ -z "$OUTPOST_PK" ]; then
    echo "ERROR: Could not create LDAP outpost."
    exit 1
fi

# ── Retrieve outpost service account token ────────────────────────────────────
echo "==> Retrieving outpost service account token..."

# Authentik 2024.10+ creates a managed token with key goauthentik.io/outpost/ak-outpost-<pk>-api
OUTPOST_MANAGED_URL="goauthentik.io%2Foutpost%2Fak-outpost-${OUTPOST_PK}-api"
TOKEN_IDENTIFIER=""
# Retry a few times — the worker may not have created the token yet
for i in 1 2 3 4 5; do
    TOKEN_IDENTIFIER=$(ak GET "/core/tokens/?managed=${OUTPOST_MANAGED_URL}" | \
        py "print(d['results'][0]['identifier'] if d.get('results') else '')" 2>/dev/null || echo "")
    [ -n "$TOKEN_IDENTIFIER" ] && break
    echo "    waiting for token (attempt ${i}/5)..."
    sleep 5
done

if [ -z "$TOKEN_IDENTIFIER" ]; then
    echo "ERROR: Could not find outpost service account token."
    exit 1
fi

OUTPOST_TOKEN=$(ak GET "/core/tokens/${TOKEN_IDENTIFIER}/view_key/" | \
    py "print(d.get('key',''))" 2>/dev/null || echo "")

if [ -z "$OUTPOST_TOKEN" ]; then
    echo "ERROR: Could not retrieve outpost token key."
    exit 1
fi
echo "    token retrieved (${#OUTPOST_TOKEN} chars)"

# ── Restart authentik-ldap with the real outpost token ────────────────────────
echo "==> Restarting authentik-ldap with outpost token..."
export AUTHENTIK_LDAP_TOKEN="${OUTPOST_TOKEN}"
docker compose -f "${COMPOSE_FILE}" up -d --no-deps authentik-ldap

echo "==> Waiting for LDAP outpost to connect (30s)..."
sleep 30

echo "==> Waiting for identree to be healthy..."
until curl -sf http://localhost:8098/healthz >/dev/null 2>&1; do sleep 3; done
echo "    identree ready."

# ── Ensure break-glass password is provisioned ─────────────────────────────────
# The testclient starts before identree is ready, so rotate-breakglass may have
# failed at container startup. Retry here now that identree is confirmed healthy.
echo "==> Ensuring break-glass password is provisioned..."
docker exec identree-authentik-client \
    sh -c 'test -f /etc/identree-breakglass || identree rotate-breakglass' \
    >/dev/null 2>&1 && echo "    break-glass ready." || echo "    WARNING: break-glass setup failed (validate will check)"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Authentik test environment ready"
echo ""
echo "  Services:"
echo "    Authentik admin UI: http://localhost:9000  (akadmin / AuthentikAdmin123!)"
echo "    LDAP outpost:       ldap://localhost:3896  (base: dc=test,dc=local)"
echo "    identree:           http://localhost:8098"
echo ""
echo "  OIDC client credentials:"
echo "    client_id:     identree"
echo "    client_secret: ${OIDC_CLIENT_SECRET}"
echo ""
echo "  Test users (Authentik login):"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins → identree admin)"
echo ""
echo "  Validate:"
echo "    make test-authentik-validate"
echo "    docker exec identree-authentik-client getent passwd alice"
echo "    docker exec identree-authentik-client getent group developers"
echo "════════════════════════════════════════════════════════════"
