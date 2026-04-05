#!/bin/bash
# setup.sh — configure Authentik with a SAML provider for the identree SAML test environment.
# Run after: make test-authentik-saml
#
# What this does:
#   1. Waits for Authentik to be healthy
#   2. Creates groups: developers, admins
#   3. Creates users: alice, bob, testadmin with passwords
#   4. Creates SAML provider + application (ACS URL pointing to identree)
#   5. Restarts identree so it can fetch the SAML IdP metadata
#
# Requirements: curl, python3, docker
set -euo pipefail

AK_URL="${AK_URL:-http://localhost:9010}"
AK_TOKEN="identree-authentik-saml-test-token"
COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

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
echo "==> Waiting for Authentik worker (migrations + default flows)..."
until ak GET "/flows/instances/?designation=authorization" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('results') else 1)" 2>/dev/null \
   && ak GET "/flows/instances/?designation=authentication" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('results') else 1)" 2>/dev/null \
   && ak GET "/flows/instances/?designation=invalidation" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('results') else 1)" 2>/dev/null; do
    sleep 5
done
echo "    Authentik API ready."

# ── Fetch default flows ────────────────────────────────────────────────────────
echo "==> Fetching default flows..."

AUTH_FLOW_PK=$(ak GET "/flows/instances/?designation=authorization&ordering=slug" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

INVAL_FLOW_PK=$(ak GET "/flows/instances/?designation=invalidation&ordering=slug" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

if [ -z "$AUTH_FLOW_PK" ] || [ -z "$INVAL_FLOW_PK" ]; then
    echo "ERROR: Could not find default flows."
    exit 1
fi
echo "    authorization flow: ${AUTH_FLOW_PK}"
echo "    invalidation flow:  ${INVAL_FLOW_PK}"

# ── Create groups ──────────────────────────────────────────────────────────────
echo "==> Creating groups..."

DEV_PK=$(ak POST /core/groups/ -d '{"name":"developers","is_superuser":false}' | \
    py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$DEV_PK" ] && DEV_PK=$(ak GET "/core/groups/?name=developers" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

ADM_PK=$(ak POST /core/groups/ -d '{"name":"admins","is_superuser":false}' | \
    py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$ADM_PK" ] && ADM_PK=$(ak GET "/core/groups/?name=admins" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

echo "    developers=${DEV_PK:-?}  admins=${ADM_PK:-?}"

# ── Create users ───────────────────────────────────────────────────────────────

create_user() {
    local username="$1" name="$2" email="$3" group_pk="$4" password="$5"
    echo "==> Creating user: ${username}"

    local pk
    pk=$(ak POST /core/users/ -d "{
        \"username\": \"${username}\",
        \"name\": \"${name}\",
        \"email\": \"${email}\",
        \"type\": \"internal\",
        \"is_active\": true
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

create_user "alice"     "Alice Liddell" "alice@test.local"  "${DEV_PK:-}" "AliceTest123!"
create_user "bob"       "Bob Builder"   "bob@test.local"    "${DEV_PK:-}" "BobTest123!"
create_user "testadmin" "Test Admin"    "admin@test.local"  "${ADM_PK:-}" "AdminTest123!"

# ── Fetch SAML property mappings ──────────────────────────────────────────────
echo "==> Fetching SAML property mappings..."

# Get all default SAML mappings
SAML_MAPPINGS=$(ak GET "/propertymappings/provider/saml/?managed__startswith=goauthentik.io" | \
    py "print(','.join(['\"'+r['pk']+'\"' for r in d.get('results',[])]))" 2>/dev/null || echo "")

# Create a groups mapping for SAML
SAML_GROUPS_PK=$(ak POST /propertymappings/provider/saml/ -d '{
    "name": "identree-saml-groups",
    "saml_name": "http://schemas.xmlsoap.org/claims/Group",
    "friendly_name": "groups",
    "expression": "for group in request.user.ak_groups.all():\n    yield group.name"
}' | py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$SAML_GROUPS_PK" ] && SAML_GROUPS_PK=$(ak GET "/propertymappings/provider/saml/?name=identree-saml-groups" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

# Create a username mapping
SAML_USERNAME_PK=$(ak POST /propertymappings/provider/saml/ -d '{
    "name": "identree-saml-username",
    "saml_name": "http://schemas.goauthentik.io/2021/02/saml/username",
    "friendly_name": "username",
    "expression": "return request.user.username"
}' | py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$SAML_USERNAME_PK" ] && SAML_USERNAME_PK=$(ak GET "/propertymappings/provider/saml/?name=identree-saml-username" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")

ALL_MAPPINGS="[${SAML_MAPPINGS}"
[ -n "$SAML_GROUPS_PK" ] && ALL_MAPPINGS="${ALL_MAPPINGS},\"${SAML_GROUPS_PK}\""
[ -n "$SAML_USERNAME_PK" ] && ALL_MAPPINGS="${ALL_MAPPINGS},\"${SAML_USERNAME_PK}\""
ALL_MAPPINGS="${ALL_MAPPINGS}]"

echo "    groups mapping: ${SAML_GROUPS_PK:-?}"
echo "    username mapping: ${SAML_USERNAME_PK:-?}"

# ── Create SAML provider ─────────────────────────────────────────────────────
echo "==> Creating SAML provider..."

SAML_PK=$(ak POST /providers/saml/ -d "{
    \"name\": \"identree-saml\",
    \"authorization_flow\": \"${AUTH_FLOW_PK}\",
    \"invalidation_flow\": \"${INVAL_FLOW_PK}\",
    \"acs_url\": \"http://localhost:8100/saml/acs\",
    \"issuer\": \"http://authentik-server:9000\",
    \"audience\": \"http://localhost:8100\",
    \"sp_binding\": \"post\",
    \"name_id_mapping\": null,
    \"property_mappings\": ${ALL_MAPPINGS}
}" | py "print(d.get('pk',''))" 2>/dev/null || echo "")
[ -z "$SAML_PK" ] && SAML_PK=$(ak GET "/providers/saml/?name=identree-saml" | \
    py "print(d['results'][0]['pk'] if d.get('results') else '')" 2>/dev/null || echo "")
echo "    SAML provider pk=${SAML_PK:-?}"

# Update identree docker-compose metadata URL to include the actual provider pk
# The metadata URL is: /api/v3/providers/saml/<pk>/metadata/?download
echo "    SAML metadata URL: http://authentik-server:9000/api/v3/providers/saml/${SAML_PK}/metadata/?download"

# Create SAML application
ak POST /core/applications/ -d "{
    \"name\": \"identree-saml\",
    \"slug\": \"identree-saml\",
    \"provider\": ${SAML_PK:-0}
}" >/dev/null 2>&1 || true

# ── Restart identree with the correct metadata URL ────────────────────────────
echo "==> Restarting identree with correct SAML metadata URL..."
export SAML_PROVIDER_PK="${SAML_PK}"

# Update the metadata URL environment variable dynamically
docker compose -f "${COMPOSE_FILE}" up -d --no-deps \
    -e "IDENTREE_SAML_IDP_METADATA_URL=http://authentik-server:9000/api/v3/providers/saml/${SAML_PK}/metadata/?download" \
    identree 2>/dev/null || \
    docker compose -f "${COMPOSE_FILE}" up -d --no-deps identree

echo "==> Waiting for identree to be healthy..."
until curl -sf http://localhost:8100/healthz >/dev/null 2>&1; do sleep 3; done
echo "    identree ready."

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  Authentik SAML test environment ready"
echo ""
echo "  Services:"
echo "    Authentik admin UI: http://localhost:9010  (akadmin / AuthentikAdmin123!)"
echo "    identree (SAML):   http://localhost:8100"
echo ""
echo "  SAML configuration:"
echo "    SP Entity ID:     http://localhost:8100"
echo "    ACS URL:          http://localhost:8100/saml/acs"
echo "    IdP Metadata:     http://localhost:9010/api/v3/providers/saml/${SAML_PK}/metadata/?download"
echo "    SP Metadata:      http://localhost:8100/saml/metadata"
echo ""
echo "  Test users (Authentik login):"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins -> identree admin)"
echo ""
echo "  Validate:"
echo "    make test-authentik-saml-validate"
echo "================================================================"
