#!/bin/bash
# setup.sh — configure lldap for the lldap+Dex test environment.
# Run after: make test-lldap-dex
#
# What this does:
#   1. Creates POSIX custom attributes in lldap (uidNumber, gidNumber, homeDirectory, loginShell)
#   2. Creates test users (alice, bob, testadmin) with POSIX attributes
#   3. Sets user passwords (via LDAP Password Modify so Dex can authenticate them)
#   4. Creates groups (developers, admins) with gidNumber
#   5. Assigns group membership
#
# Requirements on host: curl, python3 (for JSON parsing), ldap-utils (for ldappasswd)
#   macOS:  brew install openldap
#   Debian: apt-get install ldap-utils
set -euo pipefail

LLDAP_URL="${LLDAP_URL:-http://localhost:17171}"
# ldappasswd runs inside the testclient container via docker exec, so the URI
# must use the Docker-internal service name, not the host-side port binding.
LLDAP_LDAP_INTERNAL_URI="ldap://lldap:3890"
LLDAP_ADMIN_USER="admin"
LLDAP_ADMIN_PASS="lldap-admin-pass"
LDAP_BASE="dc=test,dc=local"
CLIENT="identree-lldap-dex-client"  # testclient container (has ldap-utils)

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
    # Run a GraphQL mutation against lldap. $TOKEN must be set.
    curl -sf "${LLDAP_URL}/api/graphql" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "$1"
}

ldap_set_password() {
    # Set a user's password via the LDAP Password Modify Extended Operation.
    # Runs inside the testclient container (which has ldap-utils installed).
    local uid="$1" pass="$2"
    docker exec "${CLIENT}" ldappasswd \
        -H "${LLDAP_LDAP_INTERNAL_URI}" \
        -D "uid=${LLDAP_ADMIN_USER},ou=people,${LDAP_BASE}" \
        -w "${LLDAP_ADMIN_PASS}" \
        -s "${pass}" \
        "uid=${uid},ou=people,${LDAP_BASE}" 2>/dev/null || \
    echo "    WARNING: could not set password for ${uid} — Dex login will fail without it."
}

# ── Wait for lldap ─────────────────────────────────────────────────────────────
wait_for "${LLDAP_URL}/healthz" "lldap"
TOKEN=$(get_token)

# ── Create POSIX attribute schema ──────────────────────────────────────────────
# lldap stable uses addUserAttribute/addGroupAttribute (not addCustomUserAttribute).
# Attribute names are stored lowercase. attributeType: INTEGER or STRING (not TEXT).
# Mutations are idempotent — silently ignore "already exists" errors.
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

    # updateUser uses insertAttributes (not attributes); lldap stores names lowercase.
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

# Fetch IDs if groups already exist
if [ -z "$DEV_ID" ]; then
    DEV_ID=$(gql '{"query":"{ groups { id name } }"}' | \
        python3 -c "import sys,json; gs=json.load(sys.stdin)['data']['groups']; print(next((g['id'] for g in gs if g['name']=='developers'), ''))" 2>/dev/null || echo "")
fi
if [ -z "$ADM_ID" ]; then
    ADM_ID=$(gql '{"query":"{ groups { id name } }"}' | \
        python3 -c "import sys,json; gs=json.load(sys.stdin)['data']['groups']; print(next((g['id'] for g in gs if g['name']=='admins'), ''))" 2>/dev/null || echo "")
fi

echo "    developers=${DEV_ID:-?}  admins=${ADM_ID:-?}"

# Set gidNumber on groups
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
# Passwords are needed so Dex can authenticate users at its login form.
# ldappasswd runs inside the testclient container (which has ldap-utils).
echo "==> Setting user passwords (requires testclient to be running)..."
ldap_set_password "alice"     "AliceTest123!"
ldap_set_password "bob"       "BobTest123!"
ldap_set_password "testadmin" "AdminTest123!"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  lldap+Dex test environment ready"
echo ""
echo "  Services:"
echo "    lldap admin UI:  http://localhost:17171  (admin / lldap-admin-pass)"
echo "    Dex OIDC:        http://localhost:5556/dex"
echo "    identree:        http://localhost:8091"
echo "    LDAP:            ldap://localhost:3891   base=${LDAP_BASE}"
echo ""
echo "  Test users (lldap + Dex login):"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins → identree admin)"
echo ""
echo "  Validate:"
echo "    docker exec identree-lldap-dex-client getent passwd alice"
echo "    docker exec identree-lldap-dex-client getent group developers"
echo "    docker exec -it identree-lldap-dex-client bash"
echo "    sudo whoami  (as alice inside testclient → triggers identree challenge)"
echo "════════════════════════════════════════════════════════════"
