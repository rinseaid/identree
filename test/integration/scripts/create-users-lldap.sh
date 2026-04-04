#!/bin/bash
# create-users-lldap.sh — create 25 test users in lldap-backed integration stacks.
# Targets both the lldap-dex and vault-escrow stacks (same lldap schema).
# Usage: LLDAP_URL=http://localhost:17175 bash test/integration/scripts/create-users-lldap.sh
#        LLDAP_URL=http://localhost:17177 bash test/integration/scripts/create-users-lldap.sh
set -euo pipefail

LLDAP_URL="${LLDAP_URL:-http://localhost:17175}"
LLDAP_ADMIN_USER="${LLDAP_ADMIN_USER:-admin}"
LLDAP_ADMIN_PASS="${LLDAP_ADMIN_PASS:-lldap-integ-admin-pass}"
LDAP_BASE="${LDAP_BASE:-dc=integ,dc=local}"
# CLIENT: the host container that has ldap-utils for ldappasswd
CLIENT="${CLIENT:-integ-lldap-dex-ubuntu2204}"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() {
    local url="$1" name="$2"
    echo "==> Waiting for ${name}..."
    for i in $(seq 1 30); do
        if curl -sf "${url}" >/dev/null 2>&1; then
            echo "    ${name} ready."
            return
        fi
        sleep 2
    done
    echo "ERROR: ${name} not ready" >&2
    exit 1
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
    # Determine internal LDAP URI from container name
    local ldap_host
    if echo "$CLIENT" | grep -q "lldap-dex"; then
        ldap_host="ldap://lldap:3890"
    else
        ldap_host="ldap://lldap:3890"
    fi
    docker exec "${CLIENT}" ldappasswd \
        -H "${ldap_host}" \
        -D "uid=${LLDAP_ADMIN_USER},ou=people,${LDAP_BASE}" \
        -w "${LLDAP_ADMIN_PASS}" \
        -s "${pass}" \
        "uid=${uid},ou=people,${LDAP_BASE}" 2>/dev/null || \
        echo "    WARNING: could not set password for ${uid}"
}

# ── Wait ───────────────────────────────────────────────────────────────────────

wait_for "${LLDAP_URL}/healthz" "lldap"
TOKEN=$(get_token)

# ── Register POSIX attributes ──────────────────────────────────────────────────

echo "==> Registering POSIX schema attributes..."
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
    local id="$1" email="$2" display="$3" first="$4" last="$5" uid_num="$6" gid_num="$7"
    echo "    Creating user: ${id}"
    gql "{\"query\":\"mutation { createUser(user:{id:\\\"${id}\\\",email:\\\"${email}\\\",displayName:\\\"${display}\\\",firstName:\\\"${first}\\\",lastName:\\\"${last}\\\"}) { id } }\"}" \
        >/dev/null 2>&1 || echo "      (${id} may already exist)"
    # Set POSIX attributes
    gql "{\"query\":\"mutation { updateUser(user:{id:\\\"${id}\\\",insertAttributes:[{name:\\\"uidnumber\\\",value:[\\\"${uid_num}\\\"]},{name:\\\"gidnumber\\\",value:[\\\"${gid_num}\\\"]},{name:\\\"homedirectory\\\",value:[\\\"/home/${id}\\\"]},{name:\\\"loginshell\\\",value:[\\\"/bin/bash\\\"]}]}) { ok } }\"}" \
        >/dev/null 2>&1 || true
}

echo ""
echo "==> Creating 20 developer users..."
#           id          email                  displayName            first     last       uid    gid
create_user "alice"   "alice@integ.local"   "Alice Liddell"    "Alice"   "Liddell"   11001  20001
create_user "bob"     "bob@integ.local"     "Bob Builder"      "Bob"     "Builder"   11002  20001
create_user "carol"   "carol@integ.local"   "Carol Danvers"    "Carol"   "Danvers"   11003  20001
create_user "dave"    "dave@integ.local"    "Dave Grohl"       "Dave"    "Grohl"     11004  20001
create_user "erin"    "erin@integ.local"    "Erin Brockovich"  "Erin"    "Brockovich" 11005 20001
create_user "frank"   "frank@integ.local"   "Frank Castle"     "Frank"   "Castle"    11006  20001
create_user "grace"   "grace@integ.local"   "Grace Hopper"     "Grace"   "Hopper"    11007  20001
create_user "henry"   "henry@integ.local"   "Henry Ford"       "Henry"   "Ford"      11008  20001
create_user "iris"    "iris@integ.local"    "Iris West"        "Iris"    "West"      11009  20001
create_user "jack"    "jack@integ.local"    "Jack Sparrow"     "Jack"    "Sparrow"   11010  20001
create_user "kate"    "kate@integ.local"    "Kate Bishop"      "Kate"    "Bishop"    11011  20001
create_user "liam"    "liam@integ.local"    "Liam Neeson"      "Liam"    "Neeson"    11012  20001
create_user "mia"     "mia@integ.local"     "Mia Wallace"      "Mia"     "Wallace"   11013  20001
create_user "noah"    "noah@integ.local"    "Noah Bennet"      "Noah"    "Bennet"    11014  20001
create_user "olivia"  "olivia@integ.local"  "Olivia Pope"      "Olivia"  "Pope"      11015  20001
create_user "paul"    "paul@integ.local"    "Paul Atreides"    "Paul"    "Atreides"  11016  20001
create_user "quinn"   "quinn@integ.local"   "Quinn Fabray"     "Quinn"   "Fabray"    11017  20001
create_user "rose"    "rose@integ.local"    "Rose Tyler"       "Rose"    "Tyler"     11018  20001
create_user "steve"   "steve@integ.local"   "Steve Rogers"     "Steve"   "Rogers"    11019  20001
create_user "theo"    "theo@integ.local"    "Theo Raeken"      "Theo"    "Raeken"    11020  20001

echo ""
echo "==> Creating 5 admin users..."
create_user "sam"    "sam@integ.local"    "Sam Winchester"  "Sam"    "Winchester" 11021 20002
create_user "tina"   "tina@integ.local"   "Tina Turner"     "Tina"   "Turner"     11022 20002
create_user "ursula" "ursula@integ.local" "Ursula Burns"    "Ursula" "Burns"      11023 20002
create_user "victor" "victor@integ.local" "Victor Von Doom" "Victor" "Von Doom"   11024 20002
create_user "wendy"  "wendy@integ.local"  "Wendy Darling"   "Wendy"  "Darling"    11025 20002

# ── Create groups ──────────────────────────────────────────────────────────────

echo ""
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

[ -n "$DEV_ID" ] && gql "{\"query\":\"mutation { updateGroup(group:{id:${DEV_ID},insertAttributes:[{name:\\\"gidnumber\\\",value:[\\\"20001\\\"]}]}) { ok } }\"}" >/dev/null 2>&1 || true
[ -n "$ADM_ID" ] && gql "{\"query\":\"mutation { updateGroup(group:{id:${ADM_ID},insertAttributes:[{name:\\\"gidnumber\\\",value:[\\\"20002\\\"]}]}) { ok } }\"}" >/dev/null 2>&1 || true

# ── Assign membership ──────────────────────────────────────────────────────────

echo ""
echo "==> Assigning group membership..."

add_member() {
    local gid="$1" uid="$2"
    gql "{\"query\":\"mutation { addUserToGroup(userId:\\\"${uid}\\\",groupId:${gid}) }\"}" >/dev/null 2>&1 || true
}

[ -n "$DEV_ID" ] && for u in alice bob carol dave erin frank grace henry iris jack kate liam mia noah olivia paul quinn rose steve theo; do
    add_member "$DEV_ID" "$u"
done

[ -n "$ADM_ID" ] && for u in sam tina ursula victor wendy; do
    add_member "$ADM_ID" "$u"
done

# ── Set passwords ──────────────────────────────────────────────────────────────

echo ""
echo "==> Setting user passwords (requires host container to be running)..."
echo "    (runs ldappasswd inside ${CLIENT})"

for u in alice bob carol dave erin frank grace henry iris jack kate liam mia noah olivia paul quinn rose steve theo; do
    ldap_set_password "$u" "Test123!${u^}"
done
for u in sam tina ursula victor wendy; do
    ldap_set_password "$u" "Admin123!${u^}"
done

# ── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  lldap integration: users ready"
echo ""
echo "  lldap admin UI:  ${LLDAP_URL}  (admin / ${LLDAP_ADMIN_PASS})"
echo ""
echo "  Users (20 developers + 5 admins):"
echo "    developers: alice–theo (uid 11001–11020, gid 20001)"
echo "    admins:     sam–wendy  (uid 11021–11025, gid 20002)"
echo ""
echo "  Validate (change container name as needed):"
echo "    docker exec ${CLIENT} getent passwd alice"
echo "    docker exec ${CLIENT} getent group developers"
echo "════════════════════════════════════════════════════════════"
