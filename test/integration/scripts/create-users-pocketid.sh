#!/bin/bash
# create-users-pocketid.sh — create 25 test users in the PocketID integration stack.
# Run after: make integration-full-mode
# Usage: bash test/integration/scripts/create-users-pocketid.sh
set -euo pipefail

POCKETID_URL="${POCKETID_URL:-http://localhost:1413}"
API_KEY="${POCKETID_API_KEY:-integ-full-static-key}"
CONTAINER="${POCKETID_CONTAINER:-integ-full-pocketid}"
IDENTREE_URL="${IDENTREE_URL:-http://localhost:8110}"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() {
    local url="$1" name="$2" extra_header="${3:-}"
    echo "==> Waiting for ${name} at ${url}..."
    for i in $(seq 1 30); do
        if curl -sf ${extra_header:+-H "$extra_header"} "${url}" >/dev/null 2>&1; then
            echo "    ${name} ready."
            return
        fi
        sleep 2
    done
    echo "ERROR: ${name} not ready after 60s" >&2
    exit 1
}

pocket_post() {
    local path="$1" data="$2"
    curl -sf "${POCKETID_URL}/api${path}" \
        -H "Content-Type: application/json" \
        -H "X-API-KEY: ${API_KEY}" \
        -d "${data}"
}

pocket_put() {
    local path="$1" data="$2"
    curl -sf -X PUT "${POCKETID_URL}/api${path}" \
        -H "Content-Type: application/json" \
        -H "X-API-KEY: ${API_KEY}" \
        -d "${data}"
}

pocket_get() {
    local path="$1"
    curl -sf "${POCKETID_URL}/api${path}" \
        -H "X-API-KEY: ${API_KEY}"
}

get_user_id() {
    local username="$1"
    # Use search= to bypass pagination (avoids 20-item default page limit)
    pocket_get "/users?search=${username}" | python3 -c "
import sys, json
users = json.load(sys.stdin).get('data', [])
for u in users:
    if u.get('username') == '${username}':
        print(u['id'])
        break
" 2>/dev/null || echo ""
}

get_group_id() {
    local name="$1"
    pocket_get "/user-groups" | python3 -c "
import sys, json
data = json.load(sys.stdin)
groups = data.get('data', data) if isinstance(data, dict) else data
for g in groups:
    if g.get('name') == '${name}':
        print(g['id'])
        break
" 2>/dev/null || echo ""
}

create_user() {
    local username="$1" email="$2" first="$3" last="$4"
    echo "    Creating user: ${username}"
    pocket_post "/users" "{
        \"username\": \"${username}\",
        \"email\": \"${email}\",
        \"firstName\": \"${first}\",
        \"lastName\": \"${last}\",
        \"isAdmin\": false
    }" >/dev/null 2>&1 || echo "    (${username} may already exist)"
}

create_group() {
    local name="$1"
    echo "    Creating group: ${name}"
    # PocketID v2.5+ requires friendlyName alongside name; omitting it returns 400.
    local resp
    resp=$(pocket_post "/user-groups" "{\"name\":\"${name}\",\"friendlyName\":\"${name}\"}" 2>&1) || {
        echo "    WARNING: group creation failed for ${name}: ${resp}" >&2
    }
}

add_to_group() {
    # PocketID v2.5+: PUT /api/user-groups/{id}/users with {"userIds": [...]}
    # Adds incrementally (does not replace existing members).
    local group_id="$1" user_id="$2" username="$3"
    if [ -n "$group_id" ] && [ -n "$user_id" ]; then
        pocket_put "/user-groups/${group_id}/users" "{\"userIds\":[\"${user_id}\"]}" >/dev/null 2>&1 || \
            echo "    WARNING: could not add ${username} to group ${group_id}"
    fi
}

# ── Wait for services ──────────────────────────────────────────────────────────

wait_for "${POCKETID_URL}/api/users" "PocketID" "X-API-KEY: ${API_KEY}"
wait_for "${IDENTREE_URL}/healthz" "identree"

# ── Create groups ──────────────────────────────────────────────────────────────

echo ""
echo "==> Creating groups..."
create_group "developers"
create_group "admins"
sleep 1  # allow PocketID to settle

DEV_ID=$(get_group_id "developers")
ADM_ID=$(get_group_id "admins")
echo "    developers=${DEV_ID:-?}  admins=${ADM_ID:-?}"
if [ -z "$DEV_ID" ] || [ -z "$ADM_ID" ]; then
    echo "ERROR: group creation failed — developers or admins group not found in PocketID" >&2
    exit 1
fi

# ── Create 25 users ────────────────────────────────────────────────────────────
# 20 developers (alice–theo) + 5 admins (sam–wendy)

echo ""
echo "==> Creating 20 developer users..."
create_user "alice"   "alice@integ.local"   "Alice"   "Liddell"
create_user "bob"     "bob@integ.local"     "Bob"     "Builder"
create_user "carol"   "carol@integ.local"   "Carol"   "Danvers"
create_user "dave"    "dave@integ.local"    "Dave"    "Grohl"
create_user "erin"    "erin@integ.local"    "Erin"    "Brockovich"
create_user "frank"   "frank@integ.local"   "Frank"   "Castle"
create_user "grace"   "grace@integ.local"   "Grace"   "Hopper"
create_user "henry"   "henry@integ.local"   "Henry"   "Ford"
create_user "iris"    "iris@integ.local"    "Iris"    "West"
create_user "jack"    "jack@integ.local"    "Jack"    "Sparrow"
create_user "kate"    "kate@integ.local"    "Kate"    "Bishop"
create_user "liam"    "liam@integ.local"    "Liam"    "Neeson"
create_user "mia"     "mia@integ.local"     "Mia"     "Wallace"
create_user "noah"    "noah@integ.local"    "Noah"    "Bennet"
create_user "olivia"  "olivia@integ.local"  "Olivia"  "Pope"
create_user "paul"    "paul@integ.local"    "Paul"    "Atreides"
create_user "quinn"   "quinn@integ.local"   "Quinn"   "Fabray"
create_user "rose"    "rose@integ.local"    "Rose"    "Tyler"
create_user "steve"   "steve@integ.local"   "Steve"   "Rogers"
create_user "theo"    "theo@integ.local"    "Theo"    "Raeken"

echo ""
echo "==> Creating 5 admin users..."
create_user "sam"     "sam@integ.local"     "Sam"     "Winchester"
create_user "tina"    "tina@integ.local"    "Tina"    "Turner"
create_user "ursula"  "ursula@integ.local"  "Ursula"  "Burns"
create_user "victor"  "victor@integ.local"  "Victor"  "Von Doom"
create_user "wendy"   "wendy@integ.local"   "Wendy"   "Darling"

sleep 1  # allow PocketID to settle

# ── Assign group membership ────────────────────────────────────────────────────

echo ""
echo "==> Assigning group membership..."

for u in alice bob carol dave erin frank grace henry iris jack kate liam mia noah olivia paul quinn rose steve theo; do
    uid=$(get_user_id "$u")
    [ -n "$uid" ] && add_to_group "$DEV_ID" "$uid" "$u" || echo "    WARNING: ${u} not found"
done

for u in sam tina ursula victor wendy; do
    uid=$(get_user_id "$u")
    [ -n "$uid" ] && add_to_group "$ADM_ID" "$uid" "$u" || echo "    WARNING: ${u} not found"
done

# ── Set PocketID custom LDAP claims ───────────────────────────────────────────
# PocketID full-mode maps LDAP attributes via custom claims.
# Set uidNumber and gidNumber for each user so SSSD resolves numeric IDs.

echo ""
echo "==> Setting POSIX custom claims on users..."

set_posix_claims() {
    local username="$1" uid_num="$2" gid_num="$3"
    local user_id
    user_id=$(get_user_id "$username")
    if [ -z "$user_id" ]; then
        echo "    WARNING: user ${username} not found for claims"
        return
    fi
    pocket_put "/custom-claims/user/${user_id}" \
        "[{\"key\":\"uidNumber\",\"value\":\"${uid_num}\"},{\"key\":\"gidNumber\",\"value\":\"${gid_num}\"},{\"key\":\"homeDirectory\",\"value\":\"/home/${username}\"},{\"key\":\"loginShell\",\"value\":\"/bin/bash\"}]" \
        >/dev/null 2>&1 || echo "    WARNING: could not set claims for ${username}"
}

# developers (gid 20001)
uid=11001
for u in alice bob carol dave erin frank grace henry iris jack kate liam mia noah olivia paul quinn rose steve theo; do
    set_posix_claims "$u" "$uid" "20001"
    uid=$((uid + 1))
done

# admins (gid 20002)
uid=11021
for u in sam tina ursula victor wendy; do
    set_posix_claims "$u" "$uid" "20002"
    uid=$((uid + 1))
done

# ── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  full-mode integration: PocketID users ready"
echo ""
echo "  PocketID admin UI:  ${POCKETID_URL}"
echo "  identree:           ${IDENTREE_URL}"
echo ""
echo "  Users (20 developers + 5 admins):"
echo "    developers: alice bob carol dave erin frank grace henry iris jack"
echo "                kate liam mia noah olivia paul quinn rose steve theo"
echo "    admins:     sam tina ursula victor wendy"
echo ""
echo "  Validate:"
echo "    docker exec integ-full-ubuntu2204 getent passwd alice"
echo "    docker exec integ-full-ubuntu2204 getent group developers"
echo "════════════════════════════════════════════════════════════"
