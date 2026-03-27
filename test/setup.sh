#!/bin/bash
# setup.sh — configure PocketID for identree testing
# Run AFTER docker-compose up: ./setup.sh
set -euo pipefail

POCKETID_URL="http://localhost:1411"
API_KEY="identree-test-static-key"
REDIRECT_URI="http://localhost:8090/callback"

api() {
    local method="$1"; local path="$2"; shift 2
    curl -sf -X "$method" \
        -H "Content-Type: application/json" \
        -H "X-API-KEY: $API_KEY" \
        "${POCKETID_URL}${path}" "$@"
}

echo "==> Waiting for PocketID..."
until curl -sf "${POCKETID_URL}/healthz" >/dev/null 2>&1; do sleep 1; done
echo "    PocketID ready."

# ── Create test users ──────────────────────────────────────────────────────────

echo "==> Creating test users..."

ALICE_ID=$(api POST /api/users -d '{
  "username": "alice",
  "firstName": "Alice",
  "lastName": "Liddell",
  "email": "alice@test.local",
  "isAdmin": false
}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

BOB_ID=$(api POST /api/users -d '{
  "username": "bob",
  "firstName": "Bob",
  "lastName": "Builder",
  "email": "bob@test.local",
  "isAdmin": false
}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

ADMIN_ID=$(api POST /api/users -d '{
  "username": "testadmin",
  "firstName": "Test",
  "lastName": "Admin",
  "email": "admin@test.local",
  "isAdmin": true
}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

echo "    alice=${ALICE_ID} bob=${BOB_ID} admin=${ADMIN_ID}"

# ── Custom claims on users ─────────────────────────────────────────────────────

echo "==> Setting custom claims on alice..."
if [ -n "$ALICE_ID" ]; then
    api PUT "/api/custom-claims/user/${ALICE_ID}" -d '[
      {"key":"loginShell","value":"/bin/zsh"},
      {"key":"homeDirectory","value":"/home/alice"},
      {"key":"sshPublicKey","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyForAlice alice@test.local"}
    ]' >/dev/null || true
fi

# ── Create groups ──────────────────────────────────────────────────────────────

echo "==> Creating groups..."

DEV_ID=$(api POST /api/user-groups -d '{
  "name": "developers",
  "friendlyName": "Developers"
}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

ADMIN_GRP_ID=$(api POST /api/user-groups -d '{
  "name": "admins",
  "friendlyName": "Admins"
}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

echo "    developers=${DEV_ID} admins=${ADMIN_GRP_ID}"

# ── Add sudo claims to developers group ────────────────────────────────────────

if [ -n "$DEV_ID" ]; then
    api PUT "/api/custom-claims/user-group/${DEV_ID}" -d '[
      {"key":"sudoCommands","value":"/usr/bin/apt,/usr/bin/systemctl"},
      {"key":"sudoHosts","value":"ALL"},
      {"key":"sudoRunAsUser","value":"root"}
    ]' >/dev/null || true
fi

# ── Add users to groups ────────────────────────────────────────────────────────

echo "==> Adding users to groups..."
if [ -n "$DEV_ID" ] && [ -n "$ALICE_ID" ] && [ -n "$BOB_ID" ]; then
    api PUT "/api/user-groups/${DEV_ID}/users" \
        -d "{\"userIds\":[\"${ALICE_ID}\",\"${BOB_ID}\"]}" >/dev/null || true
fi
if [ -n "$ADMIN_GRP_ID" ] && [ -n "$ADMIN_ID" ]; then
    api PUT "/api/user-groups/${ADMIN_GRP_ID}/users" \
        -d "{\"userIds\":[\"${ADMIN_ID}\"]}" >/dev/null || true
fi

# ── Create OIDC client ─────────────────────────────────────────────────────────

echo "==> Creating OIDC client for identree..."
OIDC_RESULT=$(api POST /api/oidc/clients -d "{
  \"name\": \"identree-test\",
  \"callbackURLs\": [\"${REDIRECT_URI}\"],
  \"logoutCallbackURLs\": [],
  \"isPublic\": false,
  \"pkceEnabled\": false
}" 2>/dev/null || echo "")

CLIENT_ID=$(echo "$OIDC_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || echo "")

if [ -z "$CLIENT_ID" ]; then
    echo "    WARNING: Could not create OIDC client."
    echo "    Raw response: $OIDC_RESULT"
else
    # PocketID v2.5.0: secret must be created separately
    SECRET_RESULT=$(api POST "/api/oidc/clients/${CLIENT_ID}/secret" -d '' 2>/dev/null || echo "")
    CLIENT_SECRET=$(echo "$SECRET_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('secret','?'))" 2>/dev/null || echo "?")

    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  OIDC client created:"
    echo "    client_id:     ${CLIENT_ID}"
    echo "    client_secret: ${CLIENT_SECRET}"
    echo ""
    echo "  Restart identree with these values:"
    echo ""
    echo "    OIDC_CLIENT_ID=${CLIENT_ID} OIDC_CLIENT_SECRET=${CLIENT_SECRET} \\"
    echo "    docker --context orbstack compose up -d identree"
    echo "════════════════════════════════════════════════════════════"
fi

echo ""
echo "==> Setup complete."
echo "    PocketID UI:  http://localhost:1411"
echo "    identree UI:  http://localhost:8090"
echo "    LDAP:         ldap://localhost:3389  base=dc=test,dc=local"
echo ""
echo "    Test LDAP: docker exec identree-test-client getent passwd"
echo "    Shell in:  docker exec -it identree-test-client bash"
