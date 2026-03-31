#!/bin/bash
# setup.sh — configure Kanidm for the identree test environment.
# Run after: make test-kanidm
#
# What this does:
#   1. Recovers the admin account (resets to a generated password)
#   2. Authenticates via Kanidm REST API to get a bearer token
#   3. Creates POSIX groups: developers (gid=20001), admins (gid=20002)
#   4. Creates POSIX users: alice (uid=10001), bob (uid=10002), testadmin (uid=10003)
#   5. Assigns group membership
#   6. Creates the identree-test OAuth2/OIDC client
#   7. Configures scope maps so groups appear in tokens
#   8. Outputs KANIDM_CLIENT_SECRET
#
# All provisioning uses the Kanidm v1 REST API directly (no CLI) to avoid
# dependency on specific CLI versions in kanidm/tools:latest.
#
# kanidm login requires /dev/tty (rpassword), which is not available in CI
# non-interactive Docker containers. We authenticate via the Kanidm REST API
# from the host instead.
set -euo pipefail

KC_URL="https://localhost:8443"
CONTAINER="identree-kanidm-server"

COOKIE_FILE=$(mktemp)
HEADER_FILE=$(mktemp)
trap 'rm -f "${COOKIE_FILE}" "${HEADER_FILE}"' EXIT

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() { echo "==> Waiting for ${2}..."; until curl -skf "$1" >/dev/null 2>&1; do sleep 2; done; echo "    ${2} ready."; }

# Kanidm v1 REST API call with bearer token auth.
kapi() {
    local method="$1" path="$2"
    shift 2
    curl -sk -X "${method}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        "${KC_URL}${path}" "$@" 2>&1
}

# ── Wait for Kanidm ────────────────────────────────────────────────────────────
wait_for "${KC_URL}/status" "Kanidm"

# ── Recover admin account ──────────────────────────────────────────────────────
# kanidmd recover-account resets the account password and prints the new one.
# We recover 'admin' (system superadmin) which can manage persons, groups,
# POSIX attributes, and OAuth2 clients.
echo "==> Recovering idm_admin account..."
# idm_admin is the IDM superadmin that can manage persons, groups, POSIX
# attributes, and OAuth2 clients.  (admin is the system superadmin and is
# not allowed to create OAuth2 resource server entries.)
ADMIN_RECOVERY=$(docker exec "${CONTAINER}" \
    kanidmd recover-account idm_admin 2>&1 || true)

# Extract the generated password — try "Password: <value>" first, then fall back
# to any 20+ char alphanumeric token as a last resort.
ADMIN_PW=$(printf '%s' "$ADMIN_RECOVERY" | grep -oP '(?<=Password: )\S+' 2>/dev/null | head -1 || true)
if [ -z "$ADMIN_PW" ]; then
    ADMIN_PW=$(printf '%s' "$ADMIN_RECOVERY" | grep -i 'password' | grep -oE '[A-Za-z0-9]{20,}' | head -1 || true)
fi

if [ -z "$ADMIN_PW" ]; then
    echo "ERROR: Could not extract idm_admin password from recover-account output."
    echo "Recovery output:"
    echo "$ADMIN_RECOVERY"
    echo ""
    echo "Try manually: docker exec ${CONTAINER} kanidmd recover-account idm_admin"
    exit 1
fi
echo "    idm_admin recovered."

# ── Authenticate via Kanidm REST API ──────────────────────────────────────────
# kanidm login requires /dev/tty (rpassword library) which is not available
# in CI containers run without a pseudo-TTY. We use the Kanidm REST API
# directly to get a bearer token.
#
# Session tracking: Kanidm uses HMAC-signed session tokens.  The raw UUID
# in the JSON response body is NOT what the server accepts as the session
# identifier for subsequent requests — it expects the HMAC-signed value
# returned in the X-KANIDM-AUTH-SESSION-ID response header.  Cookies are
# also set (auth-session-id) as an alternative mechanism.
# We capture both and forward them on the Begin and Cred steps.
echo "==> Authenticating as admin via Kanidm REST API..."

# Kanidm AuthStep enum uses #[serde(rename_all = "lowercase")] so all variant
# names and inner enum values must be lowercase in the JSON body.

# Step 1: Init auth session — save response cookies and headers
INIT_RESP=$(curl -sk \
    -c "${COOKIE_FILE}" \
    -D "${HEADER_FILE}" \
    -X POST "${KC_URL}/v1/auth" \
    -H "Content-Type: application/json" \
    -d '{"step":{"init2":{"username":"idm_admin","issue":"token","privileged":false}}}')
echo "    Init response: $INIT_RESP"

# Extract HMAC-signed session token from response header (what the server
# expects back) and raw UUID (for display / fallback).
SESSION_HDR=$(grep -i 'X-KANIDM-AUTH-SESSION-ID' "${HEADER_FILE}" | \
    awk '{print $2}' | tr -d '\r\n' || echo "")
SESSION_ID=$(printf '%s' "$INIT_RESP" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['sessionid'])" 2>/dev/null || echo "")

echo "    Session header: ${SESSION_HDR:-(not set)}"
echo "    Session UUID:   ${SESSION_ID:-(not set)}"
# (SPN for idm_admin in domain "localhost" is idm_admin@localhost)

if [ -z "$SESSION_ID" ]; then
    echo "ERROR: Failed to init auth session."
    exit 1
fi

# Use HMAC-signed header value if the server returned one; otherwise fall back
# to the raw UUID (works on some older Kanidm builds).
SESSION_TOKEN="${SESSION_HDR:-$SESSION_ID}"

# Step 2: Select Password mechanism — forward cookies + HMAC-signed session header
curl -sk \
    -c "${COOKIE_FILE}" -b "${COOKIE_FILE}" \
    -X POST "${KC_URL}/v1/auth" \
    -H "Content-Type: application/json" \
    -H "X-KANIDM-AUTH-SESSION-ID: ${SESSION_TOKEN}" \
    -d '{"step":{"begin":"password"}}' >/dev/null

# Step 3: Submit password credential → receive bearer token
CRED_RESP=$(curl -sk \
    -c "${COOKIE_FILE}" -b "${COOKIE_FILE}" \
    -X POST "${KC_URL}/v1/auth" \
    -H "Content-Type: application/json" \
    -H "X-KANIDM-AUTH-SESSION-ID: ${SESSION_TOKEN}" \
    -d "{\"step\":{\"cred\":{\"password\":\"${ADMIN_PW}\"}}}")
echo "    Cred response: $(printf '%s' "$CRED_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print({k: v[:20]+'...' if isinstance(v,str) and len(v)>20 else v for k,v in d.items()})" 2>/dev/null || echo "$CRED_RESP")"

ADMIN_TOKEN=$(printf '%s' "$CRED_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
state = d.get('state', {})
# Kanidm serde rename_all=lowercase: variant is 'success' not 'Success'
if isinstance(state, dict):
    token = state.get('success') or state.get('Success')
    if token:
        print(token)
" 2>/dev/null || echo "")

if [ -z "$ADMIN_TOKEN" ]; then
    echo "ERROR: Failed to get admin bearer token."
    echo "Credential response: $CRED_RESP"
    exit 1
fi
echo "    admin authenticated."

# ── Create groups with POSIX GIDs ─────────────────────────────────────────────
echo "==> Creating groups..."
# POST /v1/group creates a new group.  Setting gidnumber enables POSIX access
# (server automatically adds posixgroup class).
echo "    developers:"; kapi POST /v1/group \
    -d '{"attrs":{"name":["developers"],"displayname":["developers"]}}' | head -c 200; echo
echo "    admins:";     kapi POST /v1/group \
    -d '{"attrs":{"name":["admins"],"displayname":["admins"]}}' | head -c 200; echo

echo "    posix gids:"; \
    kapi PUT /v1/group/developers/_attr/gidnumber -d '["20001"]' | head -c 200; echo; \
    kapi PUT /v1/group/admins/_attr/gidnumber     -d '["20002"]' | head -c 200; echo

# ── Create users with POSIX attributes ────────────────────────────────────────
echo "==> Creating users..."
echo "    alice:";     kapi POST /v1/person \
    -d '{"attrs":{"name":["alice"],"displayname":["Alice Liddell"]}}' | head -c 200; echo
echo "    bob:";       kapi POST /v1/person \
    -d '{"attrs":{"name":["bob"],"displayname":["Bob Builder"]}}' | head -c 200; echo
echo "    testadmin:"; kapi POST /v1/person \
    -d '{"attrs":{"name":["testadmin"],"displayname":["Test Admin"]}}' | head -c 200; echo

# Enable POSIX attributes — required for sssd to resolve UID/GID/shell/home.
# Setting uidnumber on a person enables posixaccount in the Kanidm schema.
echo "    Setting POSIX for alice..."
kapi PUT /v1/person/alice/_attr/uidnumber    -d '["10001"]'         | head -c 100; echo
kapi PUT /v1/person/alice/_attr/gidnumber    -d '["20001"]'         | head -c 100; echo
kapi PUT /v1/person/alice/_attr/loginshell   -d '["/bin/bash"]'     | head -c 100; echo
kapi PUT /v1/person/alice/_attr/homedirectory -d '["/home/alice"]'  | head -c 100; echo

echo "    Setting POSIX for bob..."
kapi PUT /v1/person/bob/_attr/uidnumber    -d '["10002"]'        | head -c 100; echo
kapi PUT /v1/person/bob/_attr/gidnumber    -d '["20001"]'        | head -c 100; echo
kapi PUT /v1/person/bob/_attr/loginshell   -d '["/bin/bash"]'    | head -c 100; echo
kapi PUT /v1/person/bob/_attr/homedirectory -d '["/home/bob"]'   | head -c 100; echo

echo "    Setting POSIX for testadmin..."
kapi PUT /v1/person/testadmin/_attr/uidnumber    -d '["10003"]'             | head -c 100; echo
kapi PUT /v1/person/testadmin/_attr/gidnumber    -d '["20002"]'             | head -c 100; echo
kapi PUT /v1/person/testadmin/_attr/loginshell   -d '["/bin/bash"]'         | head -c 100; echo
kapi PUT /v1/person/testadmin/_attr/homedirectory -d '["/home/testadmin"]'  | head -c 100; echo

# ── Assign group membership ────────────────────────────────────────────────────
echo "==> Assigning group membership..."
# POST appends members; members are referenced by SPN (name@domain).
echo "    developers members:"; kapi POST /v1/group/developers/_attr/member \
    -d '["alice@localhost","bob@localhost"]' | head -c 200; echo
echo "    admins members:";     kapi POST /v1/group/admins/_attr/member \
    -d '["testadmin@localhost"]' | head -c 200; echo

# ── Create OAuth2/OIDC client ──────────────────────────────────────────────────
echo "==> Creating OAuth2 client identree-test..."
# POST /v1/oauth2/_basic creates a confidential (basic auth) OAuth2 client.
echo "    create:"; kapi POST /v1/oauth2/_basic \
    -d '{
        "attrs": {
            "name":         ["identree-test"],
            "displayname":  ["identree (test)"],
            "oauth2_rs_origin": ["http://localhost:8093/callback"]
        }
    }' | head -c 200; echo

# Add Docker-internal redirect URI (used by identree container)
echo "    add redirect:"; kapi POST /v1/oauth2/identree-test/_attr/oauth2_rs_origin \
    -d '["http://identree:8090/callback"]' | head -c 200; echo

# Configure scope maps: groups get openid+profile+email+groups scopes.
echo "    scope maps:"; \
    kapi POST /v1/oauth2/identree-test/_attr/oauth2_rs_scope_map \
        -d '["developers@localhost:openid profile email groups"]' | head -c 200; echo; \
    kapi POST /v1/oauth2/identree-test/_attr/oauth2_rs_scope_map \
        -d '["admins@localhost:openid profile email groups"]' | head -c 200; echo

# Retrieve the client secret
SECRET_RESP=$(kapi GET /v1/oauth2/identree-test/_basic_secret)
echo "    _basic_secret raw: $(printf '%s' "$SECRET_RESP" | head -c 60)"
CLIENT_SECRET=$(printf '%s' "$SECRET_RESP" | \
    python3 -c "
import sys, json
v = json.load(sys.stdin)
if isinstance(v, str) and v:
    print(v)
" 2>/dev/null || echo "")

# ── Summary ────────────────────────────────════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Kanidm test environment ready"
echo ""
echo "  Services:"
echo "    Kanidm:    https://localhost:8443   (admin recovered above)"
echo "    identree:  http://localhost:8093"
echo "    LDAP:      ldap://localhost:3636   base=dc=localhost"
echo ""
echo "  OIDC client credentials:"
echo "    client_id:     identree-test"
echo "    client_secret: ${CLIENT_SECRET:-<retrieve: GET /v1/oauth2/identree-test/_basic_secret>}"
echo ""
echo "  Restart identree with the client secret:"
echo "    KANIDM_CLIENT_SECRET=${CLIENT_SECRET:-<secret>} \\"
echo "    docker compose -f test/providers/kanidm/docker-compose.yml up -d identree"
echo ""
echo "  Validate:"
echo "    docker exec identree-kanidm-client getent passwd alice"
echo "    docker exec identree-kanidm-client getent group developers"
echo "    docker exec -it identree-kanidm-client bash"
echo "    sudo whoami  (as alice → triggers identree PAM challenge)"
echo "════════════════════════════════════════════════════════════"
