#!/bin/bash
# setup.sh — configure Kanidm for the identree test environment.
# Run after: make test-kanidm
#
# What this does:
#   1. Recovers admin (system superadmin) and idm_admin (IDM superadmin) accounts
#   2. Authenticates both via Kanidm REST API
#   3. Creates POSIX groups: developers (gid=20001), admins (gid=20002) [via admin]
#   4. Creates POSIX users: alice (uid auto), bob (uid auto), testadmin (uid auto)
#   5. Assigns group membership [via admin]
#   6. Creates the identree-test OAuth2/OIDC client [via idm_admin]
#   7. Configures scope maps so groups appear in tokens [via idm_admin]
#   8. Outputs KANIDM_CLIENT_SECRET
#
# All provisioning uses the Kanidm v1 REST API directly (no CLI) to avoid
# dependency on specific CLI versions in kanidm/tools:latest.
#
# Two accounts are required:
#   admin     — system superadmin; member of system_admins@localhost; needed
#               to create/manage groups (entry_managed_by requirement)
#   idm_admin — IDM superadmin; creates persons, enables POSIX, manages OAuth2
#
# kanidm login requires /dev/tty (rpassword), which is not available in CI
# non-interactive Docker containers. We authenticate via the Kanidm REST API
# from the host instead.
set -euo pipefail

KC_URL="https://localhost:8443"
CONTAINER="identree-kanidm-server"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() { echo "==> Waiting for ${2}..."; until curl -skf "$1" >/dev/null 2>&1; do sleep 2; done; echo "    ${2} ready."; }

# Extract password from kanidmd recover-account output.
extract_pw() {
    local output="$1"
    local pw
    pw=$(printf '%s' "$output" | grep -oP '(?<=Password: )\S+' 2>/dev/null | head -1 || true)
    if [ -z "$pw" ]; then
        pw=$(printf '%s' "$output" | grep -i 'password' | grep -oE '[A-Za-z0-9]{20,}' | head -1 || true)
    fi
    echo "$pw"
}

# Authenticate a Kanidm account via REST API and return a bearer token.
# Usage: kanidm_auth <username> <password>
kanidm_auth() {
    local username="$1" password="$2"
    local cookie_f header_f init_resp session_hdr session_id session_token cred_resp token

    cookie_f=$(mktemp)
    header_f=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '${cookie_f}' '${header_f}'" RETURN

    # Step 1: Init auth session — Kanidm AuthStep enum uses rename_all=lowercase
    init_resp=$(curl -sk \
        -c "${cookie_f}" \
        -D "${header_f}" \
        -X POST "${KC_URL}/v1/auth" \
        -H "Content-Type: application/json" \
        -d "{\"step\":{\"init2\":{\"username\":\"${username}\",\"issue\":\"token\",\"privileged\":false}}}")

    # HMAC-signed session token is in the response header; raw UUID is in the body.
    # The server requires the HMAC-signed value back on subsequent requests.
    session_hdr=$(grep -i 'X-KANIDM-AUTH-SESSION-ID' "${header_f}" | \
        awk '{print $2}' | tr -d '\r\n' || echo "")
    session_id=$(printf '%s' "$init_resp" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['sessionid'])" 2>/dev/null || echo "")

    if [ -z "$session_id" ]; then
        echo "ERROR: Failed to init auth session for ${username}." >&2
        echo "Init response: ${init_resp}" >&2
        rm -f "${cookie_f}" "${header_f}"
        return 1
    fi

    session_token="${session_hdr:-$session_id}"

    # Step 2: Select Password mechanism
    curl -sk \
        -c "${cookie_f}" -b "${cookie_f}" \
        -X POST "${KC_URL}/v1/auth" \
        -H "Content-Type: application/json" \
        -H "X-KANIDM-AUTH-SESSION-ID: ${session_token}" \
        -d '{"step":{"begin":"password"}}' >/dev/null

    # Step 3: Submit password credential → receive bearer token
    cred_resp=$(curl -sk \
        -c "${cookie_f}" -b "${cookie_f}" \
        -X POST "${KC_URL}/v1/auth" \
        -H "Content-Type: application/json" \
        -H "X-KANIDM-AUTH-SESSION-ID: ${session_token}" \
        -d "{\"step\":{\"cred\":{\"password\":\"${password}\"}}}")

    rm -f "${cookie_f}" "${header_f}"

    token=$(printf '%s' "$cred_resp" | python3 -c "
import sys, json
d = json.load(sys.stdin)
state = d.get('state', {})
if isinstance(state, dict):
    token = state.get('success') or state.get('Success')
    if token:
        print(token)
" 2>/dev/null || echo "")

    if [ -z "$token" ]; then
        echo "ERROR: Failed to get bearer token for ${username}." >&2
        echo "Cred response: ${cred_resp}" >&2
        return 1
    fi

    echo "$token"
}

# Kanidm v1 REST API call.
# Uses global TOKEN variable — set TOKEN before calling.
kapi() {
    local method="$1" path="$2"
    shift 2
    curl -sk -X "${method}" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        "${KC_URL}${path}" "$@" 2>&1
}

# ── Wait for Kanidm ────────────────────────────────────────────────────────────
wait_for "${KC_URL}/status" "Kanidm"

# ── Recover accounts ──────────────────────────────────────────────────────────
# admin:     system superadmin — can create/manage groups (system_admins@localhost)
# idm_admin: IDM superadmin   — can create persons, enable POSIX, manage OAuth2
echo "==> Recovering admin account..."
SYS_RECOVERY=$(docker exec "${CONTAINER}" kanidmd recover-account admin 2>&1 || true)
SYS_PW=$(extract_pw "$SYS_RECOVERY")
if [ -z "$SYS_PW" ]; then
    echo "ERROR: Could not extract admin password."
    echo "$SYS_RECOVERY"
    exit 1
fi
echo "    admin recovered."

echo "==> Recovering idm_admin account..."
IDM_RECOVERY=$(docker exec "${CONTAINER}" kanidmd recover-account idm_admin 2>&1 || true)
IDM_PW=$(extract_pw "$IDM_RECOVERY")
if [ -z "$IDM_PW" ]; then
    echo "ERROR: Could not extract idm_admin password."
    echo "$IDM_RECOVERY"
    exit 1
fi
echo "    idm_admin recovered."

# ── Authenticate both accounts ─────────────────────────────────────────────────
echo "==> Authenticating admin (system superadmin)..."
SYS_TOKEN=$(kanidm_auth "admin" "$SYS_PW")
echo "    admin authenticated."

echo "==> Authenticating idm_admin..."
IDM_TOKEN=$(kanidm_auth "idm_admin" "$IDM_PW")
echo "    idm_admin authenticated."

# ── Diagnostics: check idm_admin group memberships ────────────────────────────
echo "==> Checking idm_admin memberOf..."
TOKEN="$IDM_TOKEN"
kapi GET /v1/account/idm_admin | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    mo = d.get('attrs', {}).get('memberof', [])
    print('    memberof:', mo[:10])
except Exception as e:
    print('    (parse error:', e, ')')
" 2>/dev/null || echo "    (query failed)"

# ── Create groups with POSIX GIDs ─────────────────────────────────────────────
# Group creation ACP (idm_acp_group_manage) receiver is idm_group_admins.
# idm_admin is transitively in idm_group_admins via idm_admins → idm_group_admins.
# Do NOT set entry_managed_by: pointing it at an HP group (like idm_admins)
# makes the new group HP, which the ACP target filter excludes — causing accessdenied.
echo "==> Creating groups (as idm_admin)..."
TOKEN="$IDM_TOKEN"
echo "    developers:"
kapi POST /v1/group \
    -d '{"attrs":{"name":["developers"],"displayname":["developers"]}}'
echo
echo "    admins:"
kapi POST /v1/group \
    -d '{"attrs":{"name":["admins"],"displayname":["admins"]}}'
echo

echo "    posix gids (developers):"
kapi POST /v1/group/developers/_unix -d '{"gidnumber": 20001}'
echo
echo "    posix gids (admins):"
kapi POST /v1/group/admins/_unix -d '{"gidnumber": 20002}'
echo

# ── Create users ──────────────────────────────────────────────────────────────
# Persons are managed by idm_admin.
echo "==> Creating users (as idm_admin)..."
TOKEN="$IDM_TOKEN"
echo "    alice:";     kapi POST /v1/person \
    -d '{"attrs":{"name":["alice"],"displayname":["Alice Liddell"]}}' | head -c 200; echo
echo "    bob:";       kapi POST /v1/person \
    -d '{"attrs":{"name":["bob"],"displayname":["Bob Builder"]}}' | head -c 200; echo
echo "    testadmin:"; kapi POST /v1/person \
    -d '{"attrs":{"name":["testadmin"],"displayname":["Test Admin"]}}' | head -c 200; echo

# ── Enable POSIX for users ────────────────────────────────────────────────────
# POST /v1/person/{name}/_unix enables the posixaccount class.
# AccountUnixExtend struct: {gidnumber: Option<u32>, shell: Option<String>}
# uidnumber is auto-assigned by Kanidm — do NOT pass it in the body.
# gidnumber must be unique across ALL POSIX entries (users + groups), so we
# omit it here and let Kanidm auto-assign a unique primary GID per user.
echo "==> Enabling POSIX for users (as idm_admin)..."
TOKEN="$IDM_TOKEN"
echo "    alice:";     kapi POST /v1/person/alice/_unix \
    -d '{"shell": "/bin/bash"}' | head -c 200; echo
echo "    bob:";       kapi POST /v1/person/bob/_unix \
    -d '{"shell": "/bin/bash"}' | head -c 200; echo
echo "    testadmin:"; kapi POST /v1/person/testadmin/_unix \
    -d '{"shell": "/bin/bash"}' | head -c 200; echo

# Set homedirectory via _attr (posixaccount class now present after _unix call).
echo "    homedirs:"; \
    kapi PUT /v1/person/alice/_attr/homedirectory    -d '["/home/alice"]'      | head -c 100; echo; \
    kapi PUT /v1/person/bob/_attr/homedirectory      -d '["/home/bob"]'        | head -c 100; echo; \
    kapi PUT /v1/person/testadmin/_attr/homedirectory -d '["/home/testadmin"]' | head -c 100; echo

# ── Assign group membership ────────────────────────────────────────────────────
# Groups were created by idm_admin (non-HP, no entry_managed_by), so
# idm_admin (in idm_group_admins) can also manage their membership.
echo "==> Assigning group membership (as idm_admin)..."
TOKEN="$IDM_TOKEN"
# POST appends members; members are referenced by SPN (name@domain).
echo "    developers members:"; kapi POST /v1/group/developers/_attr/member \
    -d '["alice@localhost","bob@localhost"]' | head -c 200; echo
echo "    admins members:";     kapi POST /v1/group/admins/_attr/member \
    -d '["testadmin@localhost"]' | head -c 200; echo

# ── Create OAuth2/OIDC client ──────────────────────────────────────────────────
# POST /v1/oauth2/_basic creates a confidential (basic auth) OAuth2 client.
# oauth2_rs_origin_landing is a MUST attribute in Kanidm 1.4+.
# idm_admin has the idm_acp_oauth2_manage privilege needed for OAuth2 management.
echo "==> Creating OAuth2 client identree-test (as idm_admin)..."
TOKEN="$IDM_TOKEN"
echo "    create:"; kapi POST /v1/oauth2/_basic \
    -d '{
        "attrs": {
            "name":                     ["identree-test"],
            "displayname":              ["identree (test)"],
            "oauth2_rs_origin":         ["http://localhost:8093/callback"],
            "oauth2_rs_origin_landing": ["http://localhost:8093"]
        }
    }' | head -c 200; echo

# Add Docker-internal redirect URI (used by identree container)
echo "    add redirect:"; kapi POST /v1/oauth2/identree-test/_attr/oauth2_rs_origin \
    -d '["http://identree:8090/callback"]' | head -c 200; echo

# Configure scope maps: groups get openid+profile+email+groups scopes.
# In Kanidm 1.9+, scope maps cannot be set via attribute modification; use
# the dedicated IDM endpoint: POST /v1/oauth2/{name}/_scopemap/{group_spn}
# Body is a JSON array of scope strings.
echo "    scope maps:"; \
    kapi POST "/v1/oauth2/identree-test/_scopemap/developers%40localhost" \
        -d '["openid","profile","email","groups"]' | head -c 200; echo; \
    kapi POST "/v1/oauth2/identree-test/_scopemap/admins%40localhost" \
        -d '["openid","profile","email","groups"]' | head -c 200; echo

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
