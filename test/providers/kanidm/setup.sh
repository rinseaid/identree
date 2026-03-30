#!/bin/bash
# setup.sh — configure Kanidm for the identree test environment.
# Run after: make test-kanidm
#
# What this does:
#   1. Recovers the idm_admin account (resets to a generated password)
#   2. Creates POSIX groups: developers (gid=20001), admins (gid=20002)
#   3. Creates POSIX users: alice (uid=10001), bob (uid=10002), testadmin (uid=10003)
#   4. Assigns group membership
#   5. Creates the identree-test OAuth2/OIDC client
#   6. Configures scope maps so groups appear in tokens
#   7. Outputs KANIDM_CLIENT_SECRET
#
# All kanidm CLI commands run inside the kanidm container via docker exec.
# The kanidm CLI caches its session token in /tmp/kanidm-home/.config/ across
# exec invocations (the container filesystem persists between exec calls).
set -euo pipefail

KC_URL="https://localhost:8443"
CONTAINER="identree-kanidm-server"
HOME_DIR="/tmp/kanidm-home"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() { echo "==> Waiting for ${2}..."; until curl -skf "$1" >/dev/null 2>&1; do sleep 2; done; echo "    ${2} ready."; }

# Run a kanidm CLI command inside the container with a consistent HOME dir
# so the session token cache persists between exec invocations.
ke() {
    docker exec -e HOME="${HOME_DIR}" "${CONTAINER}" \
        kanidm "$@" -H "https://localhost:8443" --skip-hostname-verification 2>&1
}

# ── Wait for Kanidm ────────────────────────────────────────────────────────────
wait_for "${KC_URL}/status" "Kanidm"

# ── Recover idm_admin ──────────────────────────────────────────────────────────
# kanidmd recover-account resets the account password and prints the new one.
# It connects to the running server (not directly to the DB).
echo "==> Recovering idm_admin account..."
docker exec "${CONTAINER}" mkdir -p "${HOME_DIR}/.config"

RECOVERY=$(docker exec "${CONTAINER}" \
    kanidmd recover-account idm_admin 2>&1 || true)

# Extract the generated password — it appears after "New password: " or similar
IDM_ADMIN_PW=$(printf '%s' "$RECOVERY" | grep -oE '[A-Za-z0-9+/=_-]{20,}' | tail -1)

if [ -z "$IDM_ADMIN_PW" ]; then
    echo "ERROR: Could not extract idm_admin password from recover-account output."
    echo "Recovery output was:"
    echo "$RECOVERY"
    echo ""
    echo "Try running manually:"
    echo "  docker exec ${CONTAINER} kanidmd recover-account idm_admin"
    exit 1
fi
echo "    idm_admin recovered."

# ── Login ──────────────────────────────────────────────────────────────────────
echo "==> Logging in as idm_admin..."
printf '%s\n' "$IDM_ADMIN_PW" | \
    docker exec -i -e HOME="${HOME_DIR}" "${CONTAINER}" \
    kanidm login -D idm_admin -H https://localhost:8443 --skip-hostname-verification || {
    echo "ERROR: kanidm login failed. The kanidm CLI in this container version"
    echo "may require interactive authentication."
    echo "Try manually: docker exec -it ${CONTAINER} kanidm login -D idm_admin -H https://localhost:8443"
    exit 1
}

# ── Create groups with POSIX GIDs ─────────────────────────────────────────────
echo "==> Creating groups..."
ke group create developers -D idm_admin || true
ke group create admins     -D idm_admin || true

ke group posix-set developers --gid 20001 -D idm_admin || true
ke group posix-set admins     --gid 20002 -D idm_admin || true

# ── Create users with POSIX attributes ────────────────────────────────────────
echo "==> Creating users..."

# person create <loginname> <display name>
ke person create alice     "Alice Liddell"  -D idm_admin || true
ke person create bob       "Bob Builder"    -D idm_admin || true
ke person create testadmin "Test Admin"     -D idm_admin || true

# Enable POSIX attributes — required for sssd to resolve UID/GID/shell/home
ke person posix-set alice     --uid 10001 --gid 20001 --shell /bin/bash --home /home/alice     -D idm_admin || true
ke person posix-set bob       --uid 10002 --gid 20001 --shell /bin/bash --home /home/bob       -D idm_admin || true
ke person posix-set testadmin --uid 10003 --gid 20002 --shell /bin/bash --home /home/testadmin -D idm_admin || true

# ── Assign group membership ────────────────────────────────────────────────────
echo "==> Assigning group membership..."
ke group add-members developers alice bob        -D idm_admin || true
ke group add-members admins     testadmin        -D idm_admin || true

# ── Create OAuth2/OIDC client ──────────────────────────────────────────────────
echo "==> Creating OAuth2 client identree-test..."
# Kanidm OAuth2 client: name, display name, redirect URI
ke system oauth2 create identree-test "identree (test)" \
    "http://localhost:8093/callback" -D admin || true

# Add the Docker-internal redirect URI
ke system oauth2 update-redirect-url identree-test \
    "http://identree:8090/callback" -D admin || true

# Allow public clients or confidential clients — use basic secret (client_secret_basic)
# The secret is auto-generated; we retrieve it below.

# Configure scope maps: which groups get which scopes in the token.
# identree needs the 'groups' scope to see group membership.
for group in developers admins; do
    ke system oauth2 update-scope-map identree-test "${group}" \
        openid profile email groups -D admin || true
done

# Retrieve the client secret
CLIENT_SECRET=$(ke system oauth2 show-basic-secret identree-test -D admin 2>&1 | \
    grep -oE '[A-Za-z0-9+/=_-]{20,}' | head -1 || echo "")

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Kanidm test environment ready"
echo ""
echo "  Services:"
echo "    Kanidm:    https://localhost:8443   (admin recovered above)"
echo "    identree:  http://localhost:8093"
echo "    LDAP:      ldap://localhost:3636   base=dc=test,dc=local"
echo ""
echo "  OIDC client credentials:"
echo "    client_id:     identree-test"
echo "    client_secret: ${CLIENT_SECRET:-<retrieve manually: ke system oauth2 show-basic-secret identree-test -D admin>}"
echo ""
echo "  Set user passwords (required for Kanidm web login):"
echo "    docker exec -it ${CONTAINER} kanidm person credential create-reset-token alice -D idm_admin"
echo "    (follow the reset link to set alice's password)"
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
