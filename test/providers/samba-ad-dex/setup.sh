#!/bin/bash
# setup.sh — bootstrap Samba AD DC for the samba-ad-dex test environment.
# Run after: make test-samba-ad-dex
#
# What this does:
#   1. Waits for Samba DC, Dex, and identree to be healthy
#   2. Creates test users (alice, bob, testadmin) via samba-tool inside the DC container
#   3. Creates groups (developers, admins) and assigns membership
#   4. Ensures break-glass password is provisioned on the testclient
#
# Samba AD user creation sets passwords directly — no separate ldappasswd step
# is needed. Dex authenticates users by binding as them with the password set here.
#
# Requirements: docker
set -euo pipefail

DC="identree-samba-ad-dex-dc"
CLIENT="identree-samba-ad-dex-client"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() {
    local url="$1" name="$2"
    echo "==> Waiting for ${name}..."
    until curl -sf "$url" >/dev/null 2>&1; do sleep 2; done
    echo "    ${name} ready."
}

samba() {
    docker exec "$DC" samba-tool "$@"
}

# ── Wait for services ──────────────────────────────────────────────────────────
wait_for "http://localhost:5560/dex/healthz" "Dex"
wait_for "http://localhost:8099/healthz"     "identree"

# ── Create users ───────────────────────────────────────────────────────────────
# samba-tool user create <username> <password> [options]
# AD password complexity: uppercase + lowercase + digit + symbol, min 7 chars.
echo "==> Creating users..."

create_user() {
    local username="$1" password="$2" first="$3" last="$4" email="$5"
    echo "    ${username}"
    samba user create "${username}" "${password}" \
        --given-name="${first}" --surname="${last}" \
        --mail-address="${email}" \
        2>/dev/null || echo "    (${username} may already exist)"
    samba user enable "${username}" 2>/dev/null || true
}

create_user "alice"     "AliceTest123!" "Alice" "Liddell" "alice@samba.test.local"
create_user "bob"       "BobTest123!"   "Bob"   "Builder" "bob@samba.test.local"
create_user "testadmin" "AdminTest123!" "Test"  "Admin"   "admin@samba.test.local"

# ── Create groups ──────────────────────────────────────────────────────────────
echo "==> Creating groups..."
samba group add developers 2>/dev/null || echo "    developers may already exist"
samba group add admins     2>/dev/null || echo "    admins may already exist"

# ── Assign group membership ────────────────────────────────────────────────────
echo "==> Assigning group membership..."
samba group addmembers developers alice 2>/dev/null || true
samba group addmembers developers bob   2>/dev/null || true
samba group addmembers admins testadmin 2>/dev/null || true

# ── Ensure break-glass password is provisioned ────────────────────────────────
echo "==> Ensuring break-glass password is provisioned..."
docker exec "${CLIENT}" \
    sh -c 'test -f /etc/identree-breakglass || identree rotate-breakglass' \
    >/dev/null 2>&1 && echo "    break-glass ready." || echo "    WARNING: break-glass setup failed"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Samba AD DC + Dex test environment ready"
echo ""
echo "  Services:"
echo "    Samba AD DC:  ldap://localhost:3897"
echo "                  CN=Administrator,CN=Users,DC=samba,DC=test,DC=local / Admin@samba1"
echo "    Dex OIDC:     http://localhost:5560/dex"
echo "    identree:     http://localhost:8099"
echo ""
echo "  Test users (Samba AD + Dex login):"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins → identree admin)"
echo ""
echo "  Validate:"
echo "    make test-samba-ad-dex-validate"
echo "    docker exec identree-samba-ad-dex-client getent passwd alice"
echo "    docker exec identree-samba-ad-dex-client getent group developers"
echo "    docker exec -it identree-samba-ad-dex-client bash"
echo "    sudo whoami  (triggers identree challenge)"
echo "════════════════════════════════════════════════════════════"
