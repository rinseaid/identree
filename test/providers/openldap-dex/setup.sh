#!/bin/bash
# setup.sh — configure OpenLDAP user passwords for the openldap+Dex test environment.
# Run after: make test-openldap-dex
#
# What this does:
#   1. Waits for OpenLDAP, Dex, and identree to be healthy
#   2. Sets user passwords via ldappasswd (run inside testclient container)
#      Passwords are needed so Dex can authenticate users at its login form.
#      Users/groups are created at startup from ldifs/ via LDAP_CUSTOM_LDIF_DIR.
#
# Requirements: docker
set -euo pipefail

LLDAP_LDAP_INTERNAL_URI="ldap://openldap:1389"
LDAP_ADMIN_DN="cn=admin,dc=test,dc=local"
LDAP_ADMIN_PASS="openldap-admin-pass"
LDAP_BASE="dc=test,dc=local"
CLIENT="identree-openldap-dex-client"

# ── Helpers ────────────────────────────────────────────────────────────────────

wait_for() {
    local url="$1" name="$2"
    echo "==> Waiting for ${name}..."
    until curl -sf "$url" >/dev/null 2>&1; do sleep 2; done
    echo "    ${name} ready."
}

ldap_set_password() {
    local uid="$1" pass="$2"
    docker exec "${CLIENT}" ldappasswd \
        -H "${LLDAP_LDAP_INTERNAL_URI}" \
        -D "${LDAP_ADMIN_DN}" \
        -w "${LDAP_ADMIN_PASS}" \
        -s "${pass}" \
        "uid=${uid},ou=people,${LDAP_BASE}" 2>/dev/null || \
    echo "    WARNING: could not set password for ${uid} — Dex login will fail without it."
}

# ── Wait for services ──────────────────────────────────────────────────────────
wait_for "http://localhost:5559/dex/healthz" "dex"
wait_for "http://localhost:8097/healthz" "identree"

# ── Set user passwords ─────────────────────────────────────────────────────────
echo "==> Setting user passwords (requires testclient to be running)..."
ldap_set_password "alice"     "AliceTest123!"
ldap_set_password "bob"       "BobTest123!"
ldap_set_password "testadmin" "AdminTest123!"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  OpenLDAP+Dex test environment ready"
echo ""
echo "  Services:"
echo "    OpenLDAP:  ldap://localhost:3895  (cn=admin,dc=test,dc=local / openldap-admin-pass)"
echo "    Dex OIDC:  http://localhost:5559/dex"
echo "    identree:  http://localhost:8097"
echo ""
echo "  Test users (OpenLDAP + Dex login):"
echo "    alice     / AliceTest123!   (group: developers)"
echo "    bob       / BobTest123!     (group: developers)"
echo "    testadmin / AdminTest123!   (group: admins → identree admin)"
echo ""
echo "  Validate:"
echo "    make test-openldap-dex-validate"
echo "    docker exec identree-openldap-dex-client getent passwd alice"
echo "    docker exec identree-openldap-dex-client getent group developers"
echo "════════════════════════════════════════════════════════════"
