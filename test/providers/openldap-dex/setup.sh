#!/bin/bash
# setup.sh — bootstrap OpenLDAP directory and set user passwords.
# Run after: make test-openldap-dex
#
# What this does:
#   1. Waits for OpenLDAP, Dex, and identree to be healthy
#   2. Creates OUs, users (posixAccount), and groups (posixGroup) via ldapadd
#   3. Sets user passwords via ldappasswd so Dex can authenticate them
#
# LDIF reference copies are in ldifs/ — this script is the authoritative source.
# Requirements: docker
set -euo pipefail

LDAP_INTERNAL_URI="ldap://openldap:389"
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

ldap_add() {
    docker exec -i "${CLIENT}" ldapadd \
        -H "${LDAP_INTERNAL_URI}" \
        -D "${LDAP_ADMIN_DN}" \
        -w "${LDAP_ADMIN_PASS}" \
        2>/dev/null || true
}

ldap_set_password() {
    local uid="$1" pass="$2"
    docker exec "${CLIENT}" ldappasswd \
        -H "${LDAP_INTERNAL_URI}" \
        -D "${LDAP_ADMIN_DN}" \
        -w "${LDAP_ADMIN_PASS}" \
        -s "${pass}" \
        "uid=${uid},ou=people,${LDAP_BASE}" 2>/dev/null || \
    echo "    WARNING: could not set password for ${uid}"
}

# ── Wait for services ──────────────────────────────────────────────────────────
wait_for "http://localhost:5559/dex/healthz" "dex"
wait_for "http://localhost:8097/healthz" "identree"

# ── Create OUs ─────────────────────────────────────────────────────────────────
echo "==> Creating OUs..."
ldap_add << 'LDIF'
dn: ou=people,dc=test,dc=local
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=test,dc=local
objectClass: organizationalUnit
ou: groups
LDIF

# ── Create users (posixAccount, no password yet) ───────────────────────────────
echo "==> Creating users..."
ldap_add << 'LDIF'
dn: uid=alice,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: Alice Liddell
sn: Liddell
uid: alice
uidNumber: 10001
gidNumber: 20001
homeDirectory: /home/alice
loginShell: /bin/bash
mail: alice@test.local

dn: uid=bob,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: Bob Builder
sn: Builder
uid: bob
uidNumber: 10002
gidNumber: 20001
homeDirectory: /home/bob
loginShell: /bin/bash
mail: bob@test.local

dn: uid=testadmin,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: Test Admin
sn: Admin
uid: testadmin
uidNumber: 10003
gidNumber: 20002
homeDirectory: /home/testadmin
loginShell: /bin/bash
mail: admin@test.local
LDIF

# ── Create groups (posixGroup with memberUid — RFC 2307) ───────────────────────
echo "==> Creating groups..."
ldap_add << 'LDIF'
dn: cn=developers,ou=groups,dc=test,dc=local
objectClass: posixGroup
cn: developers
gidNumber: 20001
memberUid: alice
memberUid: bob

dn: cn=admins,ou=groups,dc=test,dc=local
objectClass: posixGroup
cn: admins
gidNumber: 20002
memberUid: testadmin
LDIF

# ── Set user passwords ─────────────────────────────────────────────────────────
echo "==> Setting user passwords..."
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
