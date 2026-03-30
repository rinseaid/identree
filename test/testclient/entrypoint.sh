#!/bin/bash
set -e

# ── Core LDAP settings ─────────────────────────────────────────────────────────
LDAP_URI="${LDAP_URI:-ldap://identree:3389}"
LDAP_BASE="${LDAP_BASE:-dc=test,dc=local}"

# Bind credentials (empty = anonymous bind)
LDAP_BIND_DN="${LDAP_BIND_DN:-}"
LDAP_BIND_PW="${LDAP_BIND_PW:-}"

# ── SSSD schema settings ───────────────────────────────────────────────────────
# rfc2307  : posixGroup/memberUid (default; identree full mode, OpenLDAP standard)
# rfc2307bis: groupOfNames/uniqueMember (lldap, Kanidm, most modern LDAP providers)
SSSD_SCHEMA="${SSSD_SCHEMA:-rfc2307}"

# Override objectClass names when they differ from schema defaults.
# Leave empty to use sssd defaults for the chosen schema.
SSSD_USER_OBJECT_CLASS="${SSSD_USER_OBJECT_CLASS:-}"    # e.g. inetOrgPerson for lldap
SSSD_GROUP_OBJECT_CLASS="${SSSD_GROUP_OBJECT_CLASS:-}"  # e.g. groupOfUniqueNames for lldap
SSSD_GROUP_MEMBER_ATTR="${SSSD_GROUP_MEMBER_ATTR:-}"    # e.g. uniqueMember for lldap
SSSD_USER_NAME_ATTR="${SSSD_USER_NAME_ATTR:-}"          # e.g. cn for Authentik (uid is a hex hash there)

# SID-based ID mapping (required for AD schema; id_provider=ldap defaults to false)
# Set to "true" when using ldap_schema=ad so UIDs/GIDs are derived from objectSID
# instead of requiring uidNumber/gidNumber POSIX attributes.
SSSD_ID_MAPPING="${SSSD_ID_MAPPING:-false}"

# ── Search base overrides ──────────────────────────────────────────────────────
LDAP_USER_SEARCH_BASE="${LDAP_USER_SEARCH_BASE:-ou=people,${LDAP_BASE}}"
LDAP_GROUP_SEARCH_BASE="${LDAP_GROUP_SEARCH_BASE:-ou=groups,${LDAP_BASE}}"
LDAP_SUDO_SEARCH_BASE="${LDAP_SUDO_SEARCH_BASE:-ou=sudoers,${LDAP_BASE}}"

# ── Sudo provider ──────────────────────────────────────────────────────────────
# ldap : pull sudo rules from LDAP (identree full mode or providers with sudo schema)
# none : disable sssd sudo; use STATIC_SUDO_RULES file-based rules instead
SSSD_SUDO_PROVIDER="${SSSD_SUDO_PROVIDER:-ldap}"

# ── Static sudo rules (bridge mode) ────────────────────────────────────────────
# Semicolon-separated sudoers lines. Written to /etc/sudoers.d/identree-test
# when non-empty. Enables PAM challenge testing without a sudoers LDAP tree.
# Example: "alice ALL=(ALL) ALL;%developers ALL=(ALL) /usr/bin/apt"
STATIC_SUDO_RULES="${STATIC_SUDO_RULES:-}"

# ── identree client settings ───────────────────────────────────────────────────
IDENTREE_SERVER_URL="${IDENTREE_SERVER_URL:-http://identree:8090}"
IDENTREE_SHARED_SECRET="${IDENTREE_SHARED_SECRET:-test-shared-secret-123}"

# ── Write sssd.conf ────────────────────────────────────────────────────────────
mkdir -p /etc/sssd

cat > /etc/sssd/sssd.conf <<SSSD_BASE
[sssd]
# nss: passwd/group lookups
# pam: account checks (locked/disabled state from LDAP)
# sudo: pull sudoers rules from LDAP (requires libsss-sudo + sudoers: files sss in nsswitch)
services = nss, pam, sudo
config_file_version = 2
domains = LDAP

[domain/LDAP]
id_provider     = ldap
auth_provider   = none
sudo_provider   = ${SSSD_SUDO_PROVIDER}

ldap_uri               = ${LDAP_URI}
ldap_search_base       = ${LDAP_BASE}
ldap_user_search_base  = ${LDAP_USER_SEARCH_BASE}
ldap_group_search_base = ${LDAP_GROUP_SEARCH_BASE}
ldap_sudo_search_base  = ${LDAP_SUDO_SEARCH_BASE}

ldap_schema = ${SSSD_SCHEMA}
SSSD_BASE

# Append optional objectClass / member-attribute overrides
[ -n "$SSSD_USER_OBJECT_CLASS" ]  && echo "ldap_user_object_class  = ${SSSD_USER_OBJECT_CLASS}"  >> /etc/sssd/sssd.conf
[ -n "$SSSD_GROUP_OBJECT_CLASS" ] && echo "ldap_group_object_class = ${SSSD_GROUP_OBJECT_CLASS}" >> /etc/sssd/sssd.conf
[ -n "$SSSD_GROUP_MEMBER_ATTR" ]  && echo "ldap_group_member       = ${SSSD_GROUP_MEMBER_ATTR}"  >> /etc/sssd/sssd.conf
[ -n "$SSSD_USER_NAME_ATTR" ]     && echo "ldap_user_name          = ${SSSD_USER_NAME_ATTR}"     >> /etc/sssd/sssd.conf
# SID-based ID mapping: required for AD schema (id_provider=ldap defaults to false)
[ "$SSSD_ID_MAPPING" = "true" ]   && echo "ldap_id_mapping         = true"                       >> /etc/sssd/sssd.conf

# Append bind credentials when a non-anonymous bind is required
if [ -n "$LDAP_BIND_DN" ]; then
    cat >> /etc/sssd/sssd.conf <<SSSD_BIND

ldap_default_bind_dn      = ${LDAP_BIND_DN}
ldap_default_authtok_type = password
ldap_default_authtok      = ${LDAP_BIND_PW}
SSSD_BIND
fi

cat >> /etc/sssd/sssd.conf <<SSSD_REST

ldap_id_use_start_tls = false
ldap_tls_reqcert      = never
enumerate             = false

# Do not cache credentials — identree handles auth; stale LDAP data should
# not be served. Short refresh intervals keep user/group/sudo data current.
cache_credentials           = false
entry_cache_timeout         = 60
entry_cache_user_timeout    = 60
entry_cache_group_timeout   = 60
entry_cache_sudo_timeout    = 60
refresh_expired_interval    = 30
ldap_enumeration_refresh_timeout  = 60
ldap_sudo_smart_refresh_interval  = 30
ldap_sudo_full_refresh_interval   = 60

[sudo]
sudo_timed = false
SSSD_REST

chmod 600 /etc/sssd/sssd.conf

# ── Static sudo rules (bridge mode) ────────────────────────────────────────────
# When SSSD_SUDO_PROVIDER=none, install file-based rules so that sudo still
# invokes PAM (and therefore identree's challenge flow) for test users.
if [ -n "$STATIC_SUDO_RULES" ]; then
    mkdir -p /etc/sudoers.d
    printf '%s' "$STATIC_SUDO_RULES" | tr ';' '\n' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$' \
        > /etc/sudoers.d/identree-test
    chmod 440 /etc/sudoers.d/identree-test
    visudo -c -f /etc/sudoers.d/identree-test
fi

# ── Write identree client config ───────────────────────────────────────────────
mkdir -p /etc/identree
cat > /etc/identree/client.conf <<EOF
IDENTREE_SERVER_URL=${IDENTREE_SERVER_URL}
IDENTREE_SHARED_SECRET=${IDENTREE_SHARED_SECRET}
EOF
chmod 600 /etc/identree/client.conf

# Token cache directory for identree
mkdir -p /run/identree

# Clear any stale SSSD state from a previous run
rm -rf /var/lib/sss/db/* /var/lib/sss/mc/* /run/sssd.pid 2>/dev/null || true

# Start sssd
sssd -D
echo "sssd started"

# Initialize break-glass password on first start so sudo has a fallback
# if the identree server is unreachable.
if [ ! -f /etc/identree-breakglass ]; then
    echo "Generating initial break-glass password..."
    identree rotate-breakglass && echo "Break-glass password set." || echo "WARNING: break-glass setup failed."
fi

# Execute CMD
exec "$@"
