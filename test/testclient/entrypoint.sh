#!/bin/bash
set -e

LDAP_URI="${LDAP_URI:-ldap://identree:3389}"
LDAP_BASE="${LDAP_BASE:-dc=test,dc=local}"
IDENTREE_SERVER_URL="${IDENTREE_SERVER_URL:-http://identree:8090}"
IDENTREE_SHARED_SECRET="${IDENTREE_SHARED_SECRET:-test-shared-secret-123}"

# Write sssd.conf
mkdir -p /etc/sssd
cat > /etc/sssd/sssd.conf <<EOF
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
sudo_provider   = ldap

ldap_uri            = ${LDAP_URI}
ldap_search_base    = ${LDAP_BASE}
ldap_user_search_base  = ou=people,${LDAP_BASE}
ldap_group_search_base = ou=groups,${LDAP_BASE}
ldap_sudo_search_base  = ou=sudoers,${LDAP_BASE}

ldap_schema             = rfc2307
ldap_id_use_start_tls   = false
enumerate               = true

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
EOF
chmod 600 /etc/sssd/sssd.conf

# Write identree client config
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
