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
# Use export so all variables are visible to `env | grep ^IDENTREE_` when
# writing client.conf later (bare assignments are shell-local and invisible
# to env(1) unless the variable was already exported by the parent process).
export IDENTREE_SERVER_URL="${IDENTREE_SERVER_URL:-http://identree:8090}"
export IDENTREE_SHARED_SECRET="${IDENTREE_SHARED_SECRET:-test-shared-secret-123}"
# Token cache requires an OIDC issuer; disable by default in test environments
# where no issuer is configured. Can be overridden via the docker-compose env.
export IDENTREE_TOKEN_CACHE_ENABLED="${IDENTREE_TOKEN_CACHE_ENABLED:-false}"

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
id_provider       = ldap
auth_provider     = none
access_provider   = ldap
sudo_provider     = ${SSSD_SUDO_PROVIDER}
ldap_access_order = expire

ldap_uri               = ${LDAP_URI}
ldap_search_base       = ${LDAP_BASE}
ldap_user_search_base  = ${LDAP_USER_SEARCH_BASE}
ldap_group_search_base = ${LDAP_GROUP_SEARCH_BASE}
ldap_sudo_search_base  = ${LDAP_SUDO_SEARCH_BASE}

ldap_schema = ${SSSD_SCHEMA}
SSSD_BASE

# Append optional objectClass / member-attribute overrides
[ -n "$SSSD_USER_OBJECT_CLASS" ]  && printf 'ldap_user_object_class  = %s\n' "$SSSD_USER_OBJECT_CLASS"  >> /etc/sssd/sssd.conf
[ -n "$SSSD_GROUP_OBJECT_CLASS" ] && printf 'ldap_group_object_class = %s\n' "$SSSD_GROUP_OBJECT_CLASS" >> /etc/sssd/sssd.conf
[ -n "$SSSD_GROUP_MEMBER_ATTR" ]  && printf 'ldap_group_member       = %s\n' "$SSSD_GROUP_MEMBER_ATTR"  >> /etc/sssd/sssd.conf
[ -n "$SSSD_USER_NAME_ATTR" ]     && printf 'ldap_user_name          = %s\n' "$SSSD_USER_NAME_ATTR"     >> /etc/sssd/sssd.conf
# SID-based ID mapping: required for AD schema (id_provider=ldap defaults to false)
[ "$SSSD_ID_MAPPING" = "true" ]   && echo "ldap_id_mapping         = true"                       >> /etc/sssd/sssd.conf
# Fallback home directory for providers that don't expose homeDirectory in LDAP
# (e.g. Kanidm). Uses %u placeholder for the username.
[ -n "${SSSD_FALLBACK_HOMEDIR:-}" ] && printf 'fallback_homedir        = %s\n' "$SSSD_FALLBACK_HOMEDIR" >> /etc/sssd/sssd.conf

# Append bind credentials when a non-anonymous bind is required.
# When LDAP_BIND_DN is empty and IDENTREE_SERVER_URL is set, auto-provision
# per-host bind credentials from the identree provision endpoint.
if [ -n "$LDAP_BIND_DN" ]; then
    printf '\nldap_default_bind_dn      = %s\n' "$LDAP_BIND_DN" >> /etc/sssd/sssd.conf
    printf 'ldap_default_authtok_type = password\n' >> /etc/sssd/sssd.conf
    printf 'ldap_default_authtok = %s\n' "$LDAP_BIND_PW" >> /etc/sssd/sssd.conf
elif [ -n "$IDENTREE_SERVER_URL" ] && [ -n "$IDENTREE_SHARED_SECRET" ]; then
    # Fetch per-host LDAP bind credentials from identree provision endpoint.
    # This is the full-mode path where identree acts as the LDAP server.
    # Retry up to 30 times (60s) — the identree server may still be starting,
    # or may be restarted with OIDC credentials after initial boot.
    # Stop immediately if the server responds with an HTTP error (e.g. 404 means
    # provision is not enabled — no point retrying). Only retry on connection failure.
    HOSTNAME_FOR_PROV="$(hostname)"
    echo "Auto-provisioning LDAP bind credentials for ${HOSTNAME_FOR_PROV}..."
    PROV_JSON=""
    for _attempt in $(seq 1 30); do
        HTTP_CODE=""
        HTTP_CODE=$(curl -s -o /tmp/_prov_body -w '%{http_code}' \
            -H "X-Shared-Secret: ${IDENTREE_SHARED_SECRET}" \
            -H "X-Hostname: ${HOSTNAME_FOR_PROV}" \
            "${IDENTREE_SERVER_URL}/api/client/provision" 2>/dev/null) || true
        if [ "$HTTP_CODE" = "200" ]; then
            PROV_JSON=$(cat /tmp/_prov_body)
            break
        elif [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ]; then
            # Server responded but with an error — provision not enabled or misconfigured.
            echo "  provision returned HTTP ${HTTP_CODE}, skipping auto-provision."
            break
        fi
        [ "$_attempt" -eq 1 ] && echo "  provision endpoint not ready, retrying..."
        sleep 2
    done
    rm -f /tmp/_prov_body
    if [ -n "$PROV_JSON" ]; then
        PROV_BIND_DN=$(printf '%s' "$PROV_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('bind_dn',''))" 2>/dev/null || echo "")
        PROV_BIND_PW=$(printf '%s' "$PROV_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('bind_password',''))" 2>/dev/null || echo "")
        PROV_LDAP_URL=$(printf '%s' "$PROV_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ldap_url',''))" 2>/dev/null || echo "")
        PROV_CA_CERT=$(printf '%s' "$PROV_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ca_cert',''))" 2>/dev/null || echo "")
        PROV_CLIENT_CERT=$(printf '%s' "$PROV_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('client_cert',''))" 2>/dev/null || echo "")
        PROV_CLIENT_KEY=$(printf '%s' "$PROV_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('client_key',''))" 2>/dev/null || echo "")
        PROV_TLS_CA_CERT=$(printf '%s' "$PROV_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tls_ca_cert',''))" 2>/dev/null || echo "")

        # Override LDAP URI if provision returned one
        if [ -n "$PROV_LDAP_URL" ]; then
            echo "  ldap_url: ${PROV_LDAP_URL}"
            # Rewrite ldap_uri in sssd.conf with provisioned URL
            sed -i "s|^ldap_uri.*|ldap_uri               = ${PROV_LDAP_URL}|" /etc/sssd/sssd.conf
        fi

        if [ -n "$PROV_BIND_DN" ]; then
            printf '\nldap_default_bind_dn      = %s\n' "$PROV_BIND_DN" >> /etc/sssd/sssd.conf
            printf 'ldap_default_authtok_type = password\n' >> /etc/sssd/sssd.conf
            printf 'ldap_default_authtok = %s\n' "$PROV_BIND_PW" >> /etc/sssd/sssd.conf
            echo "  bind_dn: ${PROV_BIND_DN}"
        else
            echo "WARNING: provision response missing bind_dn — SSSD may fail to authenticate"
        fi

        # ── LDAPS/mTLS TLS configuration ─────────────────────────────────────
        # When the provision response includes mTLS client cert and the LDAP URL
        # uses ldaps://, configure SSSD for TLS with client certificate auth.
        if [ -n "$PROV_CLIENT_CERT" ] && echo "$PROV_LDAP_URL" | grep -q '^ldaps://'; then
            echo "  Configuring SSSD for LDAPS with mTLS client certificate..."
            mkdir -p /etc/identree

            # Write mTLS client cert + key for SSSD LDAP TLS client auth
            printf '%s\n' "$PROV_CLIENT_CERT" > /etc/identree/ldap-client.crt
            printf '%s\n' "$PROV_CLIENT_KEY" > /etc/identree/ldap-client.key
            chmod 600 /etc/identree/ldap-client.key
            chmod 644 /etc/identree/ldap-client.crt

            # Build the CA bundle for verifying the LDAP server cert.
            # Include both the mTLS CA (which signed the server cert in test
            # environments) and any explicit TLS CA cert.
            : > /etc/identree/ldap-ca-bundle.crt
            [ -n "$PROV_CA_CERT" ] && printf '%s\n' "$PROV_CA_CERT" >> /etc/identree/ldap-ca-bundle.crt
            [ -n "$PROV_TLS_CA_CERT" ] && printf '%s\n' "$PROV_TLS_CA_CERT" >> /etc/identree/ldap-ca-bundle.crt
            # Also include the server's TLS cert if available (self-signed test envs)
            [ -f /etc/identree/server-ca.crt ] && cat /etc/identree/server-ca.crt >> /etc/identree/ldap-ca-bundle.crt
            chmod 644 /etc/identree/ldap-ca-bundle.crt

            # Configure SSSD for LDAPS with mTLS
            printf 'ldap_tls_cert     = /etc/identree/ldap-client.crt\n' >> /etc/sssd/sssd.conf
            printf 'ldap_tls_key      = /etc/identree/ldap-client.key\n' >> /etc/sssd/sssd.conf
            printf 'ldap_tls_cacert   = /etc/identree/ldap-ca-bundle.crt\n' >> /etc/sssd/sssd.conf
            echo "  LDAPS mTLS configured."
        fi
    else
        echo "WARNING: provision endpoint not available — SSSD will use anonymous bind"
    fi
fi

# Determine TLS verification mode: 'demand' when LDAPS is configured with a
# CA bundle (mTLS), 'never' for plaintext LDAP (default/test environments).
_TLS_REQCERT="never"
if [ -f /etc/identree/ldap-ca-bundle.crt ] && [ -s /etc/identree/ldap-ca-bundle.crt ]; then
    _TLS_REQCERT="demand"
fi

cat >> /etc/sssd/sssd.conf <<SSSD_REST

ldap_id_use_start_tls = false
ldap_tls_reqcert      = ${_TLS_REQCERT}
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
# Write all IDENTREE_* settings to the config file so they survive
# stripSensitiveEnv() (which strips all IDENTREE_* from the process
# environment before LoadClientConfig reads them).
env | grep '^IDENTREE_' | sort > /etc/identree/client.conf
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
