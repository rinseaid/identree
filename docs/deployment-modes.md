# Deployment modes

identree has two operating modes. The right choice depends on your existing identity stack.

---

## Full mode — identree + PocketID

**Use this if you are starting fresh or already use PocketID.**

identree pulls users and groups from PocketID's API, generates a complete LDAP directory (users, groups, sudo rules), and handles PAM authentication. You get a single stack: one IdP, one LDAP server, one auth server.

```
PocketID ──► identree ──► LDAP (posixAccount, posixGroup, sudoRole)
                     └──► PAM (sudo approval, SSH)
```

Managed hosts point sssd at identree's embedded LDAP. identree is the only thing they need.

**Requirements:** PocketID with an admin API key. No existing LDAP server needed.

### Key settings

```sh
IDENTREE_POCKETID_API_KEY=your-admin-api-key
IDENTREE_LDAP_ENABLED=true
IDENTREE_LDAP_BASE_DN=dc=example,dc=com
```

### sssd on managed hosts

```ini
[sssd]
services = nss, pam, sudo
config_file_version = 2
domains = IDENTREE

[domain/IDENTREE]
id_provider    = ldap
auth_provider  = none        # identree handles PAM auth, not sssd
sudo_provider  = ldap

ldap_uri             = ldap://identree.example.com:389
ldap_search_base              = dc=example,dc=com
ldap_user_search_base         = ou=people,dc=example,dc=com
ldap_group_search_base        = ou=groups,dc=example,dc=com
ldap_sudo_search_base         = ou=sudoers,dc=example,dc=com

ldap_schema           = rfc2307
ldap_id_use_start_tls = false
enumerate             = true
cache_credentials     = false
entry_cache_timeout   = 60
ldap_sudo_full_refresh_interval = 60
```

```
# /etc/nsswitch.conf
passwd:  files sss
group:   files sss
sudoers: files sss
```

### Sudo policy (full mode)

Sudo rules are defined as **custom claims on PocketID groups**. A group with no sudo claims generates no sudo entries.

| Claim | Required | Description | Example |
|---|---|---|---|
| `sudoCommands` | Yes | Comma-separated commands | `/usr/bin/apt, ALL` |
| `sudoHosts` | No | Comma-separated hosts (default: `ALL`) | `server1,server2` |
| `sudoRunAsUser` | No | Run-as user (default: `root`) | `root` |
| `sudoRunAsGroup` | No | Run-as group | `docker` |
| `sudoOptions` | No | Extra sudo options | `NOPASSWD` |

Set `IDENTREE_SUDO_NO_AUTHENTICATE=false` (the default) so every `sudo` invocation requires passkey approval. Set to `true` to disable, or `claims` to control per-group via `sudoOptions=!authenticate`.

### LDAP schema

| DN | Object classes | Content |
|---|---|---|
| `ou=people,<base>` | `posixAccount`, `shadowAccount`, `inetOrgPerson` | One entry per PocketID user |
| `ou=groups,<base>` | `posixGroup` | PocketID groups + one UPG per user |
| `ou=sudoers,<base>` | `sudoRole` | Rules from group custom claims |

UIDs and GIDs are stable, never reused, and persisted to `/config/uidmap.json`.

---

## PAM bridge mode — identree alongside your existing LDAP

**Use this if you already have an LDAP server (Authentik, Kanidm, lldap, OpenLDAP, etc.).**

Your existing LDAP handles user and group resolution. identree adds only the passkey-gated PAM approval flow on top. Any OIDC-compliant IdP can be used for authentication — PocketID is not required.

```
Authentik / Kanidm / any IdP ──► LDAP (posixAccount, posixGroup)
                                                  │
                              identree ──► LDAP (sudoRole only, optional)
                                     └──► PAM (sudo approval, SSH)
```

Managed hosts still point sssd at **your existing LDAP** for user/group resolution. identree is only contacted by the PAM helper when `sudo` is invoked.

Optionally, identree can also serve `ou=sudoers` — managed via its admin UI — so you get fine-grained sudo policy without adding `sudoRole` attributes to your primary LDAP.

**Requirements:** Any OIDC-compliant IdP. An existing LDAP server for user/group resolution.

### Key settings

```sh
# No IDENTREE_POCKETID_API_KEY — omitting it activates bridge mode

# Optional: serve ou=sudoers from identree's rules engine
IDENTREE_LDAP_ENABLED=true
IDENTREE_LDAP_BASE_DN=dc=example,dc=com
# Rules are edited in the admin UI at /admin/sudo-rules
```

### sssd on managed hosts (bridge mode)

Point sssd at your **existing LDAP** for users/groups, and optionally add identree as a second LDAP source for sudo rules:

```ini
[sssd]
services = nss, pam, sudo
config_file_version = 2
domains = MYLDAP

[domain/MYLDAP]
id_provider   = ldap
auth_provider = none
sudo_provider = ldap

# Your existing LDAP
ldap_uri        = ldap://ldap.example.com:389
ldap_search_base           = dc=example,dc=com
ldap_user_search_base      = ou=people,dc=example,dc=com
ldap_group_search_base     = ou=groups,dc=example,dc=com

# Point sudo at identree's sudoers tree (if IDENTREE_LDAP_ENABLED)
ldap_sudo_search_base      = ou=sudoers,dc=example,dc=com

ldap_schema           = rfc2307
cache_credentials     = false
enumerate             = true
```

> If you don't use identree's LDAP for sudo, point `ldap_sudo_search_base` at your own LDAP's sudoers branch instead.

### Supported OIDC providers (bridge mode examples)

**Authentik**
```sh
IDENTREE_OIDC_ISSUER_URL=https://authentik.example.com/application/o/identree/
IDENTREE_OIDC_CLIENT_ID=your-client-id
IDENTREE_OIDC_CLIENT_SECRET=your-client-secret
```

**Kanidm**
```sh
IDENTREE_OIDC_ISSUER_URL=https://kanidm.example.com/oauth2/openid/identree
IDENTREE_OIDC_CLIENT_ID=identree
IDENTREE_OIDC_CLIENT_SECRET=your-client-secret
```

**Keycloak**
```sh
IDENTREE_OIDC_ISSUER_URL=https://keycloak.example.com/realms/your-realm
IDENTREE_OIDC_CLIENT_ID=identree
IDENTREE_OIDC_CLIENT_SECRET=your-client-secret
```

**Any OIDC provider:** identree performs standard OIDC discovery at `IDENTREE_OIDC_ISSUER_URL/.well-known/openid-configuration`. As long as the IdP implements OIDC discovery and issues `groups` claims, it will work.

---

## Choosing the right mode

| | Full mode | PAM bridge mode |
|---|---|---|
| Requires PocketID | Yes | No |
| Requires existing LDAP | No | Yes |
| Manages LDAP users/groups | Yes | No |
| Serves sudoers LDAP | Yes | Optional |
| Admin UI: user management | Yes | No |
| Admin UI: sudo rules editor | No (via PocketID claims) | Yes |
| Any OIDC IdP | No (PocketID only) | Yes |
