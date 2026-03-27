# identree

**identree** is a single-binary identity bridge for Linux environments. It turns PocketID (or any OIDC provider) into a full-stack identity system for your servers:

- **PAM authentication** — browser-based sudo approval via OIDC. Tap "Approve" on your phone instead of typing a password.
- **Embedded LDAP server** — exposes every PocketID user and group as `posixAccount`/`posixGroup`/`sudoRole` entries. Your servers resolve usernames, UIDs, and group membership from `nslcd`/`sssd` without running a separate LDAP service.
- **Admin dashboard** — web UI for approving/rejecting sudo challenges, managing sessions, viewing history, and deploying the client to new hosts via SSH.
- **Break-glass passwords** — bcrypt-hashed local fallback when the server is unreachable. Auto-generated, auto-rotated, auto-escrowed.

## Quick start

### Server

```sh
# /etc/identree/identree.conf
IDENTREE_OIDC_ISSUER_URL=https://pocket-id.example.com
IDENTREE_OIDC_CLIENT_ID=your-client-id
IDENTREE_OIDC_CLIENT_SECRET=your-client-secret
IDENTREE_POCKETID_API_KEY=your-admin-api-key   # required — enables LDAP + admin features
IDENTREE_EXTERNAL_URL=https://identree.example.com
IDENTREE_SHARED_SECRET=change-me-use-a-strong-secret
IDENTREE_ADMIN_GROUPS=admins

# LDAP
IDENTREE_LDAP_ENABLED=true
IDENTREE_LDAP_LISTEN_ADDR=:389
IDENTREE_LDAP_BASE_DN=dc=example,dc=com
IDENTREE_LDAP_UID_MAP_FILE=/var/lib/identree/uidmap.json

identree serve
```

### Client (managed hosts)

```sh
# /etc/identree/client.conf
IDENTREE_SERVER_URL=https://identree.example.com
IDENTREE_SHARED_SECRET=change-me-use-a-strong-secret

# /etc/pam.d/sudo — add before the first auth line:
auth required pam_exec.so stdout /usr/local/bin/identree
```

Or use the one-command remote deploy from the admin dashboard.

## LDAP schema

identree exposes a standard POSIX LDAP schema under your configured base DN:

| DN | Object classes | Purpose |
|---|---|---|
| `ou=people,<base>` | `posixAccount`, `shadowAccount`, `inetOrgPerson` | One entry per PocketID user |
| `ou=groups,<base>` | `posixGroup` | PocketID groups + one User Private Group per user |
| `ou=sudoers,<base>` | `sudoRole` | Sudo rules derived from group names |

**Sudo group convention:** A group named `sudo` or `sudoers` grants `Host: ALL`. A group named `sudo-<hostname>` grants sudo on that specific host.

**UID/GID stability:** UIDs and GIDs are assigned on first encounter and persisted to `uidmap.json`. They are never reused, even if a user is deleted.

### nslcd example (`/etc/nslcd.conf`)

```
uid nslcd
gid nslcd
uri ldap://identree.example.com:389
base dc=example,dc=com
base passwd ou=people,dc=example,dc=com
base group ou=groups,dc=example,dc=com
base sudoers ou=sudoers,dc=example,dc=com
```

### sssd example (`/etc/sssd/sssd.conf`)

```ini
[sssd]
services = nss, pam, sudo

[domain/identree]
id_provider = ldap
auth_provider = none
ldap_uri = ldap://identree.example.com
ldap_search_base = dc=example,dc=com
ldap_user_search_base = ou=people,dc=example,dc=com
ldap_group_search_base = ou=groups,dc=example,dc=com
ldap_sudo_search_base = ou=sudoers,dc=example,dc=com
```

## PocketID webhook

For real-time LDAP updates (instead of waiting for the 5-minute poll interval), configure PocketID to send webhooks to identree:

```
POST https://identree.example.com/api/webhook/pocketid
```

Optionally secure with `IDENTREE_WEBHOOK_SECRET` — identree verifies the `X-Webhook-Signature: sha256=<hmac>` header.

## Configuration reference

### Server (`/etc/identree/identree.conf`)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_OIDC_ISSUER_URL` | — | **Required.** PocketID base URL |
| `IDENTREE_OIDC_CLIENT_ID` | — | **Required.** OIDC client ID |
| `IDENTREE_OIDC_CLIENT_SECRET` | — | **Required.** OIDC client secret |
| `IDENTREE_POCKETID_API_KEY` | — | **Required.** PocketID admin API key |
| `IDENTREE_EXTERNAL_URL` | — | **Required.** Public URL of this server |
| `IDENTREE_SHARED_SECRET` | — | **Required.** Secret shared with PAM clients |
| `IDENTREE_LISTEN_ADDR` | `:8090` | HTTP listen address |
| `IDENTREE_LDAP_ENABLED` | `true` | Enable embedded LDAP server |
| `IDENTREE_LDAP_LISTEN_ADDR` | `:389` | LDAP listen address |
| `IDENTREE_LDAP_BASE_DN` | — | **Required if LDAP enabled.** Base DN |
| `IDENTREE_LDAP_BIND_DN` | — | Service account DN for read-only bind |
| `IDENTREE_LDAP_BIND_PASSWORD` | — | Service account password |
| `IDENTREE_LDAP_REFRESH_INTERVAL` | `300s` | How often to poll PocketID API |
| `IDENTREE_LDAP_UID_MAP_FILE` | `/var/lib/identree/uidmap.json` | UID/GID persistence file |
| `IDENTREE_ADMIN_GROUPS` | — | Comma-separated groups with admin UI access |
| `IDENTREE_GRACE_PERIOD` | `0` | Skip re-auth if approved within this window |
| `IDENTREE_CHALLENGE_TTL` | `120s` | How long a pending challenge lives |
| `IDENTREE_WEBHOOK_SECRET` | — | HMAC secret for validating PocketID webhooks |

### Client (`/etc/identree/client.conf`)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_SERVER_URL` | — | **Required.** identree server URL |
| `IDENTREE_SHARED_SECRET` | — | **Required.** Shared secret |
| `IDENTREE_BREAKGLASS_ENABLED` | `true` | Enable break-glass fallback |
| `IDENTREE_BREAKGLASS_FILE` | `/etc/identree-breakglass` | Break-glass hash file path |
| `IDENTREE_BREAKGLASS_ROTATION_DAYS` | `90` | Days between rotations |
| `IDENTREE_BREAKGLASS_PASSWORD_TYPE` | `random` | `random`, `passphrase`, or `alphanumeric` |

Legacy `PAM_POCKETID_*` variable names are also accepted for backward compatibility.

## CLI reference

```
identree serve                         Run the server (HTTP + LDAP)
identree                               PAM helper (called by pam_exec.so)
identree rotate-breakglass [--force]   Rotate break-glass password
identree verify-breakglass             Verify break-glass password
identree add-host <hostname>           Register a host
identree remove-host <hostname>        Unregister a host
identree list-hosts                    List registered hosts
identree rotate-host-secret <hostname> Rotate a host's shared secret
identree --version                     Show version
```

## Migrating from pam-pocketid + glauth-pocketid

identree absorbs both projects into a single binary and deployment.

1. Export your existing `uidmap.json` from the glauth-pocketid container.
2. On first start, set `IDENTREE_LDAP_UID_MAP_FILE` to a path and copy in the exported `uidmap.json` — identree imports it automatically on startup.
3. Update `/etc/pam.d/sudo` to call `identree` instead of `pam-pocketid`.
4. Legacy `PAM_POCKETID_*` env vars in `/etc/pam-pocketid.conf` are read as fallback — no immediate config migration needed.

## Building

```sh
go build -ldflags "-X main.version=v0.1.0 -X main.commit=$(git rev-parse --short=8 HEAD)" -o identree .
```

## License

MIT
