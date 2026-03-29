# identree

**identree** bridges your identity provider to Linux. Type `sudo` and approve it on your phone. SSH in without a password. No RADIUS, no password sprawl, no "just disable sudo" compromises.

It is a single binary that runs on one server and installs a small PAM helper on each managed host.

---

## The problem

Your homelab IdP handles web app logins beautifully — passkeys, MFA, SSO. But your servers still use Unix passwords. `sudo` prompts for a password that either never changes, gets shared, or gets disabled entirely. SSH keys get copied everywhere. There is no audit trail.

identree fixes this by making every `sudo` invocation and every SSH login go through your IdP's approval flow, the same way a web app login would.

---

## How it works

```
User runs sudo
      │
      ▼
PAM helper (identree) ──► identree server ──► OIDC approval page
      │                                              │
      │                          User approves on phone/browser
      │                                              │
      └──────── sudo succeeds ◄──────────────────────┘
```

1. A user runs `sudo` on a managed host.
2. The PAM helper calls the identree server and blocks.
3. The user (or an admin) sees a notification / approval prompt from their IdP.
4. They approve — `sudo` succeeds. They deny — `sudo` fails. No password exchanged.

The identree server handles the OIDC challenge flow. The PAM helper is a small binary that blocks until it gets a result.

---

## Deployment modes

identree has two modes. Choose based on what your identity stack already looks like.

### Full mode — identree manages everything

Use this if you run **PocketID** and want a zero-infrastructure solution. identree acts as your LDAP server, your sudo policy engine, and your PAM auth bridge in one process.

```
PocketID ──► identree ──► LDAP (posixAccount, posixGroup, sudoRole)
                     └──► PAM (sudo approval, SSH)
```

- Users and groups come from PocketID
- Sudo policies are custom claims on PocketID groups
- identree serves LDAP for `nslcd`/`sssd` — no separate LDAP server needed
- UIDs/GIDs are stable and persisted across restarts

**Requires:** PocketID with an admin API key.

---

### PAM bridge mode — identree adds passkey auth to your existing stack

Use this if you already have an identity stack that provides LDAP (Authentik, Kanidm, lldap, OpenLDAP, etc.). identree adds the one thing those systems don't have: **passkey-gated PAM auth**.

```
Authentik / Kanidm / any IdP ──► LDAP (posixAccount, posixGroup)
                                                  │
                              identree ──► LDAP (sudoRole only, optional)
                                     └──► PAM (sudo approval, SSH)
```

- Your existing LDAP handles user/group resolution as normal
- identree handles only the PAM challenge flow
- Optionally, identree also serves `ou=sudoers` — managed via its admin UI — so you get fine-grained sudo policy without needing custom LDAP attributes
- Any OIDC-compliant IdP works; no PocketID dependency

**Requires:** Any OIDC-compliant IdP.

---

## Quick start — Full mode (PocketID)

### Server

```sh
# /etc/identree/identree.conf
IDENTREE_OIDC_ISSUER_URL=https://pocket-id.example.com
IDENTREE_OIDC_CLIENT_ID=your-client-id
IDENTREE_OIDC_CLIENT_SECRET=your-client-secret
IDENTREE_POCKETID_API_KEY=your-admin-api-key
IDENTREE_EXTERNAL_URL=https://identree.example.com
IDENTREE_SHARED_SECRET=change-me-use-a-strong-secret
IDENTREE_ADMIN_GROUPS=admins

IDENTREE_LDAP_ENABLED=true
IDENTREE_LDAP_LISTEN_ADDR=:389
IDENTREE_LDAP_BASE_DN=dc=example,dc=com

identree serve
```

### Client (each managed host)

```sh
# Install in one command from the admin dashboard, or manually:
curl -fsSL https://identree.example.com/install.sh | sudo bash
```

Or manually:

```sh
# /etc/identree/client.conf
IDENTREE_SERVER_URL=https://identree.example.com
IDENTREE_SHARED_SECRET=change-me-use-a-strong-secret
```

```
# /etc/pam.d/sudo — add before the first auth line
auth required pam_exec.so stdout /usr/local/bin/identree
```

### nslcd (`/etc/nslcd.conf`)

```
uid nslcd
gid nslcd
uri ldap://identree.example.com:389
base dc=example,dc=com
base passwd ou=people,dc=example,dc=com
base group  ou=groups,dc=example,dc=com
base sudoers ou=sudoers,dc=example,dc=com
```

---

## Quick start — PAM bridge mode

Bridge mode requires no PocketID API key. Omit `IDENTREE_POCKETID_API_KEY` from the server config.

```sh
# /etc/identree/identree.conf
IDENTREE_OIDC_ISSUER_URL=https://authentik.example.com/application/o/identree/
IDENTREE_OIDC_CLIENT_ID=your-client-id
IDENTREE_OIDC_CLIENT_SECRET=your-client-secret
IDENTREE_EXTERNAL_URL=https://identree.example.com
IDENTREE_SHARED_SECRET=change-me-use-a-strong-secret
IDENTREE_ADMIN_GROUPS=admins

# Optional: serve ou=sudoers from identree's built-in rules engine
IDENTREE_LDAP_ENABLED=true
IDENTREE_LDAP_BASE_DN=dc=example,dc=com
IDENTREE_SUDO_RULES_FILE=/var/lib/identree/sudorules.json
```

In bridge mode, identree's admin UI exposes a sudo rules editor at `/admin/sudo-rules`. Rules created there are served as `sudoRole` LDAP entries for any host that includes `ou=sudoers` in its LDAP search base.

---

## Sudo policy (Full mode)

Sudo rules are defined as **custom claims on PocketID groups**. A group with no sudo claims generates no sudo entries — there is no naming convention to follow.

| Claim | Required | Description | Example |
|---|---|---|---|
| `sudoCommands` | Yes | Comma-separated commands the group may run | `/usr/bin/apt, /usr/bin/systemctl` |
| `sudoHosts` | No | Comma-separated hosts (default: `ALL`) | `server1,server2` |
| `sudoRunAsUser` | No | Run-as user (default: `root`) | `root` |
| `sudoRunAsGroup` | No | Run-as group (optional) | `docker` |
| `sudoOptions` | No | Extra sudo options (see note) | `NOPASSWD` |

**`IDENTREE_SUDO_NO_AUTHENTICATE`** controls whether sudo invocations require PAM authentication (i.e. the identree approval flow):

| Value | Behaviour |
|---|---|
| `false` (default) | Every sudo invocation triggers the passkey approval flow |
| `true` | `!authenticate` added to all rules — no approval required |
| `claims` | Per-group: set `sudoOptions=!authenticate` on specific groups |

The default (`false`) is the point of identree — keep it unless you have a good reason.

---

## LDAP schema (Full mode)

| DN | Object classes | Content |
|---|---|---|
| `ou=people,<base>` | `posixAccount`, `shadowAccount`, `inetOrgPerson` | One entry per PocketID user |
| `ou=groups,<base>` | `posixGroup` | PocketID groups + one User Private Group per user |
| `ou=sudoers,<base>` | `sudoRole` | Sudo rules from group custom claims |

UID/GID assignments are stable and persisted to `uidmap.json`. They are never reused.

---

## Break-glass

Every managed host gets a locally-stored bcrypt-hashed password as a fallback for when the identree server is unreachable. It is auto-generated, auto-rotated on a configurable schedule, and can be escrowed to a secret manager.

```sh
identree rotate-breakglass          # rotate immediately
identree verify-breakglass          # check the current password works
```

**Supported escrow backends:** 1Password Connect, HashiCorp Vault, Bitwarden Secrets Manager, Infisical, and a local AES-256-GCM backend (no external service required).

---

## Notifications

identree can call a script or send webhooks whenever a new sudo challenge is created.

### Shell command

```sh
IDENTREE_NOTIFY_COMMAND=/usr/local/bin/my-notify.sh
# Variables passed: NOTIFY_USERNAME, NOTIFY_HOSTNAME, NOTIFY_USER_CODE,
#                   NOTIFY_APPROVAL_URL, NOTIFY_EXPIRES_IN, NOTIFY_USER_URLS,
#                   NOTIFY_ONETAP_URL
```

### Webhooks (Discord, Slack, ntfy, Apprise, raw JSON)

```sh
# IDENTREE_WEBHOOKS is a JSON array:
IDENTREE_WEBHOOKS='[{"url":"https://discord.com/api/webhooks/xxx","format":"discord"}]'

# Or point to a file:
IDENTREE_WEBHOOKS_FILE=/etc/identree/webhooks.json
```

Supported formats: `raw`, `apprise`, `discord`, `slack`, `ntfy`, `custom` (Go template).

Custom format example:

```json
[{
  "url": "https://ntfy.sh/my-topic",
  "format": "custom",
  "template": "{\"topic\":\"my-topic\",\"message\":\"{{.Username}} wants sudo on {{.Hostname}}\"}"
}]
```

### Per-user notification routing

```sh
# Map usernames to per-user webhook URLs (NOTIFY_USER_URLS env var in notify script):
IDENTREE_NOTIFY_USERS='{"alice":"https://...", "bob":"https://..."}'
# Or from a file:
IDENTREE_NOTIFY_USERS_FILE=/etc/identree/notify-users.json
```

---

## PocketID webhook integration

identree can receive webhooks from PocketID to trigger immediate LDAP directory refreshes when users or groups change, without waiting for the next polling interval.

In PocketID, create a webhook pointing to `https://identree.example.com/api/webhook/pocketid`.

```sh
IDENTREE_WEBHOOK_SECRET=your-hmac-secret   # validates incoming signatures
```

---

## Configuration reference

### Server (`/etc/identree/identree.conf`)

#### OIDC / Authentication

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_OIDC_ISSUER_URL` | — | **Required.** OIDC issuer URL (PocketID base URL) |
| `IDENTREE_OIDC_ISSUER_PUBLIC_URL` | — | Public-facing OIDC URL for browser redirects (split internal/external routing) |
| `IDENTREE_OIDC_CLIENT_ID` | — | **Required.** OIDC client ID |
| `IDENTREE_OIDC_CLIENT_SECRET` | — | **Required.** OIDC client secret |

#### PocketID API (full mode only)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_POCKETID_API_KEY` | — | **Required (full mode).** PocketID admin API key |
| `IDENTREE_POCKETID_API_URL` | `IDENTREE_OIDC_ISSUER_URL` | Internal PocketID API URL (if different from issuer) |

#### HTTP server

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_EXTERNAL_URL` | — | **Required.** Public-facing URL of identree |
| `IDENTREE_LISTEN_ADDR` | `:8090` | HTTP listen address |
| `IDENTREE_INSTALL_URL` | `IDENTREE_EXTERNAL_URL` | URL embedded in client install scripts (use when identree is behind a split-horizon DNS) |
| `IDENTREE_SHARED_SECRET` | — | **Required.** HMAC secret shared with PAM clients |
| `IDENTREE_API_KEYS` | — | Comma-separated API bearer tokens for programmatic access |

#### Challenge / session flow

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_CHALLENGE_TTL` | `120s` | How long a pending challenge lives |
| `IDENTREE_GRACE_PERIOD` | `0` | Skip re-auth if user approved on this host within this window |
| `IDENTREE_ONE_TAP_MAX_AGE` | `24h` | Max PocketID session age for silent one-tap approval |
| `IDENTREE_SESSION_STATE_FILE` | — | Path to persist active session state across restarts |

#### Admin access

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_ADMIN_GROUPS` | — | Comma-separated OIDC groups with admin UI access |
| `IDENTREE_ADMIN_APPROVAL_HOSTS` | — | Comma-separated hostnames requiring manual admin approval (glob patterns) |

#### LDAP server

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_LDAP_ENABLED` | `true` | Enable the embedded LDAP server |
| `IDENTREE_LDAP_LISTEN_ADDR` | `:389` | LDAP listen address |
| `IDENTREE_LDAP_BASE_DN` | — | **Required if LDAP enabled.** Base DN |
| `IDENTREE_LDAP_BIND_DN` | — | Service account DN for read-only bind (leave blank for anonymous binds) |
| `IDENTREE_LDAP_BIND_PASSWORD` | — | Service account password |
| `IDENTREE_LDAP_REFRESH_INTERVAL` | `300s` | How often to sync from PocketID |
| `IDENTREE_LDAP_UID_MAP_FILE` | `/var/lib/identree/uidmap.json` | UID/GID persistence file |
| `IDENTREE_LDAP_UID_BASE` | `200000` | First UID assigned to PocketID users |
| `IDENTREE_LDAP_GID_BASE` | `200000` | First GID assigned to PocketID groups |
| `IDENTREE_LDAP_DEFAULT_SHELL` | `/bin/bash` | Default `loginShell` for LDAP user entries |
| `IDENTREE_LDAP_DEFAULT_HOME` | `/home/%s` | `homeDirectory` pattern (`%s` = username) |
| `IDENTREE_SUDO_NO_AUTHENTICATE` | `false` | `false`, `true`, or `claims` — see [Sudo policy](#sudo-policy-full-mode) |
| `IDENTREE_SUDO_RULES_FILE` | `/var/lib/identree/sudorules.json` | Static sudo rules file (bridge mode) |

#### Notifications

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_NOTIFY_COMMAND` | — | Script to run when a new challenge is created |
| `IDENTREE_NOTIFY_ENV_PASSTHROUGH` | — | Comma-separated env var prefixes passed to the notify command (e.g. `SLACK_,MY_APP_`) |
| `IDENTREE_NOTIFY_USERS_FILE` | — | JSON file mapping usernames → per-user webhook URLs |
| `IDENTREE_NOTIFY_USERS` | — | Inline JSON equivalent of `IDENTREE_NOTIFY_USERS_FILE` |
| `IDENTREE_NOTIFY_TIMEOUT` | `15s` | Max time to wait for the notify command to complete |
| `IDENTREE_WEBHOOKS` | — | JSON array of webhook destinations (see [Notifications](#notifications)) |
| `IDENTREE_WEBHOOKS_FILE` | — | Path to a JSON file containing webhook destinations |
| `IDENTREE_WEBHOOK_TIMEOUT` | `10s` | Per-webhook HTTP request timeout |

#### PocketID webhook receiver

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_WEBHOOK_SECRET` | — | HMAC-SHA256 secret for validating incoming PocketID webhook signatures |

#### Break-glass escrow

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_ESCROW_BACKEND` | — | `1password-connect`, `vault`, `bitwarden`, `infisical`, or `local` |
| `IDENTREE_ESCROW_URL` | — | API URL of the secret backend |
| `IDENTREE_ESCROW_AUTH_ID` | — | Application/client ID for the secret backend |
| `IDENTREE_ESCROW_AUTH_SECRET` | — | Credential for the secret backend |
| `IDENTREE_ESCROW_AUTH_SECRET_FILE` | — | Path to a file containing the secret backend credential |
| `IDENTREE_ESCROW_PATH` | — | Storage path/prefix in the backend (vault mount, 1Password vault name, etc.) |
| `IDENTREE_ESCROW_WEB_URL` | — | Link to the backend's web UI (shown in admin panel) |
| `IDENTREE_ESCROW_ENCRYPTION_KEY` | — | Encryption key for `local` backend (AES-256-GCM) |
| `IDENTREE_BREAKGLASS_ROTATE_BEFORE` | — | RFC 3339 timestamp — clients with older hashes are prompted to rotate |

#### Client defaults (pushed to clients at registration)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE` | `random` | Break-glass password style: `random`, `passphrase`, `alphanumeric` |
| `IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS` | `90` | Days between auto-rotations (`0` disables) |
| `IDENTREE_CLIENT_TOKEN_CACHE_ENABLED` | `true` | Allow clients to cache OIDC tokens locally |

#### Miscellaneous

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_HOST_REGISTRY_FILE` | — | JSON file of registered hosts |
| `IDENTREE_HISTORY_PAGE_SIZE` | `10` | Default entries per page in the history view |

---

### Client (`/etc/identree/client.conf`)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_SERVER_URL` | — | **Required.** identree server URL |
| `IDENTREE_SHARED_SECRET` | — | **Required.** Shared secret |
| `IDENTREE_POLL_INTERVAL` | `2s` | How often to poll for challenge resolution |
| `IDENTREE_TIMEOUT` | `120s` | Max time to wait for user approval |
| `IDENTREE_BREAKGLASS_ENABLED` | `true` | Enable break-glass fallback |
| `IDENTREE_BREAKGLASS_FILE` | `/etc/identree-breakglass` | Break-glass hash file |
| `IDENTREE_BREAKGLASS_ROTATION_DAYS` | `90` | Days between rotations |
| `IDENTREE_BREAKGLASS_PASSWORD_TYPE` | `random` | `random`, `passphrase`, or `alphanumeric` |
| `IDENTREE_TOKEN_CACHE_ENABLED` | `true` | Cache OIDC tokens locally |
| `IDENTREE_TOKEN_CACHE_DIR` | `/run/identree` | Token cache directory |

> Legacy `PAM_POCKETID_*` env vars and `/etc/pam-pocketid.conf` are still read as fallbacks.

---

## CLI reference

```
identree serve                          Start the server
identree                                PAM helper (invoked by pam_exec.so)
identree rotate-breakglass [--force]    Rotate break-glass password
identree verify-breakglass              Verify current break-glass password
identree add-host <hostname>            Register a host
identree remove-host <hostname>         Unregister a host
identree list-hosts                     List registered hosts
identree --version                      Print version
```

---

## Development

### Prerequisites

- Go 1.22+
- Docker (for the test environment)
- `make`

### Running the test environment

```sh
make up      # build and start all containers
make down    # stop and remove
make logs    # follow server logs
make ps      # show container status
```

The test environment starts:
- PocketID at `http://localhost:1411`
- identree server at `http://localhost:8090`
- An SSH test host at `192.168.215.2`

### Logging into the test PocketID instance

To get a browser session cookie for the test PocketID instance as `testadmin`:

```bash
CODE=$(docker exec identree-test-pocketid /app/pocket-id one-time-access-token testadmin 2>&1 | grep -oE '/lc/[^ ]+' | grep -oE '[^/]+$')
JWT=$(curl -si "http://localhost:1411/api/one-time-access-token/$CODE" -X POST | grep -i "set-cookie" | grep -oE 'access_token=[^;]+')
printf 'document.cookie = "%s; path=/; SameSite=Lax"' "$JWT" | pbcopy
```

Paste the copied command into the browser console on `http://localhost:1411` and refresh.

### Building

```sh
go build -trimpath \
  -ldflags "-X main.version=v0.1.0 -X main.commit=$(git rev-parse HEAD)" \
  -o identree ./cmd/identree/
```

Or with `make`:

```sh
make build
```

---

## Migrating from pam-pocketid + glauth-pocketid

identree replaces both. Migration is designed to be non-breaking.

1. Export `uidmap.json` from your glauth-pocketid container.
2. Set `IDENTREE_LDAP_UID_MAP_FILE` and copy in the exported file — identree imports the existing UID/GID assignments automatically.
3. Replace `pam-pocketid` with `identree` in `/etc/pam.d/sudo`.
4. `PAM_POCKETID_*` env vars and `/etc/pam-pocketid.conf` are still read as fallbacks — no immediate config changes required.
5. Move sudo policy from group naming conventions (`sudo-hostname`) to [custom claims](#sudo-policy-full-mode) on your PocketID groups.

---

## License

MIT
