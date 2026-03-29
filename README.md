# identree

**identree** bridges your identity provider to Linux. Type `sudo` and approve it on your phone. SSH in without a password. No RADIUS, no password sprawl, no "just disable sudo" compromises.

It is a single binary (or Docker container) that runs on one server and deploys a small PAM helper to each managed host.

---

## The problem

Your IdP handles web app logins beautifully — passkeys, MFA, SSO. But your servers still use Unix passwords. `sudo` prompts for a password that never changes or gets shared. SSH keys are copied everywhere. There is no audit trail.

identree fixes this by routing every `sudo` invocation and SSH login through your IdP's approval flow.

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

1. User runs `sudo` on a managed host.
2. The PAM helper calls the identree server and blocks.
3. The user sees an approval prompt from their IdP.
4. They approve — `sudo` succeeds. They deny — `sudo` fails. No password exchanged.

---

## Deployment modes

identree has two modes. See [docs/deployment-modes.md](docs/deployment-modes.md) for full details and sssd config examples.

### Full mode — identree + PocketID

Use this if you are starting fresh or already use [PocketID](https://github.com/pocket-id/pocket-id). identree acts as your LDAP server, sudo policy engine, and PAM auth bridge in one process. No separate LDAP server needed.

**Requires:** PocketID with an admin API key.

### PAM bridge mode — identree alongside your existing stack

Use this if you already have LDAP (Authentik, Kanidm, lldap, OpenLDAP, etc.) and just want to add passkey-gated PAM auth on top. Your existing LDAP continues to handle user/group resolution. identree handles only the PAM challenge flow, and optionally serves `ou=sudoers` for sudo policy management.

**Requires:** Any OIDC-compliant IdP. An existing LDAP server for user/group resolution.

---

## Quick start

This walks through a full mode deployment (PocketID + identree) using Docker Compose.

### Step 1 — Start PocketID

Copy the example compose file and start PocketID first:

```sh
cp docker-compose.example.yml docker-compose.yml
mkdir config
docker compose up pocketid -d
```

Open PocketID at `http://localhost:1411` (or your configured `APP_URL`) and complete the initial setup to create your admin account.

### Step 2 — Configure PocketID

In PocketID:

1. **Create an OIDC client** (OIDC Clients → New):
   - Redirect URL: `https://identree.example.com/callback`
   - Note the **Client ID** and **Client Secret**

2. **Create an API key** (Settings → API Keys → New):
   - Note the key value

3. **Create an admin group** named `admins` (or whatever you set in `IDENTREE_ADMIN_GROUPS`) and add your user to it.

### Step 3 — Configure identree

Edit `docker-compose.yml` and fill in:

```yaml
IDENTREE_OIDC_CLIENT_ID: "your-client-id"
IDENTREE_OIDC_CLIENT_SECRET: "your-client-secret"
IDENTREE_POCKETID_API_KEY: "your-api-key"
IDENTREE_EXTERNAL_URL: "https://identree.example.com"
IDENTREE_SHARED_SECRET: "$(openssl rand -hex 32)"
IDENTREE_LDAP_BASE_DN: "dc=example,dc=com"
IDENTREE_ESCROW_ENCRYPTION_KEY: "$(openssl rand -hex 32)"
```

Also update `APP_URL` in the pocketid section and `IDENTREE_OIDC_ISSUER_PUBLIC_URL` to match.

### Step 4 — Start identree

```sh
docker compose up identree -d
docker compose logs -f identree   # watch for startup errors
```

Open `https://identree.example.com` and log in with your PocketID account. You should land on the identree dashboard.

### Step 5 — Install on a managed host

On each host you want to manage, run:

```sh
curl -fsSL https://identree.example.com/install.sh | sudo bash
```

The installer:
- Downloads the identree binary
- Writes `/etc/identree/client.conf` with the server URL and shared secret
- Configures `/etc/pam.d/sudo` to use the PAM helper
- Generates and stores a break-glass password locally

Once installed, the host appears in the identree admin UI under **Hosts**. From there you can rotate break-glass passwords, view per-host sessions, and remove hosts.

### Step 6 — Register a passkey and try it

Log into PocketID on the host's user account and register a passkey. Then try:

```sh
sudo whoami
```

A challenge notification appears (if configured) or the user opens `https://identree.example.com` — they approve, and `sudo` succeeds.

---

## The admin UI

The dashboard at `https://identree.example.com` provides:

- **Dashboard** — live pending challenges with one-click approve/reject; auto-refreshes via SSE
- **Sessions** — active approved sessions; revoke or extend individually or in bulk; "Just me" toggle to filter your own sessions
- **Access** — per-host access log with user/host/time; exportable
- **History** — full audit log of all sudo events; filterable by user, host, event type
- **Hosts** — registered hosts; install new hosts, rotate break-glass passwords, remove hosts
- **Users** — PocketID user list (full mode); manage SSH public key claims per user
- **Groups** — PocketID group list (full mode); manage sudo policy claims per group
- **Admin** — server info, live configuration editor, restart

The **Configuration** page (`/admin/config`) lets you change most settings without restarting. Secrets (shared secret, API keys, tokens) are env-only and cannot be written from the UI.

---

## Persistent state

All server state files default to `/config/`. Mount a persistent volume there:

```yaml
volumes:
  - ./config:/config
```

| File | Contents |
|---|---|
| `/config/sessions.json` | Active approved sessions (survives restarts) |
| `/config/uidmap.json` | UID/GID assignments for LDAP users (full mode) |
| `/config/hosts.json` | Registered host registry |
| `/config/sudorules.json` | Sudo rules (bridge mode) |

Override any path with the corresponding `IDENTREE_*_FILE` environment variable.

---

## Configuration reference

### Server (`/etc/identree/identree.conf` or environment)

#### OIDC / Authentication

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_OIDC_ISSUER_URL` | — | **Required.** OIDC issuer URL |
| `IDENTREE_OIDC_ISSUER_PUBLIC_URL` | — | Public-facing OIDC URL (split internal/external routing) |
| `IDENTREE_OIDC_CLIENT_ID` | — | **Required.** OIDC client ID |
| `IDENTREE_OIDC_CLIENT_SECRET` | — | **Required.** OIDC client secret |

#### PocketID API (full mode only)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_POCKETID_API_KEY` | — | **Required (full mode).** PocketID admin API key |
| `IDENTREE_POCKETID_API_URL` | `IDENTREE_OIDC_ISSUER_URL` | Internal PocketID API URL |

#### HTTP server

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_EXTERNAL_URL` | — | **Required.** Public-facing URL of identree |
| `IDENTREE_LISTEN_ADDR` | `:8090` | HTTP listen address |
| `IDENTREE_INSTALL_URL` | `IDENTREE_EXTERNAL_URL` | URL embedded in install scripts (split-horizon DNS) |
| `IDENTREE_SHARED_SECRET` | — | **Required.** HMAC secret shared with PAM clients |
| `IDENTREE_API_KEYS` | — | Comma-separated API bearer tokens for programmatic access |

#### Challenge / session flow

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_CHALLENGE_TTL` | `120s` | How long a pending challenge lives |
| `IDENTREE_GRACE_PERIOD` | `0` | Skip re-auth if user approved on this host within this window |
| `IDENTREE_ONE_TAP_MAX_AGE` | `24h` | Max PocketID session age for silent one-tap approval |

#### Admin access

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_ADMIN_GROUPS` | — | Comma-separated OIDC groups with admin UI access |
| `IDENTREE_ADMIN_APPROVAL_HOSTS` | — | Hostnames requiring manual admin approval (glob patterns) |

#### LDAP server

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_LDAP_ENABLED` | `true` | Enable the embedded LDAP server |
| `IDENTREE_LDAP_LISTEN_ADDR` | `:389` | LDAP listen address |
| `IDENTREE_LDAP_BASE_DN` | — | **Required if LDAP enabled.** Base DN |
| `IDENTREE_LDAP_BIND_DN` | — | Service account DN for read-only bind |
| `IDENTREE_LDAP_BIND_PASSWORD` | — | Service account password |
| `IDENTREE_LDAP_REFRESH_INTERVAL` | `300s` | How often to sync from PocketID |
| `IDENTREE_LDAP_UID_MAP_FILE` | `/config/uidmap.json` | UID/GID persistence file |
| `IDENTREE_LDAP_UID_BASE` | `200000` | First UID assigned to PocketID users |
| `IDENTREE_LDAP_GID_BASE` | `200000` | First GID assigned to PocketID groups |
| `IDENTREE_LDAP_DEFAULT_SHELL` | `/bin/bash` | Default `loginShell` |
| `IDENTREE_LDAP_DEFAULT_HOME` | `/home/%s` | `homeDirectory` pattern (`%s` = username) |
| `IDENTREE_SUDO_NO_AUTHENTICATE` | `false` | `false`, `true`, or `claims` — see [deployment modes](docs/deployment-modes.md) |
| `IDENTREE_SUDO_RULES_FILE` | `/config/sudorules.json` | Sudo rules file (bridge mode) |

#### Notifications

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_NOTIFY_BACKEND` | — | `ntfy`, `slack`, `discord`, `apprise`, `webhook`, or `custom` |
| `IDENTREE_NOTIFY_URL` | — | Webhook URL (all backends except `custom`) |
| `IDENTREE_NOTIFY_TOKEN` | — | Optional Bearer token for webhook auth |
| `IDENTREE_NOTIFY_COMMAND` | — | Command to execute (`custom` backend only) |
| `IDENTREE_NOTIFY_TIMEOUT` | `15s` | Timeout for HTTP requests or command execution |

See [docs/notifications.md](docs/notifications.md) for full details and examples.

#### PocketID webhook receiver

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_WEBHOOK_SECRET` | — | HMAC-SHA256 secret for validating incoming PocketID webhooks |

Set up a webhook in PocketID pointing to `https://identree.example.com/api/webhook/pocketid` for immediate LDAP directory refreshes when users or groups change.

#### Break-glass escrow

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_ESCROW_BACKEND` | — | `1password-connect`, `vault`, `bitwarden`, `infisical`, or `local` |
| `IDENTREE_ESCROW_URL` | — | API URL of the secret backend |
| `IDENTREE_ESCROW_AUTH_ID` | — | Application/client ID |
| `IDENTREE_ESCROW_AUTH_SECRET` | — | Credential (or use `_FILE` variant) |
| `IDENTREE_ESCROW_AUTH_SECRET_FILE` | — | Path to a file containing the credential |
| `IDENTREE_ESCROW_PATH` | — | Storage path/prefix in the backend |
| `IDENTREE_ESCROW_WEB_URL` | — | Link to the backend's web UI (shown in admin panel) |
| `IDENTREE_ESCROW_ENCRYPTION_KEY` | — | Encryption key for `local` backend |
| `IDENTREE_BREAKGLASS_ROTATE_BEFORE` | — | RFC 3339 timestamp — clients older than this are prompted to rotate |

See [docs/breakglass.md](docs/breakglass.md) for full details and per-backend examples.

#### Persistent state files

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_SESSION_STATE_FILE` | `/config/sessions.json` | Active sessions (persists across restarts) |
| `IDENTREE_HOST_REGISTRY_FILE` | `/config/hosts.json` | Registered host registry |
| `IDENTREE_HISTORY_PAGE_SIZE` | `10` | Default entries per page in the history view |

#### Client defaults (pushed to clients at registration)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE` | `random` | Break-glass password style: `random`, `passphrase`, `alphanumeric` |
| `IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS` | `90` | Days between auto-rotations (`0` disables) |
| `IDENTREE_CLIENT_TOKEN_CACHE_ENABLED` | `true` | Allow clients to cache OIDC tokens locally |

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
- Docker + Docker Compose
- `make`

### Running the test environment

```sh
make up      # build and start all containers
make down    # stop and remove
make logs    # follow server logs
make ps      # show container status
```

Test environment:
- PocketID at `http://localhost:1411`
- identree at `http://localhost:8090`
- SSH test host at `192.168.215.2`

### Building

```sh
make build
# or manually:
go build -trimpath \
  -ldflags "-X main.version=v0.1.0 -X main.commit=$(git rev-parse HEAD)" \
  -o identree ./cmd/identree/
```

---

## Migrating from pam-pocketid + glauth-pocketid

identree replaces both. Migration is non-breaking.

1. Export `uidmap.json` from glauth-pocketid and copy it to `/config/uidmap.json`.
2. Replace `pam-pocketid` with `identree` in `/etc/pam.d/sudo`.
3. `PAM_POCKETID_*` env vars and `/etc/pam-pocketid.conf` are still read as fallbacks.
4. Move sudo policy from group naming conventions to [custom claims](docs/deployment-modes.md#sudo-policy-full-mode).

---

## License

MIT
