# identree

**identree** bridges your identity provider to Linux. Type `sudo` and approve it on your phone. SSH in without a password. No RADIUS, no password sprawl, no "just disable sudo" compromises.

It is a single binary (or Docker container) that runs on one server and deploys a small PAM helper to each managed host.

---

## The problem

Your IdP handles web app logins with passkeys, MFA, and SSO. Your servers still use Unix passwords. `sudo` prompts for a password that never changes or gets shared. SSH keys are copied everywhere. There is no audit trail.

identree routes every `sudo` invocation and SSH login through your IdP's approval flow.

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
4. They approve, `sudo` succeeds. They deny, `sudo` fails. No password exchanged.

---

## Deployment modes

identree has two modes. See [docs/deployment-modes.md](docs/deployment-modes.md) for full details and sssd config examples.

### Full mode, identree + PocketID

Use this if you are starting fresh or already use [PocketID](https://github.com/pocket-id/pocket-id). identree acts as your LDAP server, sudo policy engine, and PAM auth bridge in one process. No separate LDAP server needed.

**Requires:** PocketID with an admin API key. Optionally serves LDAPS with mutual TLS on port 636 (see [docs/configuration.md](docs/configuration.md)).

### PAM bridge mode, identree alongside your existing stack

Use this if you already have LDAP (Authentik, Kanidm, lldap, OpenLDAP, etc.) and just want to add passkey-gated PAM auth on top. Your existing LDAP continues to handle user/group resolution. identree handles only the PAM challenge flow, and optionally serves `ou=sudoers` for sudo policy management.

**Requires:** Any OIDC-compliant IdP. An existing LDAP server for user/group resolution.

---

## Quick start

This walks through a full mode deployment (PocketID + identree) using Docker Compose.

### Step 1: Start PocketID

Copy the example compose file and start PocketID first:

```sh
cp docker-compose.example.yml docker-compose.yml
mkdir config
docker compose up pocketid -d
```

Open PocketID at `http://localhost:1411` (or your configured `APP_URL`) and complete the initial setup to create your admin account.

### Step 2: Configure PocketID

In PocketID:

1. **Create an OIDC client** (OIDC Clients → New):
   - Redirect URL: `https://identree.example.com/callback`
   - Note the **Client ID** and **Client Secret**

2. **Create an API key** (Settings → API Keys → New):
   - Note the key value

3. **Create an admin group** named `admins` (or whatever you set in `IDENTREE_ADMIN_GROUPS`) and add your user to it.

### Step 3: Configure identree

Generate secrets first:

```sh
openssl rand -hex 32   # → use as IDENTREE_SHARED_SECRET
openssl rand -hex 32   # → use as IDENTREE_ESCROW_ENCRYPTION_KEY
```

Then edit `docker-compose.yml` and fill in:

```yaml
IDENTREE_OIDC_CLIENT_ID: "your-client-id"
IDENTREE_OIDC_CLIENT_SECRET: "your-client-secret"
IDENTREE_POCKETID_API_KEY: "your-api-key"
IDENTREE_EXTERNAL_URL: "https://identree.example.com"
IDENTREE_SHARED_SECRET: "<paste first secret>"
IDENTREE_LDAP_BASE_DN: "dc=example,dc=com"
IDENTREE_ESCROW_ENCRYPTION_KEY: "<paste second secret>"
```

Also update `APP_URL` in the pocketid section and `IDENTREE_OIDC_ISSUER_PUBLIC_URL` to match.

### Step 4: Start identree

```sh
docker compose up identree -d
docker compose logs -f identree   # watch for startup errors
```

Open `https://identree.example.com` and log in with your PocketID account. You should land on the identree dashboard.

### Step 5: Install on a managed host

**Option A: Deploy directly from the admin UI (recommended)**

Go to **Hosts → Deploy** in the identree admin UI. Fill in the target hostname, SSH user, and paste in a private key with SSH access to the host. identree SSHes in, runs the installer, and streams the output back in real time. Once complete the host appears in the Hosts list automatically.

**Option B: Manual install**

```sh
curl -sf https://identree.example.com/install.sh | \
  sudo IDENTREE_SHARED_SECRET=xxx bash -s https://identree.example.com
```

The installer downloads the identree binary, writes `/etc/identree/client.conf`, configures `/etc/pam.d/sudo`, installs auditd monitoring rules (if auditd is present), and generates a local break-glass password. Ed25519 signature verification and custom script support are documented in [docs/install-scripts.md](docs/install-scripts.md).

### Step 6: Register a passkey and try it

Log into PocketID on the host's user account and register a passkey. Then try:

```sh
sudo whoami
```

A challenge notification appears (if configured) or the user opens `https://identree.example.com`. They approve, and `sudo` succeeds.

---

## The admin UI

The dashboard at `https://identree.example.com` provides:

- **Dashboard**: live pending challenges with one-click approve/reject; auto-refreshes via SSE
- **Sessions**: active approved sessions; revoke or extend individually or in bulk; "Just me" toggle to filter your own sessions
- **Access**: per-host access log with user/host/time; exportable
- **History**: full audit log of all sudo events; filterable by user, host, event type
- **Hosts**: registered hosts; install new hosts, rotate break-glass passwords, remove hosts
- **Users**: PocketID user list (full mode); manage SSH public key claims per user
- **Groups**: PocketID group list (full mode); manage sudo policy claims per group
- **Admin**: server info, live configuration editor, restart

The **Configuration** page (`/admin/config`) lets you change most settings without restarting. Secrets (shared secret, API keys, tokens) are env-only and cannot be written from the UI.

[![Access page, light/dark split](docs/screenshots/access-split.png)](docs/screenshots/)

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
| `/config/notification-channels.json` | Notification channel definitions |
| `/config/admin-notifications.json` | Per-admin notification preferences |
| `/config/approval-policies.json` | Approval policy rules (per-host/per-user/per-group overrides) |

Override any path with the corresponding `IDENTREE_*_FILE` environment variable.

---

## Configuration

All configuration is via environment variables or `/etc/identree/identree.conf`. These are the variables you need to get running. For the full reference (TLS, mTLS, audit streaming, notifications, escrow backends, client defaults, approval policies, and more), see [docs/configuration.md](docs/configuration.md).

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_OIDC_ISSUER_URL` | - | **Required.** OIDC issuer URL |
| `IDENTREE_OIDC_CLIENT_ID` | - | **Required.** OIDC client ID |
| `IDENTREE_OIDC_CLIENT_SECRET` | - | **Required.** OIDC client secret |
| `IDENTREE_EXTERNAL_URL` | - | **Required.** Public-facing URL of identree |
| `IDENTREE_SHARED_SECRET` | - | **Required.** HMAC secret shared with PAM clients |
| `IDENTREE_ADMIN_GROUPS` | - | Comma-separated OIDC groups with admin UI access |
| `IDENTREE_POCKETID_API_KEY` | - | **Required (full mode).** PocketID admin API key |
| `IDENTREE_POCKETID_API_URL` | `IDENTREE_OIDC_ISSUER_URL` | Internal PocketID API URL |
| `IDENTREE_LDAP_ENABLED` | `true` | Enable the embedded LDAP server |
| `IDENTREE_LDAP_BASE_DN` | - | **Required if LDAP enabled.** Base DN (e.g. `dc=example,dc=com`) |
| `IDENTREE_LDAP_BIND_PASSWORD` | - | Service account password for LDAP clients |
| `IDENTREE_GRACE_PERIOD` | `0` | Skip re-auth if user approved on this host within this window |
| `IDENTREE_ESCROW_BACKEND` | - | Break-glass backend: `1password-connect`, `vault`, `bitwarden`, `infisical`, or `local` |
| `IDENTREE_DATABASE_DRIVER` | `sqlite` | `sqlite` or `postgres` |

SAML-only IdPs are supported via an OIDC bridge (Keycloak, Authentik, or Dex). See [docs/saml-bridge.md](docs/saml-bridge.md).

### Client (`/etc/identree/client.conf`)

Only two values need to be set on each managed host. Everything else is pushed by the server.

| Variable | Description |
|---|---|
| `IDENTREE_SERVER_URL` | **Required.** URL of the identree server |
| `IDENTREE_SHARED_SECRET` | **Required.** Shared secret (must match server) |

---

## CLI reference

```
identree serve                          Start the server
identree                                PAM helper (invoked by pam_exec.so)
identree setup [--sssd] [--auditd] [--hostname <name>] [--force] [--dry-run]
                                        Configure PAM/SSSD on a managed host
identree rotate-breakglass [--force]    Rotate break-glass password
identree verify-breakglass              Verify current break-glass password
identree sign-script --key <private-key> --script <script-path>
                                        Sign a custom install script (Ed25519)
identree verify-install --key <pub> --script <sh> --sig <sig>
                                        Verify a signed install script
identree rotate-host-secret <hostname>  Rotate a host's shared secret
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

## License

MIT
