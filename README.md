# identree

**identree** bridges your identity provider to Linux. Type `sudo` and approve it on your phone. SSH in without a password. No RADIUS, no password sprawl, no "just disable sudo" compromises.

It is a single binary that runs on one server and installs a small PAM helper on each managed host.

---

## The problem

Your homelab IdP handles web app logins beautifully — passkeys, MFA, SSO. But your servers still use Unix passwords. `sudo` prompts for a password that either never changes, gets shared, or gets disabled entirely. SSH keys get copied everywhere. There is no audit trail.

identree fixes this by making every `sudo` invocation and every SSH login go through your IdP's approval flow, the same way a web app login would.

---

## How it works

1. A user runs `sudo` on a managed host.
2. The PAM helper calls the identree server and blocks.
3. The user (or an admin) sees a push notification / browser prompt from their IdP.
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
- sudo policies are custom claims on PocketID groups
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
- If your IdP supports custom group attributes (Authentik, Keycloak), those drive sudo policy automatically; the UI is the fallback for IdPs that don't

**Requires:** Any OIDC-compliant IdP. No PocketID dependency.

> **PAM bridge mode is coming soon.** Full mode (PocketID) is stable today.

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
# /etc/identree/client.conf
IDENTREE_SERVER_URL=https://identree.example.com
IDENTREE_SHARED_SECRET=change-me-use-a-strong-secret
```

```
# /etc/pam.d/sudo — add before the first auth line
auth required pam_exec.so stdout /usr/local/bin/identree
```

Or deploy to a host in one command from the admin dashboard.

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

Every managed host gets a locally-stored bcrypt-hashed password as a fallback for when the identree server is unreachable. It is auto-generated, auto-rotated on a configurable schedule, and escrowed to a secret manager (1Password Connect, Vault, Bitwarden, Infisical).

```sh
identree rotate-breakglass          # rotate immediately
identree verify-breakglass          # check the current password works
```

---

## Configuration reference

### Server (`/etc/identree/identree.conf`)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_OIDC_ISSUER_URL` | — | **Required.** OIDC issuer URL |
| `IDENTREE_OIDC_CLIENT_ID` | — | **Required.** OIDC client ID |
| `IDENTREE_OIDC_CLIENT_SECRET` | — | **Required.** OIDC client secret |
| `IDENTREE_POCKETID_API_KEY` | — | **Required (full mode).** PocketID admin API key |
| `IDENTREE_EXTERNAL_URL` | — | **Required.** Public-facing URL |
| `IDENTREE_SHARED_SECRET` | — | **Required.** Shared secret with PAM clients |
| `IDENTREE_LISTEN_ADDR` | `:8090` | HTTP listen address |
| `IDENTREE_ADMIN_GROUPS` | — | Groups with admin UI access (comma-separated) |
| `IDENTREE_GRACE_PERIOD` | `0` | Skip re-auth if approved within this window |
| `IDENTREE_CHALLENGE_TTL` | `120s` | How long a pending challenge lives |
| `IDENTREE_LDAP_ENABLED` | `true` | Enable embedded LDAP server |
| `IDENTREE_LDAP_LISTEN_ADDR` | `:389` | LDAP listen address |
| `IDENTREE_LDAP_BASE_DN` | — | **Required if LDAP enabled.** Base DN |
| `IDENTREE_LDAP_BIND_DN` | — | Service account DN for read-only bind |
| `IDENTREE_LDAP_BIND_PASSWORD` | — | Service account password |
| `IDENTREE_LDAP_REFRESH_INTERVAL` | `300s` | How often to sync from PocketID |
| `IDENTREE_LDAP_UID_MAP_FILE` | `/var/lib/identree/uidmap.json` | UID/GID persistence file |
| `IDENTREE_SUDO_NO_AUTHENTICATE` | `false` | `false`, `true`, or `claims` |
| `IDENTREE_WEBHOOK_SECRET` | — | HMAC secret for PocketID webhook validation |

### Client (`/etc/identree/client.conf`)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_SERVER_URL` | — | **Required.** identree server URL |
| `IDENTREE_SHARED_SECRET` | — | **Required.** Shared secret |
| `IDENTREE_BREAKGLASS_ENABLED` | `true` | Enable break-glass fallback |
| `IDENTREE_BREAKGLASS_FILE` | `/etc/identree-breakglass` | Break-glass hash file |
| `IDENTREE_BREAKGLASS_ROTATION_DAYS` | `90` | Days between rotations |
| `IDENTREE_BREAKGLASS_PASSWORD_TYPE` | `random` | `random`, `passphrase`, or `alphanumeric` |

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

## Migrating from pam-pocketid + glauth-pocketid

identree replaces both. Migration is designed to be non-breaking.

1. Export `uidmap.json` from your glauth-pocketid container.
2. Set `IDENTREE_LDAP_UID_MAP_FILE` and copy in the exported file — identree imports the existing UID/GID assignments automatically.
3. Replace `pam-pocketid` with `identree` in `/etc/pam.d/sudo`.
4. `PAM_POCKETID_*` env vars and `/etc/pam-pocketid.conf` are still read as fallbacks — no immediate config changes required.
5. Move sudo policy from group naming conventions (`sudo-hostname`) to [custom claims](#sudo-policy-full-mode) on your PocketID groups.

---

## Building

```sh
go build -trimpath \
  -ldflags "-X main.version=v0.1.0 -X main.commit=$(git rev-parse --short=8 HEAD)" \
  -o identree ./cmd/identree/
```

---

## License

MIT
