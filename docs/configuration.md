# Configuration Reference

All configuration is via environment variables or `/etc/identree/identree.conf` (KEY=VALUE format, one per line).

## OIDC / Authentication

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_OIDC_ISSUER_URL` | - | **Required.** OIDC issuer URL |
| `IDENTREE_OIDC_ISSUER_PUBLIC_URL` | - | Public-facing OIDC URL (split internal/external routing) |
| `IDENTREE_OIDC_CLIENT_ID` | - | **Required.** OIDC client ID |
| `IDENTREE_OIDC_CLIENT_SECRET` | - | **Required.** OIDC client secret |
| `IDENTREE_OIDC_INSECURE_SKIP_VERIFY` | `false` | Skip TLS certificate verification for the OIDC issuer |
| `IDENTREE_OIDC_ENFORCE_IP_BINDING` | `false` | Bind sessions to the originating IP address |

### SAML IdPs (via OIDC bridge)

identree authenticates exclusively via OIDC. If your organization uses a SAML-only IdP, deploy an OIDC-to-SAML bridge (Keycloak, Authentik, or Dex) between your IdP and identree. See [`saml-bridge.md`](saml-bridge.md) for architecture and configuration details.

## PocketID API (full mode only)

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_POCKETID_API_KEY` | - | **Required (full mode).** PocketID admin API key |
| `IDENTREE_POCKETID_API_URL` | `IDENTREE_OIDC_ISSUER_URL` | Internal PocketID API URL |

## HTTP Server

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_EXTERNAL_URL` | - | **Required.** Public-facing URL of identree |
| `IDENTREE_LISTEN_ADDR` | `:8090` | HTTP listen address |
| `IDENTREE_INSTALL_URL` | `IDENTREE_EXTERNAL_URL` | URL embedded in install scripts (split-horizon DNS) |
| `IDENTREE_INSTALL_SIGNING_KEY` | `/config/install-signing.key` | Ed25519 private key for install script signing (auto-generated if absent) |
| `IDENTREE_INSTALL_VERIFY_KEY` | `/config/install-signing.pub` | Ed25519 public key for install script verification (auto-generated if absent) |
| `IDENTREE_SHARED_SECRET` | - | **Required.** HMAC secret shared with PAM clients |
| `IDENTREE_HMAC_SECRET` | - | Separate HMAC secret for internal token signing (defaults to `IDENTREE_SHARED_SECRET`) |
| `IDENTREE_SESSION_SECRET` | (SharedSecret) | Signs session cookies and CSRF tokens. Falls back to SharedSecret if unset. |
| `IDENTREE_ESCROW_SECRET` | (SharedSecret) | Signs break-glass escrow HMAC tokens. Falls back to SharedSecret if unset. |
| `IDENTREE_LDAP_SECRET` | (SharedSecret) | Derives per-host LDAP bind passwords. Falls back to SharedSecret if unset. Unnecessary when mTLS is enabled. |
| `IDENTREE_API_KEYS` | - | Comma-separated API bearer tokens for programmatic access |
| `IDENTREE_METRICS_TOKEN` | - | Bearer token for the `/metrics` endpoint |

> **Split secrets:** Production deployments should set independent secrets for each trust domain. Compromise of one secret does not affect the others.

## TLS / mTLS

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_TLS_CERT_FILE` | - | Path to TLS certificate file for HTTPS listener |
| `IDENTREE_TLS_KEY_FILE` | - | Path to TLS private key file for HTTPS listener |
| `IDENTREE_MTLS_CA_CERT` | - | Path to CA certificate for verifying client certificates (enables mTLS) |
| `IDENTREE_MTLS_CA_KEY` | - | Path to CA key for issuing client certificates |
| `IDENTREE_MTLS_CERT_TTL` | `8760h` | Validity duration for issued client certificates (default: 1 year) |

## Challenge / Session Flow

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_CHALLENGE_TTL` | `120s` | How long a pending challenge lives |
| `IDENTREE_GRACE_PERIOD` | `0` | Skip re-auth if user approved on this host within this window |
| `IDENTREE_ONE_TAP_MAX_AGE` | `24h` | Max PocketID session age for silent one-tap approval |

## Justification

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_REQUIRE_JUSTIFICATION` | `false` | Require a written justification for every elevation |
| `IDENTREE_JUSTIFICATION_CHOICES` | - | Comma-separated preset choices (defaults to: Routine maintenance, Incident response, Deployment, Debugging / troubleshooting, Security investigation, Configuration change) |

See [justification.md](justification.md) for full details including the terminal prompt flow and `SUDO_REASON` env var.

## Admin Access

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_ADMIN_GROUPS` | - | Comma-separated OIDC groups with admin UI access |
| `IDENTREE_APPROVAL_POLICIES_FILE` | `/config/approval-policies.json` | Path to the approval policies JSON file (per-host/per-user rules) |

Approval policies let you define per-host, per-user, and per-group rules that override the global challenge/session defaults. Policies can require additional approvers, enforce justification, set custom TTLs, or auto-approve/deny specific combinations. See [approval-policies.md](approval-policies.md) for schema and examples.

Key policy features:

- **Multi-approval**: Set the `min_approvals` field (e.g. `3`) to require N-of-M quorum. Each approval is tracked individually; the challenge resolves only when the threshold is met. Partial approvals are visible in the dashboard.
- **Step-up auth**: Set `require_fresh_oidc` (e.g. `"5m"`) to force the approver to have authenticated via OIDC within the given duration before their approval is accepted.
- **Break-glass override**: Set `break_glass_bypass` to `true` to allow admins to force-approve challenges matching this policy via `/api/challenges/override`, bypassing all policy checks. All overrides are audited.
- **Policy notification channels**: Set `notify_channels` to a list of channel names (from `notification-channels.json`) to route notifications for events matching this policy to specific channels instead of (or in addition to) the global defaults.

## LDAP Server

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_LDAP_ENABLED` | `true` | Enable the embedded LDAP server |
| `IDENTREE_LDAP_LISTEN_ADDR` | `:389` | LDAP listen address |
| `IDENTREE_LDAP_BASE_DN` | - | **Required if LDAP enabled.** Base DN |
| `IDENTREE_LDAP_BIND_DN` | - | Service account DN for read-only bind |
| `IDENTREE_LDAP_BIND_PASSWORD` | - | Service account password |
| `IDENTREE_LDAP_REFRESH_INTERVAL` | `300s` | How often to sync from PocketID |
| `IDENTREE_LDAP_UID_MAP_FILE` | `/config/uidmap.json` | UID/GID persistence file |
| `IDENTREE_LDAP_UID_BASE` | `200000` | First UID assigned to PocketID users |
| `IDENTREE_LDAP_GID_BASE` | `200000` | First GID assigned to PocketID groups |
| `IDENTREE_LDAP_DEFAULT_SHELL` | `/bin/bash` | Default `loginShell` |
| `IDENTREE_LDAP_DEFAULT_HOME` | `/home/%s` | `homeDirectory` pattern (`%s` = username) |
| `IDENTREE_LDAP_ALLOW_ANONYMOUS` | `false` | Allow anonymous LDAP binds |
| `IDENTREE_LDAP_PROVISION_ENABLED` | `false` | Enable automatic provisioning of LDAP accounts |
| `IDENTREE_LDAP_EXTERNAL_URL` | - | Public-facing LDAP URL (for client referrals) |
| `IDENTREE_LDAP_TLS_CA_CERT` | - | Path to CA certificate for LDAPS (LDAP over TLS) |
| `IDENTREE_LDAP_TLS_LISTEN_ADDR` | `:636` | LDAPS listen address (used when `IDENTREE_LDAP_TLS_CA_CERT` is set) |
| `IDENTREE_LDAP_SUDO_NO_AUTHENTICATE` | `false` | `false`, `true`, or `claims`. See [deployment modes](deployment-modes.md) |
| `IDENTREE_SUDO_RULES_FILE` | `/config/sudorules.json` | Sudo rules file (bridge mode) |

## Notifications

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_NOTIFICATION_CONFIG_FILE` | `/config/notification-channels.json` | Channel definitions (backends, URLs, tokens) |
| `IDENTREE_ADMIN_NOTIFY_FILE` | `/config/admin-notifications.json` | Per-admin notification preferences |
| `IDENTREE_NOTIFY_TIMEOUT` | `15s` | Timeout for HTTP requests or command execution |

Notifications use multi-channel routing: events are matched against org-level rules and per-admin preferences, then deduplicated and fanned out. See [notifications.md](notifications.md) for full details, supported backends, and examples.

## Audit Streaming

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_AUDIT_LOG` | - | `stdout` or `file:/path/to/audit.jsonl`. Structured JSON event stream |
| `IDENTREE_AUDIT_SYSLOG_URL` | - | RFC 5424 syslog destination (`udp://host:514` or `tcp://host:601`) |
| `IDENTREE_AUDIT_SPLUNK_HEC_URL` | - | Splunk HTTP Event Collector endpoint URL |
| `IDENTREE_AUDIT_SPLUNK_TOKEN` | - | Splunk HEC authentication token |
| `IDENTREE_AUDIT_LOKI_URL` | - | Grafana Loki push URL (e.g. `http://loki:3100`) |
| `IDENTREE_AUDIT_LOKI_TOKEN` | - | Optional Loki bearer token |
| `IDENTREE_AUDIT_BUFFER_SIZE` | `4096` | Event channel buffer size |
| `IDENTREE_AUDIT_LOG_MAX_SIZE` | `100MB` | Maximum size of a single audit log file before rotation |
| `IDENTREE_AUDIT_LOG_MAX_FILES` | `5` | Number of rotated audit log files to retain |

Multiple sinks can be active simultaneously. See [audit-streaming.md](audit-streaming.md) for event format, sink details, and LogQL/Splunk query examples.

## Database Backend

identree persists all state (challenges, grace sessions, action log, audit
metadata, escrow records, agent heartbeats) to a SQL database. SQLite is
the default and is appropriate for single-node homelab deployments.
PostgreSQL is the supported HA option.

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_DATABASE_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `IDENTREE_DATABASE_DSN` | `/config/identree.db` (sqlite) | SQLite path or `postgres://user:pass@host:5432/identree?sslmode=require` |
| `IDENTREE_DATABASE_MAX_OPEN_CONNS` | `1` for sqlite, `25` for postgres | Connection pool ceiling |

For HA, run multiple identree replicas behind a load balancer pointing at
the same Postgres instance. Cross-replica SSE fan-out and admin-session
revocation broadcasts ride on Postgres `LISTEN/NOTIFY`.

## PocketID Webhook Receiver

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_WEBHOOK_SECRET` | - | HMAC-SHA256 secret for validating incoming PocketID webhooks |

Set up a webhook in PocketID pointing to `https://identree.example.com/api/webhook/pocketid` for immediate LDAP directory refreshes when users or groups change.

## Break-glass Escrow

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_ESCROW_BACKEND` | - | `1password-connect`, `vault`, `bitwarden`, `infisical`, or `local` |
| `IDENTREE_ESCROW_URL` | - | API URL of the secret backend |
| `IDENTREE_ESCROW_AUTH_ID` | - | Application/client ID |
| `IDENTREE_ESCROW_AUTH_SECRET` | - | Credential (or use `_FILE` variant) |
| `IDENTREE_ESCROW_AUTH_SECRET_FILE` | - | Path to a file containing the credential |
| `IDENTREE_ESCROW_PATH` | - | Storage path/prefix in the backend |
| `IDENTREE_ESCROW_WEB_URL` | - | Link to the backend's web UI (shown in admin panel) |
| `IDENTREE_ESCROW_ENCRYPTION_KEY` | - | Encryption key for `local` backend |
| `IDENTREE_ESCROW_COMMAND` | - | External command to run after escrow storage (e.g. custom notification) |
| `IDENTREE_ESCROW_COMMAND_ENV` | - | Comma-separated `KEY=VALUE` pairs passed as environment to the escrow command |
| `IDENTREE_ESCROW_VAULT_MAP` | - | JSON map of hostname patterns to Vault paths for per-host secret routing |
| `IDENTREE_ESCROW_HKDF_SALT` | - | Hex-encoded salt for HKDF key derivation (16+ bytes recommended). Set to a random value per deployment for cross-deployment key diversification. Generate with: `openssl rand -hex 32`. Changing this value invalidates existing escrow ciphertexts. If unset, a static legacy salt is used (warning logged at startup). |
| `IDENTREE_BREAKGLASS_ROTATE_BEFORE` | - | RFC 3339 timestamp. Clients older than this are prompted to rotate |

See [breakglass.md](breakglass.md) for full details and per-backend examples.

## Persistent State Files

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_SESSION_STATE_FILE` | `/config/sessions.json` | Active sessions (persists across restarts) |
| `IDENTREE_HOST_REGISTRY_FILE` | `/config/hosts.json` | Registered host registry |
| `IDENTREE_DEFAULT_PAGE_SIZE` | `15` | Default entries per page in the history view |

## Client Defaults (pushed to clients on every auth)

These are sent in the challenge response and override each client's local config without editing files on the host. Configure them in the admin UI under **Configuration > Client Defaults**.

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_CLIENT_POLL_INTERVAL` | `0` | How often clients poll for challenge resolution (server override; 0 = use client default of `2s`) |
| `IDENTREE_CLIENT_TIMEOUT` | `0` | Max time clients wait for user approval (server override; 0 = use client default of `120s`) |
| `IDENTREE_CLIENT_BREAKGLASS_ENABLED` | `true` | Enable break-glass fallback on clients |
| `IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE` | `random` | Break-glass password style: `random`, `passphrase`, `alphanumeric` |
| `IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS` | `0` | Days between auto-rotations (server override; 0 = use client default of `90`) |
| `IDENTREE_CLIENT_TOKEN_CACHE_ENABLED` | `true` | Allow clients to cache OIDC tokens locally |

## Client (`/etc/identree/client.conf`)

Only two values need to be set locally. Everything else is pushed by the server on every authentication.

| Variable | Default | Source |
|---|---|---|
| `IDENTREE_SERVER_URL` | - | **Required. Local only.** |
| `IDENTREE_SHARED_SECRET` | - | **Required. Local only.** |
| `IDENTREE_BREAKGLASS_FILE` | `/etc/identree-breakglass` | Local only (filesystem path) |
| `IDENTREE_POLL_INTERVAL` | `2s` | Pushed by server (`IDENTREE_CLIENT_POLL_INTERVAL`) |
| `IDENTREE_TIMEOUT` | `120s` | Pushed by server (`IDENTREE_CLIENT_TIMEOUT`) |
| `IDENTREE_BREAKGLASS_ENABLED` | `true` | Pushed by server (`IDENTREE_CLIENT_BREAKGLASS_ENABLED`) |
| `IDENTREE_BREAKGLASS_ROTATION_DAYS` | `90` | Pushed by server (`IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS`) |
| `IDENTREE_BREAKGLASS_PASSWORD_TYPE` | `random` | Pushed by server (`IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE`) |
| `IDENTREE_TOKEN_CACHE_ENABLED` | `true` | Pushed by server (`IDENTREE_CLIENT_TOKEN_CACHE_ENABLED`) |
| `IDENTREE_TOKEN_CACHE_DIR` | `/run/identree` | Local only (filesystem path) |

Server-pushed values are sent in the challenge response on every `sudo` invocation and apply for that session. They override the local config without modifying the file. Configure them centrally in the admin UI under **Configuration > Client Defaults**.

## Operations

See [operations.md](operations.md) for reverse proxy setup, backup procedures, monitoring, and security hardening.
