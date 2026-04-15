# Changelog

All notable changes to identree will be documented in this file.

## [0.1.0] - 2026-04-05

### Added

#### Core
- PAM authentication module bridging Linux sudo/SSH to your identity provider
- OIDC authentication with any compliant IdP (SAML IdPs supported via OIDC bridge)
- Challenge/approval flow with browser-based passkey verification
- Grace sessions to avoid repeated approval prompts within a configurable window
- Justification system with predefined choices, required flag, and one-tap support
- Optional deny reason on challenge rejection
- Split internal/external URL routing for air-gapped or NAT environments
- `IDENTREE_DEV_LOGIN` bypass for local development

#### LDAP
- Embedded LDAP server exposing IdP users, groups, and sudo rules
- SSSD auto-provisioning via `setup --sssd` subcommand and per-host LDAP bind credentials
- LDAPS (LDAP over TLS) with mutual TLS client certificate authentication
- Bridge mode for sudoers-only LDAP from a JSON rules store
- Claims-based sudo rules with admin UI management
- UID/GID mapping with collision-free allocation

#### Security
- Per-domain secret splitting (session, escrow, LDAP) to limit compromise blast radius
- HMAC-signed grace sessions prevent injection via Redis write access
- Certificate issuance audit logging with serial number tracking
- CA signing refactored to crypto.Signer interface for future KMS/HSM integration
- mTLS client certificate authentication for PAM endpoints and LDAP (embedded CA)
- Break-glass escrow with multi-backend support (HashiCorp Vault, Infisical, Bitwarden/Vaultwarden)
- Audit event hash chains for tamper evidence (SOC 2 CC7.2 aligned)
- SSRF private IP denylist on webhook client
- Constant-time secret comparison to prevent timing side channels
- Extensive security hardening across 23+ audit rounds addressing input validation, CSRF, cookie security, rate limiting, path traversal, and more
- PKCE, hostname binding, HMAC domain separation

#### Notifications
- Multi-channel notification routing with per-admin preferences
- Six notification backends: webhook, email, Slack, Pushover, Gotify, ntfy
- Admin UI for managing notification channels, routes, and preferences
- Delivery latency metrics

#### Approval Policies
- Policy engine replacing the simple AdminApprovalHosts allowlist
- Time-of-day scheduling constraints
- Host group targeting
- Multi-approval (N-of-M quorum with partial approval tracking)
- Step-up OIDC re-authentication (`require_fresh_oidc`)
- Break-glass policy override for emergency access
- Per-policy notification channel routing

#### Admin UI
- Sessions page with active session display and inline bar approval
- Session highlight animation after inline bar approval
- Access management with filter controls and pending approval modal
- History page with user filtering, reason column, and pagination
- Host, user, group, and sudo rule management
- Notification channel and route configuration
- Approval policy editor
- Configuration page with live-update support
- Dark and light themes with WCAG AA contrast compliance
- Internationalization (i18n) support
- Responsive pagination across all pages (15/30/50/100)

#### Infrastructure
- Redis/Valkey state backend for multi-instance high availability
- Redis pub/sub cluster control channel for cross-instance state sync
- SSE Redis pub/sub reconnection with exponential backoff
- Notification config and admin preferences stored in Redis for HA
- Kubernetes Helm chart with PDB, NetworkPolicy, and resource defaults
- Multi-arch Docker images (linux/amd64, linux/arm64)
- Grafana dashboard JSON templates for monitoring
- Audit log file rotation (size-based)
- Health endpoint with writable state file check
- OpenAPI 3.1 specification (55+ endpoints)
- GitHub Actions CI/CD pipeline with multi-OS integration tests
- Ed25519 signed install scripts with static/config split architecture and custom script support
- Install script with per-platform download links

#### Audit
- Four SIEM sink backends (syslog, webhook, Loki, Splunk HEC)
- Hash chain integrity verification for tamper evidence
- `remote_addr` tracking on all audit events
- Comprehensive event coverage: login, session extend, challenge lifecycle, notification config, break-glass escrow/deploy
