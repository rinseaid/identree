# Operations Guide

This guide covers day-to-day operational concerns for running identree in production: reverse proxy configuration, backup procedures, monitoring, audit durability, scaling, and security hardening.

---

## Reverse Proxy / TLS Termination

identree listens on plain HTTP internally (default `:8090`). TLS must always be terminated at a reverse proxy in front of it. `IDENTREE_EXTERNAL_URL` must match the public HTTPS URL exactly (e.g. `https://identree.example.com`).

The `/api/events` endpoint uses Server-Sent Events (SSE) for real-time dashboard updates. Your proxy must not buffer this path or it will break live challenge notifications.

### Key headers

Your proxy should set (or pass through) these headers on every request:

| Header | Purpose |
|---|---|
| `X-Forwarded-For` | Client IP for audit logs and rate limiting |
| `X-Forwarded-Proto` | Lets identree know the original scheme was HTTPS |
| `Host` | Must match the hostname in `IDENTREE_EXTERNAL_URL` |

Strip `X-Forwarded-*` headers from untrusted clients at the edge to prevent IP spoofing.

### nginx

```nginx
upstream identree {
    server 127.0.0.1:8090;
}

server {
    listen 443 ssl http2;
    server_name identree.example.com;

    ssl_certificate     /etc/ssl/certs/identree.pem;
    ssl_certificate_key /etc/ssl/private/identree.key;

    # Strip X-Forwarded-* from untrusted clients
    proxy_set_header X-Forwarded-For    $remote_addr;
    proxy_set_header X-Forwarded-Proto  $scheme;
    proxy_set_header Host               $host;

    location / {
        proxy_pass http://identree;

        # WebSocket / SSE support (required for /api/events)
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }
}
```

The critical lines for SSE are `proxy_buffering off` and the long `proxy_read_timeout`. Without these, the dashboard will not receive live challenge updates.

### Caddy

Caddy handles TLS automatically via Let's Encrypt:

```
identree.example.com {
    reverse_proxy 127.0.0.1:8090 {
        # Disable response buffering for SSE
        flush_interval -1
    }
}
```

Caddy sets `X-Forwarded-For` and `X-Forwarded-Proto` by default.

### Traefik (Docker labels)

```yaml
services:
  identree:
    image: identree:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.identree.rule=Host(`identree.example.com`)"
      - "traefik.http.routers.identree.tls=true"
      - "traefik.http.routers.identree.tls.certresolver=letsencrypt"
      - "traefik.http.services.identree.loadbalancer.server.port=8090"
      # Disable response buffering for SSE
      - "traefik.http.middlewares.identree-nobuffer.buffering.maxResponseBodyBytes=0"
      - "traefik.http.routers.identree.middlewares=identree-nobuffer"
```

Traefik forwards `X-Forwarded-For` and `X-Forwarded-Proto` by default.

---

## Backup and Recovery

### What to back up

identree stores all persistent state as JSON files in `/config/` (or wherever the corresponding `IDENTREE_*_FILE` variables point). Back up these files regularly:

| File | Contents | Impact if lost |
|---|---|---|
| `/config/sessions.json` | Active approved sudo sessions | Users must re-approve; no data loss |
| `/config/uidmap.json` | UID/GID assignments for LDAP users | UID reassignment breaks file ownership on hosts |
| `/config/hosts.json` | Registered host registry | Hosts must re-register |
| `/config/sudorules.json` | Sudo rules (bridge mode) | Sudo policies must be recreated |

**`uidmap.json` is the most critical file.** If lost, identree assigns new UIDs to existing users, which breaks file ownership on every managed host. Back this up regularly.

### Other files to back up

- **Break-glass hash files** (`/etc/identree-breakglass` on each managed host) -- the bcrypt hash is the only local authentication fallback if the server is unreachable.
- **TOML config** (`/etc/identree/identree.toml`) -- if you use the live configuration editor in the admin UI, changes are written to this file.
- **Escrow data** -- if using the `local` escrow backend, the encrypted break-glass passwords are stored inside identree's state. Ensure your backup captures the full `/config/` directory.

### Recovery procedure

1. Stop identree.
2. Restore `/config/sessions.json`, `/config/uidmap.json`, `/config/hosts.json`, and `/config/sudorules.json` from backup.
3. Restore `/etc/identree/identree.toml` if applicable.
4. Verify environment variables or config file contain all required secrets (`IDENTREE_SHARED_SECRET`, `IDENTREE_OIDC_CLIENT_SECRET`, etc.).
5. Start identree.
6. Open the admin UI and verify hosts appear and LDAP sync completes.

---

## Monitoring

### Healthcheck endpoint

```
GET /healthz
```

Returns JSON with per-component status:

```json
{
  "status": "ok",
  "checks": {
    "disk": "ok",
    "ldap_sync": "ok",
    "ldap_server": "ok",
    "pocketid": "ok",
    "oidc": "ok"
  }
}
```

| HTTP status | `status` field | Meaning |
|---|---|---|
| 200 | `"ok"` | All components healthy |
| 200 | `"degraded"` | PocketID or OIDC issuer unreachable (LDAP continues from cache) |
| 503 | `"unhealthy"` | Critical failure: disk not writable, LDAP sync stale, or LDAP server not started |

The Docker image includes a built-in `HEALTHCHECK` that polls `/healthz` every 30 seconds.

Component statuses:

| Check | `"ok"` | Failure value | Severity |
|---|---|---|---|
| `disk` | Config directory is writable | `"not_writable"` | Critical (503) |
| `ldap_sync` | Last sync within 1.5x refresh interval | `"stale"` | Critical (503) |
| `ldap_server` | LDAP listener is bound | `"not_started"` | Critical (503) |
| `pocketid` | PocketID API responds (full mode only) | `"unreachable"` | Degraded (200) |
| `oidc` | OIDC discovery endpoint responds | `"unreachable"` | Degraded (200) |

### Prometheus metrics

Metrics are served at `GET /metrics` in Prometheus exposition format.

**Authentication:** When `IDENTREE_METRICS_TOKEN` is set, requests must include `Authorization: Bearer <token>`. When unset, metrics are served without authentication.

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: identree
    scheme: https
    static_configs:
      - targets: ["identree.example.com"]
    authorization:
      credentials: "your-metrics-token"
```

### Key metrics to alert on

| Metric | Type | Alert condition | Description |
|---|---|---|---|
| `identree_challenges_created_total` | Counter | Unexpected drop to zero | No challenges being created may indicate PAM misconfiguration |
| `identree_challenges_approved_total` | Counter | — | Track approval rate |
| `identree_challenges_auto_approved_total` | Counter | — | Grace period / one-tap approvals |
| `identree_challenges_denied_total` | Counter (by `reason`) | Spike in denials | Possible brute-force or misconfiguration |
| `identree_challenge_duration_seconds` | Histogram | p95 > 60s | Users waiting too long for approval |
| `identree_audit_events_total{status="dropped"}` | Counter | Any increase | Audit events are being lost due to buffer overflow |
| `identree_audit_events_total{status="failed"}` | Counter | Any increase | A sink is failing to deliver events |
| `identree_breakglass_escrow_total{status="failure"}` | Counter | Any increase | Break-glass password escrow is failing |
| `identree_auth_failures_total` | Counter | Spike | Invalid shared secrets -- possible misconfigured or rogue host |
| `identree_rate_limit_rejections_total` | Counter | Sustained increase | Legitimate users may be rate-limited |
| `identree_ldap_sync_failures_total` | Counter | Any increase | PocketID API unreachable or returning errors |
| `identree_registered_hosts` | Gauge | Unexpected decrease | Hosts may have been removed |
| `identree_oidc_exchange_duration_seconds` | Histogram | p95 > 5s | OIDC provider is slow |
| `identree_notifications_total{status,channel}` | Counter | Spike in `status="failed"` | Notification delivery failures by channel |
| `identree_notification_delivery_duration_seconds{channel}` | Histogram | p95 > 10s | Notification delivery latency by channel |

### Grafana dashboards

Ready-to-import Grafana dashboard JSON files are provided in [`deploy/grafana/`](../deploy/grafana/):

| File | Contents |
|---|---|
| `identree-overview.json` | Challenge flow (rates, durations, active gauges), notifications (by channel/status, delivery latency), authentication (auth failures, rate limiting, OIDC latency), LDAP (sync failures, query rates, bind failures, host count), and break-glass escrow operations |
| `identree-audit-health.json` | Audit pipeline health (emitted/dropped/failed events by sink) and Redis backend metrics (pool connections, command latency) |

**Importing into Grafana:**

1. Open Grafana and navigate to **Dashboards > Import** (or the `+` menu > **Import dashboard**).
2. Click **Upload JSON file** and select one of the files from `deploy/grafana/`.
3. On the import screen, select your Prometheus datasource from the **Prometheus** dropdown (the dashboards use a `${DS_PROMETHEUS}` variable).
4. Click **Import**.

Both dashboards default to a 6-hour time range with 30-second refresh. The overview dashboard uses collapsible rows to organize panels by subsystem.

**Recommended alerts** (configure in Grafana or Alertmanager):

- `identree_audit_events_total{status="dropped"}` -- any increase means the audit buffer is full
- `identree_audit_events_total{status="failed"}` -- any increase means a sink is failing
- `identree_auth_failures_total` -- spike indicates invalid shared secrets (misconfigured or rogue host)
- `identree_breakglass_escrow_total{status="failure"}` -- any increase means escrow is broken
- `identree_challenge_duration_seconds` p95 > 60s -- users waiting too long for approval
- `identree_oidc_exchange_duration_seconds` p95 > 5s -- OIDC provider is slow

---

## Audit Durability and Event Loss

identree supports multiple audit sinks running simultaneously. Each has different durability characteristics. Understanding these tradeoffs is critical for compliance.

### JSON log sink (stdout or file)

- **Durability:** Synchronous write. Events are written to the output stream before the function returns.
- **Loss scenario:** A process crash (SIGKILL, OOM) may lose the event currently being written. In practice, this is effectively zero-loss for normal operations.
- **Recommendation:** Use as your primary sink. Container runtimes (Docker, Kubernetes) capture stdout automatically, making it the simplest and most reliable option.

```sh
IDENTREE_AUDIT_LOG=stdout
# or
IDENTREE_AUDIT_LOG=file:/var/log/identree/audit.jsonl
```

### Syslog (RFC 5424)

- **UDP:** Fire-and-forget. Events may be lost on network congestion, packet drops, or if the syslog receiver is down. No delivery confirmation.
- **TCP:** Reliable delivery with automatic reconnection on connection failure. Events buffer in-process during reconnection.
- **Recommendation:** Use TCP (`tcp://host:601`) if syslog is your compliance sink. UDP is acceptable only as a secondary/convenience sink.

```sh
IDENTREE_AUDIT_SYSLOG_URL=tcp://syslog.local:601   # reliable
IDENTREE_AUDIT_SYSLOG_URL=udp://syslog.local:514   # fire-and-forget
```

### Splunk HEC / Loki

- **Durability:** Events are batched (up to 100 events or 5 seconds) before being pushed over HTTP.
- **Loss scenario:** Up to 5 seconds of events (one batch window) can be lost on a hard crash. Events in the current batch that have not yet been flushed are gone.
- **Recommendation:** Use as a secondary sink alongside the JSON log sink. The JSON log captures everything synchronously; Splunk/Loki provides searchability and dashboards.

### Buffer overflow

All sinks receive events through a buffered channel (default size: 4096). If all sinks are slow or blocked, new events are **dropped** rather than blocking the server. Dropped events are counted:

```
identree_audit_events_total{sink="_channel",status="dropped"}
```

Alert on any increase in this counter. If you see drops, either increase the buffer size or investigate why sinks are slow:

```sh
IDENTREE_AUDIT_BUFFER_SIZE=8192   # increase from default 4096
```

### Recommended configuration

Use the JSON log sink as your primary (captured by the container runtime with no configuration), and add Splunk/Loki/syslog as secondary sinks for search and alerting:

```sh
IDENTREE_AUDIT_LOG=stdout                                          # primary: zero-loss
IDENTREE_AUDIT_SPLUNK_HEC_URL=https://splunk.example.com:8088/...  # secondary: searchable
IDENTREE_AUDIT_SYSLOG_URL=tcp://syslog.local:601                   # secondary: compliance
```

---

## Scaling Considerations

### Single-instance (default)

By default, identree is a single-instance service. All state is stored in local JSON files (`sessions.json`, `uidmap.json`, `hosts.json`, `sudorules.json`) and in-memory challenge maps. There is no database, no clustering, and no leader election. This is intentional -- it keeps the operational footprint minimal and eliminates distributed-system failure modes.

With the default `local` state backend, do not run multiple identree instances behind a load balancer. Challenges are stored in memory on the instance that created them; a second instance would not see them.

### Multi-instance with Redis

To run multiple identree instances for high availability, switch to the Redis state backend. Set `IDENTREE_STATE_BACKEND=redis` and point all instances at the same Redis/Valkey/Dragonfly server. Challenges, sessions, and all runtime state are shared via Redis, and dashboard SSE events propagate across instances via Redis pub/sub.

No sticky sessions are required. Any instance can serve any request.

See [redis-ha.md](redis-ha.md) for full deployment guides covering Docker Compose, Kubernetes, Sentinel, Cluster mode, TLS, failover behavior, and monitoring.

### Capacity

identree handles thousands of concurrent challenges whether stored in memory (local backend) or Redis. The bottleneck in practice is the OIDC provider (token exchange latency) rather than identree itself. Monitor `identree_oidc_exchange_duration_seconds` to detect IdP slowdowns.

### LDAP refresh interval tuning

In full mode, identree polls the PocketID API every `IDENTREE_LDAP_REFRESH_INTERVAL` (default 300 seconds / 5 minutes) to sync users and groups. For large directories (1000+ users):

- **Increase the interval** if the PocketID API is under load. Set `IDENTREE_LDAP_REFRESH_INTERVAL=600s` or higher.
- **Use webhooks** for near-instant sync. Point a PocketID webhook at `https://identree.example.com/api/webhook/pocketid` with `IDENTREE_WEBHOOK_SECRET` set. This triggers an immediate refresh on user/group changes, letting you use a longer polling interval as a fallback.

### Rate limiting

identree applies internal rate limiting to challenge creation to prevent abuse. Rejected requests are counted in `identree_rate_limit_rejections_total`. If legitimate users are being rate-limited, check for:

- Misconfigured PAM on a host retrying in a tight loop
- Automated scripts running `sudo` repeatedly
- A compromised host flooding the server

---

## Security Hardening Checklist

Review this list before going to production.

- [ ] **`IDENTREE_SHARED_SECRET` is 32+ random bytes**
  Generate with `openssl rand -hex 32`. This secret authenticates every PAM client request. A weak or leaked secret means any network host can create and approve challenges.

- [ ] **`IDENTREE_EXTERNAL_URL` uses HTTPS**
  All OIDC flows, approval URLs, and API calls use this URL. HTTP in production exposes tokens and session cookies.

- [ ] **`IDENTREE_WEBHOOK_SECRET` is set**
  Without this, anyone who can reach `/api/webhook/pocketid` can trigger LDAP refreshes. With a flood of requests, this becomes a denial-of-service vector.

- [ ] **`IDENTREE_ESCROW_HKDF_SALT` is set**
  Generate with `openssl rand -hex 32`. This salt diversifies the encryption key for the local escrow backend per deployment. Without it, a static legacy salt is used (and a warning is logged at startup). Two deployments with the same `ESCROW_ENCRYPTION_KEY` and no salt produce identical ciphertexts.

- [ ] **`IDENTREE_METRICS_TOKEN` is set**
  Without this, `/metrics` is unauthenticated. Prometheus metrics expose challenge counts, host counts, failure rates, and OIDC latency -- useful reconnaissance for an attacker.

- [ ] **Break-glass passwords are escrowed (not just local hash)**
  Without escrow, the break-glass password exists only as a bcrypt hash on the managed host. You can verify it works but cannot recover the plaintext if a user needs emergency access. Configure an escrow backend (`local`, `vault`, `1password-connect`, `bitwarden`, or `infisical`).

- [ ] **State files (`/config/`) are on a persistent volume with restricted permissions**
  `sessions.json` contains active session data. `uidmap.json` contains UID mappings. Mount `/config` on a volume accessible only to the identree container user (UID/GID `identree`).

- [ ] **Reverse proxy strips `X-Forwarded-*` from untrusted clients**
  identree trusts `X-Forwarded-For` for audit logging. If your proxy does not strip these headers from inbound requests, an attacker can spoof their source IP in audit logs.

- [ ] **LDAP bind credentials are set (if LDAP is network-exposed)**
  Set `IDENTREE_LDAP_BIND_DN` and `IDENTREE_LDAP_BIND_PASSWORD` to require authentication for LDAP queries. Without these (and with `IDENTREE_LDAP_ALLOW_ANONYMOUS=true`), anyone who can reach port 389 can enumerate your entire user directory.

- [ ] **Set independent secrets (`IDENTREE_SESSION_SECRET`, `IDENTREE_ESCROW_SECRET`, `IDENTREE_LDAP_SECRET`)**
  Split secrets limit blast radius if one is compromised. Each defaults to `IDENTREE_SHARED_SECRET` when unset, but production deployments should set all three independently.

- [ ] **`IDENTREE_OIDC_CLIENT_SECRET` is kept out of version control**
  Use environment variables or a secrets manager. Never commit OIDC credentials to a repository.

- [ ] **Auditd monitoring rules are installed on managed hosts**
  The install script installs auditd rules automatically if auditd is present. These rules create a kernel-level audit trail for break-glass hash reads, config file changes, PAM bypass attempts, and mTLS key exfiltration. Verify with `auditctl -l | grep identree`. Forward audit logs off-host for tamper resistance. See [auditd.md](auditd.md) for details.

- [ ] **Use a dedicated signing key for install scripts (not auto-generated)**
  The auto-generated keypair is convenient for development but lives on the server. In production, generate a keypair offline and keep the private key on a trusted workstation. Configure `IDENTREE_INSTALL_SIGNING_KEY` and `IDENTREE_INSTALL_VERIFY_KEY` to point to your keys. See [install-scripts.md](install-scripts.md) for the full production flow.

- [ ] **Distribute the install verification public key out-of-band (bake into host images)**
  Do not fetch the public key from the server at install time (TOFU). Instead, bake it into your base images, distribute it via configuration management (Ansible, Puppet, Chef), or include it in your provisioning pipeline. This ensures verification does not depend on the server's integrity.

- [ ] **Verify install script signatures before execution on all new hosts**
  Before running the install script on any host, verify its detached Ed25519 signature:
  ```sh
  curl -sf https://identree.example.com/install.sh     -o /tmp/install.sh
  curl -sf https://identree.example.com/install.sh.sig -o /tmp/install.sh.sig
  identree verify-install --key /path/to/install-verify.pub --script /tmp/install.sh --sig /tmp/install.sh.sig
  sudo IDENTREE_SHARED_SECRET=xxx bash /tmp/install.sh https://identree.example.com
  ```
  A non-zero exit code from `verify-install` means the script has been tampered with. Do not execute it. See [install-scripts.md](install-scripts.md) for architecture details and custom script support.

---

## LDAPS Troubleshooting

When LDAPS (LDAP over TLS with mTLS) is enabled, the most common issues involve certificate trust and handshake failures. This section covers diagnosis and resolution.

### mTLS handshake failures

If clients cannot connect to port 636, the TLS handshake is failing. Common causes:

- **Client certificate not presented.** The client must send a certificate signed by the CA configured in `IDENTREE_LDAP_TLS_CA_CERT`. Verify with:
  ```sh
  LDAPTLS_CERT=/etc/identree/client.crt \
  LDAPTLS_KEY=/etc/identree/client.key \
  LDAPTLS_CACERT=/etc/identree/ca.crt \
  ldapsearch -H ldaps://identree.example.com:636 -b "dc=example,dc=com" -D "cn=readonly,dc=example,dc=com" -w secret "(objectClass=*)"
  ```
- **Wrong CA.** The client certificate must be signed by the exact CA the server is configured with. Check with:
  ```sh
  openssl verify -CAfile /etc/identree/ca.crt /etc/identree/client.crt
  ```
- **Server certificate hostname mismatch.** If the server's TLS certificate does not include the hostname the client connects to, the handshake will fail. Add `-d 1` to `ldapsearch` for verbose TLS output.

### Expired client certificates

Client certificates have a configurable TTL (default 1 year, set via `IDENTREE_MTLS_CERT_TTL`). When a certificate expires, the client will be rejected during the TLS handshake.

Check certificate expiry:
```sh
openssl x509 -in /etc/identree/client.crt -noout -enddate
```

To re-provision a host with a fresh certificate, re-run the install script or call the `/api/client/provision` endpoint.

### CA trust issues

- Ensure the CA certificate on the client (`ldap_tls_cacert` in sssd.conf or `LDAPTLS_CACERT`) matches the CA configured on the server (`IDENTREE_LDAP_TLS_CA_CERT`).
- If you rotated the CA, all existing client certificates become untrusted. Re-provision all hosts after a CA rotation.
- On some distributions, sssd caches TLS state. Restart sssd after changing certificate files:
  ```sh
  sudo systemctl restart sssd
  ```

### Testing with ldapsearch

A quick end-to-end test using `ldapsearch` and `LDAPTLS_*` environment variables:

```sh
# Test plaintext LDAP (port 389)
ldapsearch -H ldap://identree.example.com:389 -b "dc=example,dc=com" -D "cn=readonly,dc=example,dc=com" -w secret "(uid=*)"

# Test LDAPS with mTLS (port 636)
LDAPTLS_CERT=/etc/identree/client.crt \
LDAPTLS_KEY=/etc/identree/client.key \
LDAPTLS_CACERT=/etc/identree/ca.crt \
ldapsearch -H ldaps://identree.example.com:636 -b "dc=example,dc=com" -D "cn=readonly,dc=example,dc=com" -w secret "(uid=*)"
```

If the LDAPS test fails but plaintext works, the issue is in the TLS/mTLS configuration.

### Certificate expiry monitoring

Monitor client certificate expiry proactively to avoid outages:

- **Prometheus alert:** If your clients report certificate metadata, alert when any certificate is within 30 days of expiry.
- **Cron job on each host:** Schedule a periodic check and alert:
  ```sh
  # Alert if certificate expires within 30 days
  if openssl x509 -in /etc/identree/client.crt -noout -checkend 2592000 2>/dev/null; then
    : # OK
  else
    echo "WARN: identree client certificate expires within 30 days" | logger -t identree-cert
  fi
  ```
- **Centralized monitoring:** Use the identree audit log to track `provision` events and calculate when certificates were last issued. Certificates older than `IDENTREE_MTLS_CERT_TTL` minus a safety margin need rotation.

---

## Known Limitations

- Admin configuration panel help descriptions are English-only. All other user-facing strings are translated.
