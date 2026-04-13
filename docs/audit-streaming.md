# Audit Streaming

identree can stream structured audit events to external SIEM and log aggregation systems. Every security-relevant action — challenge creation, approval, rejection, session revocation, break-glass usage, config changes — is emitted as a JSON event to one or more configurable sinks.

Audit streaming is independent of the [notification system](notifications.md). Notifications are human-facing alerts (Slack, ntfy); audit events are machine-readable records for compliance, forensics, and monitoring. Both can run simultaneously.

---

## Quick start

```sh
# Stream to stdout (Docker/k8s logging pipelines pick this up automatically)
IDENTREE_AUDIT_LOG=stdout

# Or write to a file for log shippers (Filebeat, Promtail, Fluentd, etc.)
IDENTREE_AUDIT_LOG=file:/var/log/identree/audit.jsonl
```

That's it. Every SIEM can ingest structured JSON lines from stdout or a file.

---

## Event format

Each event is a single JSON line:

```json
{
  "seq": 42,
  "prev_hash": "sha256:9f86d08...a3d25",
  "timestamp": "2026-04-04T22:00:00Z",
  "event": "challenge_approved",
  "username": "alice",
  "hostname": "prod-web-01",
  "code": "ABCDEF-123456",
  "actor": "bob",
  "reason": "nginx declared war. help me win this battle.",
  "remote_addr": "198.51.100.23",
  "source": "identree",
  "version": "1.2.0"
}
```

| Field | Description |
|---|---|
| `seq` | Monotonically increasing sequence number (per server instance) |
| `prev_hash` | SHA-256 hash of the previous event's JSON line, forming a hash chain for tamper evidence |
| `timestamp` | RFC 3339 UTC timestamp |
| `event` | Action type (see table below) |
| `username` | User who initiated or is the subject of the action |
| `hostname` | Target host (if applicable) |
| `code` | User-visible challenge code (if applicable) |
| `actor` | Who performed the action, if different from `username` |
| `reason` | Justification text (if provided) |
| `remote_addr` | IP address of the client that triggered the event (from `X-Forwarded-For` or direct connection) |
| `source` | Always `"identree"` |
| `version` | Server build version |

### Hash chain (tamper evidence)

Each audit event includes a `seq` number and a `prev_hash` field containing the SHA-256 digest of the previous event's serialized JSON line. Together these form a hash chain: any insertion, deletion, or modification of a log entry breaks the chain, making tampering detectable. The first event in a server instance's lifetime has `prev_hash` set to `sha256:0`. This supports SOC 2 CC7.2 (system operations monitoring) by providing a verifiable, append-only audit trail.

---

## Event types

| Event | When |
|---|---|
| `challenge_created` | User runs `sudo` and a challenge is issued |
| `challenge_approved` | Challenge approved by user or admin |
| `challenge_rejected` | Challenge rejected |
| `auto_approved` | Grace period or one-tap auto-approval |
| `session_revoked` | Active session revoked |
| `sessions_revoked_bulk` | All sessions revoked for a user |
| `grace_elevated` | Admin elevated a session |
| `breakglass_rotation_requested` | Break-glass password rotation initiated |
| `revealed_breakglass` | Break-glass password revealed |
| `config_changed` | Server configuration updated |
| `user_removed` | User removed from system |
| `host_removed` | Host removed from registry |
| `breakglass_escrowed` | Break-glass password escrowed to vault |
| `sudo_rule_modified` | Sudo rule added, updated, or deleted |
| `claims_updated` | User or group claims updated |
| `server_restarted` | Server restart requested via admin UI |
| `deployed` | Remote host deploy completed successfully |
| `session_extended` | Grace session extended |
| `user_logged_in` | User logged in via OIDC/SAML |
| `notification_channel_added` | Notification channel created |
| `notification_channel_deleted` | Notification channel removed |
| `notification_route_added` | Notification route created |
| `notification_route_deleted` | Notification route removed |

---

## Sinks

Multiple sinks can be active simultaneously. For example, you can stream to both stdout and syslog.

### JSON log (stdout or file)

The highest-coverage option. Every SIEM can ingest JSON lines from stdout or a file:
- **Docker/Kubernetes**: stdout is captured by the container runtime and routed to your logging pipeline
- **Splunk**: Universal Forwarder or HEC file monitor input
- **Elastic**: Filebeat with JSON decoding
- **Loki**: Promtail with JSON pipeline stage
- **Datadog**: Agent log collection
- **Cribl**: File tailing source
- **Kafka**: Connect file source connector

```sh
IDENTREE_AUDIT_LOG=stdout                              # write to stdout
IDENTREE_AUDIT_LOG=file:/var/log/identree/audit.jsonl  # write to file (parent dirs created automatically)
```

### Syslog (RFC 5424)

Sends RFC 5424 messages over UDP or TCP. Covers most homelab setups, pfSense, OPNsense, rsyslog, syslog-ng, and any SIEM with a syslog receiver.

```sh
IDENTREE_AUDIT_SYSLOG_URL=udp://syslog.local:514
IDENTREE_AUDIT_SYSLOG_URL=tcp://syslog.local:601
```

Messages use facility `authpriv` (10), severity `info` (6), priority 86. The structured data element contains the event type and username; the message body is the full JSON event.

Example syslog line:
```
<86>1 2026-04-04T22:00:00Z myhost identree - - [identree@0 event="challenge_approved" username="alice" hostname="prod-web-01"] {"timestamp":"2026-04-04T22:00:00Z","event":"challenge_approved",...}
```

The sink reconnects automatically on connection failure.

### Splunk HEC

Pushes directly to a Splunk HTTP Event Collector endpoint. Events are batched (up to 100 events or 5 seconds) to reduce HTTP overhead.

```sh
IDENTREE_AUDIT_SPLUNK_HEC_URL=https://splunk.example.com:8088/services/collector/event
IDENTREE_AUDIT_SPLUNK_TOKEN=your-hec-token
```

Events arrive with `sourcetype=identree:audit` and `source=identree`.

### Loki

Pushes directly to a Grafana Loki instance via the HTTP push API. Events are batched (up to 100 events or 5 seconds).

```sh
IDENTREE_AUDIT_LOKI_URL=http://loki:3100
IDENTREE_AUDIT_LOKI_TOKEN=optional-bearer-token   # omit if no auth required
```

Events are labeled `{app="identree", job="identree-audit"}`. Each log line is the full JSON event, queryable with LogQL:

```logql
{app="identree"} | json | event="challenge_approved"
```

---

## Buffer and back-pressure

Events are dispatched via a buffered channel. If the buffer fills (all sinks are slow), new events are **dropped** rather than blocking the server. A Prometheus counter tracks dropped events:

```
identree_audit_events_total{sink="_channel",status="dropped"}
```

The buffer size defaults to 4096 and can be tuned:

```sh
IDENTREE_AUDIT_BUFFER_SIZE=4096   # default
```

Per-sink delivery metrics:

```
identree_audit_events_total{sink="jsonlog",status="emitted"}
identree_audit_events_total{sink="syslog",status="failed"}
identree_audit_events_total{sink="splunk_hec",status="emitted"}
```

---

## Configuration reference

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_AUDIT_LOG` | — | `stdout` or `file:/path/to/audit.jsonl` |
| `IDENTREE_AUDIT_SYSLOG_URL` | — | `udp://host:port` or `tcp://host:port` |
| `IDENTREE_AUDIT_SPLUNK_HEC_URL` | — | Splunk HEC endpoint URL |
| `IDENTREE_AUDIT_SPLUNK_TOKEN` | — | Splunk HEC authentication token |
| `IDENTREE_AUDIT_LOKI_URL` | — | Loki base URL (e.g. `http://loki:3100`) |
| `IDENTREE_AUDIT_LOKI_TOKEN` | — | Optional Loki bearer token |
| `IDENTREE_AUDIT_BUFFER_SIZE` | `4096` | Event channel buffer size |
| `IDENTREE_AUDIT_LOG_MAX_SIZE` | `100MB` | Max bytes per log file before rotation (`0` disables rotation). Accepts human-friendly suffixes: `KB`, `MB`, `GB`. |
| `IDENTREE_AUDIT_LOG_MAX_FILES` | `5` | Number of rotated log files to keep |
