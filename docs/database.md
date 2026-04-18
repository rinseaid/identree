# Database backend

identree persists every piece of mutable state — challenges, grace sessions,
the action log, escrow records, agent heartbeats, revocations, OIDC login
nonces — to a SQL database. There is no other persistence layer; the
database is the source of truth.

Two drivers are supported:

| Driver | When to use | Concurrency model |
|---|---|---|
| `sqlite` (default) | Single-node homelab, small teams | WAL + single-writer connection |
| `postgres` | HA, enterprise, multiple identree replicas | row-level locks via `SELECT ... FOR UPDATE` |

Both share the same schema, the same query strings (placeholders are
rewritten at execution time), and the same Go test suite — what works on
SQLite works on Postgres.

## Quick start (SQLite, default)

No configuration needed. identree creates `/config/identree.db` on first
boot. Mount `/config` to a persistent volume:

```yaml
# docker-compose.yml
identree:
  image: ghcr.io/rinseaid/identree:latest
  volumes:
    - identree-data:/config
volumes:
  identree-data:
```

That's it. Action history, grace sessions, agent heartbeats, and
revocations all survive restarts. Back up `identree.db` (and the WAL
sidecar `identree.db-wal` if present) to back up identree's state.

## Postgres (HA / enterprise)

Set two environment variables:

```bash
IDENTREE_DATABASE_DRIVER=postgres
IDENTREE_DATABASE_DSN=postgres://identree:STRONG_PASSWORD@db.internal:5432/identree?sslmode=require
```

Then run as many identree replicas behind a load balancer as you want.
All replicas share the same Postgres state; no sticky sessions are
required. Cross-replica events (admin session revocations, dashboard SSE
fan-out) are coordinated via Postgres `LISTEN/NOTIFY`.

The user identree connects as needs `CREATE TABLE` privilege on first
boot (so `CREATE TABLE IF NOT EXISTS` can apply the schema). After that,
plain `INSERT/UPDATE/DELETE/SELECT` is enough.

## Tuning

| Variable | Default | Notes |
|---|---|---|
| `IDENTREE_DATABASE_MAX_OPEN_CONNS` | `1` (sqlite), `25` (postgres) | Pool ceiling. SQLite serialises all writes through one connection; raising this on SQLite buys you nothing and risks `database is locked` errors. |

## Schema

The schema is applied at startup with `CREATE TABLE IF NOT EXISTS`. There
is no migration framework yet — identree is greenfield, so v1 starts with
a clean schema and any future evolution will introduce a versioned
migrator. The current tables:

- `challenges` — every sudo elevation request and its lifecycle
- `action_log` — append-only audit trail surfaced by `/admin/history`
- `grace_sessions` — active grace periods, HMAC-signed when
  `IDENTREE_SESSION_SECRET` is set
- `agents` — last_seen / version / OS info per managed host (see
  [Agent heartbeats](#agent-heartbeats) below)
- `revoked_nonces`, `revoked_admin_sessions`, `revoke_tokens_before` —
  session and token invalidation records
- `escrowed_hosts`, `escrow_ciphertexts`, `used_escrow_tokens` — escrow
  metadata + replay protection
- `last_oidc_auth`, `session_nonces` — OIDC login state
- `rotate_breakglass_before` — per-host break-glass rotation timestamps
- `cluster_messages` — overflow buffer for `LISTEN/NOTIFY` payloads
  larger than Postgres's 8 KB notification limit
- `notify_admin_prefs`, `notify_config` — placeholders for future
  SQL-backed notification config

A background goroutine ticks every 10 seconds to mark expired challenges,
prune used escrow tokens older than 10 minutes, and trim revoked nonces
older than 35 minutes.

## Agent heartbeats

Each managed host pings `POST /api/agent/heartbeat` every 5 minutes
(via the systemd timer installed by `install.sh`, or by `identree
heartbeat` from cron). The server records the host in the `agents`
table with its version and OS info.

Query the fleet with `GET /api/agents` (admin session):

```bash
curl -s --cookie pam_session=... https://identree/api/agents | jq
{
  "agents": [
    {
      "hostname": "prod-web-01",
      "version": "0.42.0",
      "os_info": "linux/amd64",
      "ip": "10.0.0.12",
      "first_seen": "2026-04-01T09:00:00Z",
      "last_seen": "2026-04-17T20:55:14Z",
      "last_seen_ago": "12s",
      "status": "green"
    }
  ]
}
```

`status` is bucketed by `now - last_seen`:

| Status | Window |
|---|---|
| `green` | <10 minutes |
| `amber` | 10–60 minutes |
| `red` | ≥60 minutes |

Green is heartbeat-cadence + one missed ping (5min × 2), so a single
missed packet doesn't flip a healthy host amber.

To add the heartbeat timer to an existing host that was provisioned
before this feature shipped:

```bash
sudo /usr/local/bin/identree heartbeat        # one-shot test
curl -fsSL https://identree.example/install.sh | sudo bash   # re-installs the timer
```

## Backup and restore

### SQLite

`identree.db` is a normal SQLite file. With the server running, take a
consistent snapshot with the SQLite backup API:

```bash
sqlite3 /config/identree.db ".backup /backup/identree.db.$(date +%F)"
```

`cp` while the server is running is **not** safe — WAL writes may be
mid-flight. Always use `.backup` or stop the server first.

Restore: `cp identree.db.<date> /config/identree.db` with the server
stopped.

### Postgres

Standard `pg_dump` / `pg_restore` against the identree database. Take
the dump while the server is running; identree never holds long
transactions, so concurrent dumps don't block live traffic.

## Migration from earlier identree versions

There is no in-place migration. v1 is the first SQL-backed release; the
old JSON state file (`/config/sessions.json`) and Redis backend are
gone. If you're coming from a pre-release with a populated state file,
the cleanest path is to start fresh — challenges and short-lived grace
sessions don't need to carry over, and the action log is reconstructed
naturally as new approvals flow.

If preserving history matters, drop a feature request — a one-shot
import command can be added.
