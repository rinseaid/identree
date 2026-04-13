# Redis / Valkey State Backend

## Overview

By default, identree stores all runtime state (challenges, grace sessions, action logs, rate limiters) in memory and on disk as JSON files. This zero-dependency mode works perfectly for single-instance deployments.

For **high availability** or **multi-instance** deployments, switch to the Redis-compatible state backend. identree uses the Redis wire protocol, so any of these servers work interchangeably:

| Server | Description |
|--------|-------------|
| [Redis](https://redis.io/) | The original. Mature, widely deployed. |
| [Valkey](https://valkey.io/) | Open-source Redis fork (Linux Foundation). Drop-in compatible. |
| [Dragonfly](https://www.dragonflydb.io/) | Low-memory, multi-threaded alternative. Same wire protocol. |

identree does not care which one you run -- they all speak the same protocol.

---

## Quick Start -- Docker Compose

### Option A: Valkey (official Redis fork)

```yaml
services:
  valkey:
    image: valkey/valkey:8
    ports: ["6379:6379"]
    healthcheck:
      test: ["CMD", "valkey-cli", "ping"]

  identree:
    environment:
      IDENTREE_STATE_BACKEND: "redis"
      IDENTREE_REDIS_URL: "redis://valkey:6379/0"
```

### Option B: Dragonfly (low-memory alternative, single-binary)

```yaml
services:
  dragonfly:
    image: docker.dragonflydb.io/dragonflydb/dragonfly
    ports: ["6379:6379"]

  identree:
    environment:
      IDENTREE_STATE_BACKEND: "redis"
      IDENTREE_REDIS_URL: "redis://dragonfly:6379/0"
```

Both options are functionally identical from identree's perspective. Pick whichever fits your infrastructure.

---

## Quick Start -- Kubernetes

### Valkey via Bitnami Helm chart

```
helm install valkey oci://registry-1.docker.io/bitnamicharts/valkey \
  --set architecture=standalone \
  --set auth.password=your-secret
```

### Dragonfly via operator

```yaml
apiVersion: dragonflydb.io/v1alpha1
kind: Dragonfly
metadata:
  name: dragonfly
spec:
  replicas: 2
  resources:
    requests:
      memory: 128Mi
```

### Configure identree Helm chart

```yaml
stateBackend: redis
redis:
  url: redis://valkey:6379/0
  password: your-secret
```

See [Task 3 in the Helm chart section](#helm-chart) for the full set of Helm values.

---

## Configuration Reference

All Redis settings are configured via environment variables:

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_STATE_BACKEND` | `local` | `local` (file-based, single instance) or `redis` (multi-instance HA) |
| `IDENTREE_REDIS_URL` | -- | Redis connection URL (`redis://host:6379/0`) |
| `IDENTREE_REDIS_PASSWORD` | -- | Redis AUTH password (overrides any password in the URL) |
| `IDENTREE_REDIS_PASSWORD_FILE` | -- | Path to file containing Redis password |
| `IDENTREE_REDIS_DB` | `0` | Redis database number |
| `IDENTREE_REDIS_KEY_PREFIX` | `identree:` | Key namespace prefix (for shared Redis instances) |
| `IDENTREE_REDIS_TLS` | `false` | Enable TLS for Redis connections |
| `IDENTREE_REDIS_TLS_CA_CERT` | -- | Path to CA certificate PEM file for TLS verification |
| `IDENTREE_REDIS_SENTINEL_MASTER` | -- | Sentinel master name (enables Sentinel mode) |
| `IDENTREE_REDIS_SENTINEL_ADDRS` | -- | Comma-separated Sentinel addresses (`sentinel1:26379,sentinel2:26379`) |
| `IDENTREE_REDIS_CLUSTER_ADDRS` | -- | Comma-separated Cluster node addresses (`node1:6379,node2:6379,node3:6379`) |
| `IDENTREE_REDIS_POOL_SIZE` | `50` | Connection pool size (see [Pool sizing](#pool-sizing) below) |
| `IDENTREE_REDIS_DIAL_TIMEOUT` | `5s` | TCP connection timeout |
| `IDENTREE_REDIS_READ_TIMEOUT` | `3s` | Read timeout per command |
| `IDENTREE_REDIS_WRITE_TIMEOUT` | `3s` | Write timeout per command |

### Pool sizing

The default pool size of 50 connections is suitable for most deployments handling up to several hundred concurrent users. Each identree instance maintains its own pool, so a 3-instance cluster uses up to 150 total connections.

**Sizing guidance:**

- **Small deployments (< 50 hosts):** The default of 50 is more than sufficient. You can lower it to 20 if Redis memory is constrained.
- **Medium deployments (50-500 hosts):** The default of 50 works well. Monitor `identree_redis_pool_active` -- if it regularly exceeds 80% of pool size, increase to 100.
- **Large deployments (500+ hosts):** Set to 100-200. At this scale, also consider Redis Cluster or Sentinel for high availability.

The pool is shared across all Redis operations (challenges, grace sessions, rate limiters, action logs, SSE pub/sub). Under-provisioning causes goroutines to block waiting for a connection, increasing request latency. Over-provisioning wastes Redis server memory (each connection uses ~10 KB on the server side).

---

## Redis Data Model

identree stores the following in Redis. All keys are prefixed with `IDENTREE_REDIS_KEY_PREFIX` (default `identree:`).

| Data | Redis type | TTL | Description |
|------|-----------|-----|-------------|
| Challenges | Hash | `IDENTREE_CHALLENGE_TTL` | Pending sudo challenges. Each challenge is a hash with fields for user, host, code, status, timestamps. Automatically expires. |
| Grace sessions | String (key) | `IDENTREE_GRACE_PERIOD` | Records that a user recently approved on a specific host. Key presence = grace active. |
| Action log | List (capped) | None (capped by length) | Per-user lists of recent actions, used for the history/access views. Lists are trimmed to a maximum length. |
| Rate limiters | String (counter) | Sliding window | Per-user and per-host rate limit counters with TTL-based sliding windows. |
| Session nonces | String (key) | Short TTL | One-time nonces used during the OIDC callback flow to prevent replay. |
| Escrow records | Hash | None | Encrypted break-glass password escrow data (local backend only). |
| Notification config | Hash | None | Notification channels and routes (`{prefix}notify:config`). Synced across instances on write. |
| Admin notification prefs | Hash | None | Per-admin notification preferences (`{prefix}notify:prefs`). |
| SSE pub/sub | Pub/Sub channel | N/A | Cross-instance event propagation for real-time dashboard updates. |

---

## Connection Modes

### Standalone

The simplest mode. Point identree at a single Redis/Valkey/Dragonfly instance:

```sh
IDENTREE_REDIS_URL=redis://host:6379/0
```

With authentication:

```sh
IDENTREE_REDIS_URL=redis://host:6379/0
IDENTREE_REDIS_PASSWORD=your-secret
```

### Sentinel

For automatic failover with Redis Sentinel. Set the master name and Sentinel addresses instead of a direct URL:

```sh
IDENTREE_REDIS_SENTINEL_MASTER=mymaster
IDENTREE_REDIS_SENTINEL_ADDRS=sentinel1:26379,sentinel2:26379,sentinel3:26379
IDENTREE_REDIS_PASSWORD=your-secret
```

When Sentinel settings are present, `IDENTREE_REDIS_URL` is ignored. identree discovers the current master via the Sentinel protocol and reconnects automatically on failover.

### Cluster

For Redis Cluster deployments, provide the cluster node addresses:

```sh
IDENTREE_REDIS_CLUSTER_ADDRS=node1:6379,node2:6379,node3:6379
IDENTREE_REDIS_PASSWORD=your-secret
```

When cluster addresses are present, `IDENTREE_REDIS_URL` and Sentinel settings are ignored. identree uses hash tags in its key prefix to ensure related keys land on the same slot.

### TLS

Enable TLS for any connection mode:

```sh
IDENTREE_REDIS_TLS=true
IDENTREE_REDIS_TLS_CA_CERT=/path/to/ca.pem   # optional: custom CA
```

When TLS is enabled, identree connects over `rediss://` regardless of the scheme in `IDENTREE_REDIS_URL`. If `IDENTREE_REDIS_TLS_CA_CERT` is set, that CA is used for server verification; otherwise the system certificate pool is used.

---

## Multi-Instance Deployment

With the Redis backend enabled, you can run two or more identree instances behind a load balancer:

```
                ┌─────────────┐
                │ Load Balancer│
                └──────┬──────┘
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
         identree  identree  identree
              │        │        │
              └────────┼────────┘
                       ▼
                    Redis/Valkey
```

Key points:

- **All instances point to the same Redis.** Challenges, sessions, and state are shared.
- **SSE connections are instance-local** but events propagate via Redis pub/sub. When a challenge is approved on instance A, instance B's dashboard connections receive the update within milliseconds.
- **No sticky sessions required.** Any instance can serve any request.
- **Rolling deployments work.** Use `RollingUpdate` strategy instead of `Recreate` when running multiple replicas.
- **Health check:** `GET /healthz` includes a Redis PING check. If Redis is unreachable, the instance reports `unhealthy` (503).

### Kubernetes example

```yaml
# values.yaml
replicaCount: 2
stateBackend: redis
redis:
  url: redis://valkey:6379/0
```

With 2+ replicas, the Helm chart automatically switches from `Recreate` to `RollingUpdate` deployment strategy.

---

## Monitoring

### Prometheus metrics

When the Redis backend is active, identree exports additional metrics at `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `identree_redis_pool_size` | Gauge | Total connections in the pool |
| `identree_redis_pool_idle` | Gauge | Idle connections in the pool |
| `identree_redis_pool_active` | Gauge | Active (in-use) connections |
| `identree_redis_command_duration_seconds` | Histogram | Latency of Redis commands (buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms) |

### Health endpoint

When `stateBackend=redis`, the `/healthz` endpoint includes an additional `redis` check:

```json
{
  "status": "ok",
  "checks": {
    "disk": "ok",
    "redis": "ok",
    "ldap_sync": "ok",
    "ldap_server": "ok",
    "pocketid": "ok",
    "oidc": "ok"
  }
}
```

| Check value | Meaning |
|-------------|---------|
| `"ok"` | Redis PING succeeded |
| `"unreachable"` | Redis connection failed (instance reports 503 unhealthy) |

### Grafana dashboard additions

Add these panels to your identree dashboard when using Redis:

- **Redis pool utilization** -- `identree_redis_pool_active` / `identree_redis_pool_size`
- **Redis command latency** -- p50, p90, p99 from `identree_redis_command_duration_seconds`
- **Redis health** -- alert on `/healthz` returning `redis: unreachable`

---

## Failover Behavior

What happens when Redis goes down:

| Component | Behavior |
|-----------|----------|
| **Challenge creation** | Fails with HTTP 503. PAM client retries for the configured timeout, then falls back to break-glass if enabled. |
| **Challenge approval** | Fails. User sees an error on the approval page. Challenge expires and PAM client falls back to break-glass. |
| **Grace period checks** | Fail closed. No Redis means no grace session lookup, so a new challenge is required. This is the safe default. |
| **Action log writes** | Best-effort. Writes are dropped if Redis is unavailable. A counter (`identree_audit_events_total{status="dropped"}`) is incremented. No data loss for the primary audit sinks (stdout, syslog, Splunk, Loki). |
| **SSE dashboard updates** | Instance-local events still work. Cross-instance propagation stops until Redis reconnects. |
| **Rate limiting** | Fails open. If the rate limiter cannot read/write Redis, the request is allowed through. |
| **Reconnection** | Automatic. go-redis includes built-in retry with exponential backoff. No manual intervention needed. |

### Break-glass is your safety net

The break-glass fallback is designed for exactly this scenario. When the server cannot create or resolve challenges (Redis down, network partition, server crash), the PAM client prompts for the local break-glass password. Ensure break-glass is enabled and passwords are escrowed. See [docs/breakglass.md](breakglass.md).

---

## Dragonfly vs Redis/Valkey

| Feature | Redis / Valkey | Dragonfly |
|---------|---------------|-----------|
| Memory efficiency | Baseline | 2-5x better |
| Multi-threaded | No (single-threaded) | Yes |
| Sentinel HA | Yes | No (built-in replication) |
| Cluster mode | Yes | Yes |
| Persistence | RDB + AOF | Snapshots |
| Docker image size | ~30 MB | ~30 MB |
| Recommended for | Production with Sentinel | Homelabs, single-node |

**Choosing:**

- **Production with HA requirements:** Use Valkey/Redis with Sentinel or Cluster. Sentinel provides well-tested automatic failover with minimal overhead.
- **Homelab or single-node:** Dragonfly uses significantly less memory and runs as a single binary. It works well for small-scale deployments where Sentinel complexity is not justified.
- **Kubernetes with operator:** Dragonfly's operator provides a simple CRD-based deployment. Valkey via Bitnami Helm chart is also straightforward.

All three are fully compatible with identree. The choice is purely operational.
