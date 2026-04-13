# Notifications

identree delivers push notifications through named **channels** routed by configurable **rules**. Each admin can also subscribe to personal notification preferences.

---

## Architecture

```
Event (challenge_created, approved, etc.)
  │
  ├─ Routing Rules (org-level, config-driven)
  │    match event × hostname × username → channels
  │
  └─ Admin Preferences (per-admin, UI-driven)
       match event × hostname → channels
  └─ Deduplicate → Fan-out delivery to matched channels
```

---

## Notification channels

Channels are named destinations defined in `/config/notification-channels.json` (configurable via `IDENTREE_NOTIFICATION_CONFIG_FILE`). Manage them via the admin UI at **Admin > Notifications** or edit the JSON file directly.

### Supported backends

| Backend | Format | Use case |
|---------|--------|----------|
| `ntfy` | ntfy.sh JSON with action buttons | Self-hosted push notifications |
| `slack` | Incoming webhook payload | Slack channels |
| `discord` | Webhook embed format | Discord channels |
| `apprise` | Apprise API JSON | Multi-service router (80+ services) |
| `webhook` | Generic JSON | Any HTTP endpoint |
| `custom` | Shell command with env vars | Telegram, PagerDuty, custom scripts |

### Example configuration

```json
{
  "channels": [
    {
      "name": "ops-slack",
      "backend": "slack",
      "url": "https://hooks.slack.com/services/T.../B.../..."
    },
    {
      "name": "oncall-ntfy",
      "backend": "ntfy",
      "url": "https://ntfy.sh/oncall-alerts"
    },
    {
      "name": "security-discord",
      "backend": "discord",
      "url": "https://discord.com/api/webhooks/.../"
    },
    {
      "name": "custom-pager",
      "backend": "custom"
    }
  ],
  "routes": [
    {
      "channels": ["ops-slack", "oncall-ntfy"],
      "events": ["challenge_created", "challenge_approved", "challenge_rejected"],
      "hosts": ["*.prod", "bastion-*"]
    },
    {
      "channels": ["security-discord"],
      "events": ["revealed_breakglass", "breakglass_escrowed", "config_changed"]
    },
    {
      "channels": ["ops-slack"],
      "events": ["*"],
      "hosts": ["*.staging"]
    }
  ]
}
```

### Channel secrets

Tokens and custom commands are injected via environment variables (never stored in JSON):

```sh
# For a channel named "ops-slack":
IDENTREE_NOTIFY_CHANNEL_OPS_SLACK_TOKEN=xoxb-...

# For a channel named "custom-pager":
IDENTREE_NOTIFY_CHANNEL_CUSTOM_PAGER_COMMAND=/usr/local/bin/page.sh
```

The naming convention is: `IDENTREE_NOTIFY_CHANNEL_<NAME>_TOKEN` or `_COMMAND`, where `<NAME>` is the channel name uppercased with hyphens replaced by underscores.

---

## Routing rules

Routes determine which events are delivered to which channels. Each route specifies:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `channels` | string array | required | Channel names to deliver to |
| `events` | string array | required | Event type globs (`*` = all events) |
| `hosts` | string array | all | Hostname globs (empty = all hosts) |
| `users` | string array | all | Requesting-user globs (empty = all users) |

All filters use `filepath.Match` glob syntax. Routes are evaluated in order; all matching routes contribute their channels (not first-match-wins).

### Examples

**All challenge events on production hosts to ops channels:**
```json
{
  "channels": ["ops-slack", "oncall-ntfy"],
  "events": ["challenge_created", "challenge_approved", "challenge_rejected"],
  "hosts": ["*.prod", "bastion-*"]
}
```

**Security events (all hosts) to security team:**
```json
{
  "channels": ["security-discord"],
  "events": ["revealed_breakglass", "breakglass_escrowed", "config_changed"]
}
```

**Everything on staging to Slack:**
```json
{
  "channels": ["ops-slack"],
  "events": ["*"],
  "hosts": ["*.staging"]
}
```

---

## Per-admin notification preferences

Each admin can subscribe to notifications independently via **Admin > Notifications > My Notification Preferences**. This enables:

- **"Notify me about everything"**: set events to `*` and leave hosts empty
- **Targeted subscriptions**: e.g., only `challenge_created` events on `*.prod` hosts
- **Enable/disable toggle**: pause without deleting the subscription

Preferences are stored in `/config/admin-notifications.json` (configurable via `IDENTREE_ADMIN_NOTIFY_FILE`).

Admin preferences are evaluated alongside org-level routes. If both match, the channel is deduplicated (no duplicate delivery).

---

## Custom script backend

Custom commands receive event data via environment variables:

| Variable | Description |
|----------|-------------|
| `NOTIFY_CHANNEL` | Channel name |
| `NOTIFY_EVENT` | Event type (e.g. `challenge_created`) |
| `NOTIFY_USERNAME` | Unix username who ran sudo |
| `NOTIFY_HOSTNAME` | Hostname of the managed machine |
| `NOTIFY_USER_CODE` | Short code displayed at the terminal |
| `NOTIFY_APPROVAL_URL` | Best approval URL (one-tap if available) |
| `NOTIFY_ONETAP_URL` | Direct one-tap approval URL (may be empty) |
| `NOTIFY_EXPIRES_IN` | Seconds until the challenge expires |
| `NOTIFY_TIMESTAMP` | ISO 8601 timestamp |
| `NOTIFY_REASON` | Justification text (may be empty) |
| `NOTIFY_ACTOR` | Who performed the action (may be empty) |

`PATH` and `HOME` from the server process are passed through; no other environment is inherited.

### Example: Telegram

```sh
#!/bin/sh
curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
  -d chat_id="${TG_CHAT_ID}" \
  -d text="[${NOTIFY_EVENT}] ${NOTIFY_USERNAME}@${NOTIFY_HOSTNAME} — ${NOTIFY_APPROVAL_URL}"
```

---

## Events reference

| Event | When |
|-------|------|
| `challenge_created` | User runs `sudo` and a challenge is issued |
| `challenge_approved` | Admin approves in the browser |
| `challenge_rejected` | Admin rejects the challenge |
| `auto_approved` | Grace period auto-approval |
| `session_revoked` | Grace session revoked |
| `sessions_revoked_bulk` | Bulk session revocation |
| `grace_elevated` | Admin elevates a grace session |
| `revealed_breakglass` | Break-glass password revealed |
| `breakglass_escrowed` | Break-glass password escrowed to vault |
| `breakglass_rotation_requested` | Break-glass rotation requested |
| `host_removed` | Host removed from registry |
| `deployed` | Host deployment completed |
| `config_changed` | Server configuration changed |
| `server_restarted` | Server restart requested |
| `sudo_rule_modified` | Sudo rule added/updated/deleted |
| `user_removed` | User removed |
| `claims_updated` | User or group claims updated |
| `session_extended` | Grace session extended |
| `user_logged_in` | User logged in via OIDC/SAML |
| `notification_channel_added` | Notification channel created |
| `notification_channel_deleted` | Notification channel removed |
| `notification_route_added` | Notification route created |
| `notification_route_deleted` | Notification route removed |
| `test` | Test notification |

---

## Configuration reference

| Variable | Default | Description |
|----------|---------|-------------|
| `IDENTREE_NOTIFICATION_CONFIG_FILE` | `/config/notification-channels.json` | Path to channels/routes JSON |
| `IDENTREE_ADMIN_NOTIFY_FILE` | `/config/admin-notifications.json` | Path to admin preferences JSON |
| `IDENTREE_NOTIFY_TIMEOUT` | `15s` | Default delivery timeout (channels can override) |
| `IDENTREE_NOTIFY_CHANNEL_<NAME>_TOKEN` | — | Bearer token for a named channel |
| `IDENTREE_NOTIFY_CHANNEL_<NAME>_COMMAND` | — | Custom command for a named channel |

---

## Testing

Use the **Test** button next to each channel on the admin notifications page, or call the API:

```sh
# Test a specific channel
curl -X POST https://identree.example.com/api/admin/test-notification?channel=ops-slack \
  -H "Authorization: Bearer $API_KEY"

# Test all channels
curl -X POST https://identree.example.com/api/admin/test-notification \
  -H "Authorization: Bearer $API_KEY"
```

---

## Delivery behavior

- Notifications are dispatched asynchronously (non-blocking)
- Up to 50 concurrent deliveries (semaphore-gated)
- Webhook retries: 3 attempts with exponential backoff (1s, 2s)
- 4xx responses are treated as permanent failures (no retry)
- Prometheus metrics: `identree_notifications_total{status="sent|failed|skipped",channel="..."}`
- Delivery latency histogram: `identree_notification_delivery_duration_seconds{channel="..."}`
- Graceful shutdown waits for in-flight notifications (configurable timeout)
