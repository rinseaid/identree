# Notifications

identree can send notifications when sudo challenges are created or resolved. Set `IDENTREE_NOTIFY_BACKEND` to enable.

---

## Webhook backends

All webhook backends POST to a URL. The payload format is tailored to each service.

```sh
IDENTREE_NOTIFY_BACKEND=ntfy          # ntfy | slack | discord | apprise | webhook
IDENTREE_NOTIFY_URL=https://...       # destination URL
IDENTREE_NOTIFY_TOKEN=your-token      # optional — sent as Authorization: Bearer <token>
IDENTREE_NOTIFY_TIMEOUT=15s           # optional — default 15s
```

Webhook backends fire for all events: `challenge_created`, `challenge_approved`, `challenge_rejected`, and `auto_approved`.

### ntfy

```sh
IDENTREE_NOTIFY_BACKEND=ntfy
IDENTREE_NOTIFY_URL=https://ntfy.sh/your-topic
IDENTREE_NOTIFY_TOKEN=your-ntfy-token     # if your topic requires auth
```

The ntfy payload includes a title, message, and action button linking directly to the approval page.

### Slack

```sh
IDENTREE_NOTIFY_BACKEND=slack
IDENTREE_NOTIFY_URL=https://hooks.slack.com/services/T.../B.../...
```

Uses Slack's incoming webhook format with a formatted attachment block.

### Discord

```sh
IDENTREE_NOTIFY_BACKEND=discord
IDENTREE_NOTIFY_URL=https://discord.com/api/webhooks/.../.../
```

Uses Discord's webhook embed format.

### Apprise

```sh
IDENTREE_NOTIFY_BACKEND=apprise
IDENTREE_NOTIFY_URL=https://apprise.example.com/notify/your-tag
```

Uses the [Apprise API](https://github.com/caronc/apprise-api) JSON format. Apprise acts as a notification router and supports 80+ services.

### Raw webhook (generic JSON)

```sh
IDENTREE_NOTIFY_BACKEND=webhook
IDENTREE_NOTIFY_URL=https://your-service.example.com/webhook
IDENTREE_NOTIFY_TOKEN=your-token    # optional
```

Sends a plain JSON payload:

```json
{
  "event": "challenge_created",
  "username": "alice",
  "hostname": "server1",
  "user_code": "ABC123",
  "approval_url": "https://identree.example.com/approve/...",
  "one_tap_url": "https://identree.example.com/api/onetap/...",
  "expires_in": 120,
  "timestamp": "2025-01-15T10:30:00Z"
}
```

---

## Custom script

```sh
IDENTREE_NOTIFY_BACKEND=custom
IDENTREE_NOTIFY_COMMAND=/usr/local/bin/my-notify.sh   # executed via sh -c
IDENTREE_NOTIFY_TIMEOUT=15s
```

The command is run via `sh -c` with the following environment variables:

| Variable | Description |
|---|---|
| `NOTIFY_USERNAME` | Unix username who ran sudo |
| `NOTIFY_HOSTNAME` | Hostname of the managed machine |
| `NOTIFY_USER_CODE` | Short code displayed at the terminal |
| `NOTIFY_APPROVAL_URL` | Approval page URL (or one-tap URL if available) |
| `NOTIFY_ONETAP_URL` | Direct one-tap approval URL (empty if not available) |
| `NOTIFY_EXPIRES_IN` | Seconds until the challenge expires |
| `NOTIFY_TIMESTAMP` | ISO 8601 timestamp of when the challenge was created |

The custom backend fires only for `challenge_created` events. `PATH` and `HOME` from the server process are passed through; no other environment is inherited.

### Example: send a Telegram message

```sh
#!/bin/sh
curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
  -d chat_id="${TG_CHAT_ID}" \
  -d text="Sudo request from ${NOTIFY_USERNAME} on ${NOTIFY_HOSTNAME} — ${NOTIFY_APPROVAL_URL}"
```

Store the token and chat ID in a wrapper script or use a secrets manager to inject them at runtime.

---

## Events reference

| Event | When | Webhook | Custom script |
|---|---|---|---|
| `challenge_created` | User runs `sudo` and a challenge is issued | Yes | Yes |
| `challenge_approved` | User approves in the browser/app | Yes | No |
| `challenge_rejected` | User or admin rejects | Yes | No |
| `auto_approved` | Grace period or one-tap auto-approval | Yes | No |
