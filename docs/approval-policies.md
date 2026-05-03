# Approval Policies

Approval policies control who can approve challenges, when, and how many approvals are needed. Policies are defined in a JSON file and evaluated at challenge creation and approval time.

---

## Configuration

Set the policy file path:

```sh
IDENTREE_APPROVAL_POLICIES_FILE=/config/approval-policies.json  # default
```

Manage policies via the admin UI at **Admin > Policies** or edit the JSON file directly.

---

## Policy schema

```json
[
  {
    "name": "production",
    "match_hosts": ["prod-*", "bastion-*"],
    "match_host_groups": ["production"],
    "match_users": [],
    "require_admin": true,
    "min_approvals": 2,
    "auto_approve_grace": false,
    "allowed_hours": "08:00-18:00",
    "allowed_days": "Mon-Fri",
    "require_fresh_oidc": "5m",
    "break_glass_bypass": true,
    "notify_channels": ["ops-oncall"]
  }
]
```

### Field reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Unique policy identifier |
| `match_hosts` | string[] | all | Hostname glob patterns (e.g., `prod-*`, `*.staging`) |
| `match_host_groups` | string[] | all | Host registry group labels (e.g., `production`, `staging`) |
| `match_users` | string[] | all | Username glob patterns (empty = all users) |
| `require_admin` | bool | false | Only admin-role users may approve |
| `min_approvals` | int | 1 | Number of distinct approvers needed (multi-approval) |
| `auto_approve_grace` | bool | true | Allow grace-period auto-approval |
| `allowed_hours` | string | — | UTC time window, `HH:MM-HH:MM` (e.g., `08:00-18:00`). Wraps around midnight. |
| `allowed_days` | string | — | Day-of-week restriction (e.g., `Mon-Fri`, `Mon,Wed,Fri`) |
| `require_fresh_oidc` | string | — | Go duration (e.g., `5m`, `1h`). Approver must have logged in via OIDC within this duration. |
| `break_glass_bypass` | bool | false | Allow admin emergency override via `/api/challenges/override` |
| `notify_channels` | string[] | — | Notification channel names to receive events for matching hosts |

---

## Evaluation

Policies are evaluated **in definition order** (first match wins). If no policy matches and no policy named `"default"` exists, a permissive fallback is used (any user can approve, grace auto-approve enabled, no time restrictions).

### Match criteria

A policy matches when ALL of these are true:
- Hostname matches any pattern in `match_hosts` (or `match_hosts` is empty)
- Hostname's host-registry group matches any entry in `match_host_groups` (or empty)
- Username matches any pattern in `match_users` (or empty)

Glob patterns use `filepath.Match` syntax: `*` matches any sequence of non-separator characters.

### When policies are evaluated

- **Challenge creation**: determines `RequiredApprovals`, `RequireAdmin`, `GraceEligible`, `BreakglassBypassAllowed` (snapshotted on the challenge)
- **Auto-approve check**: blocked if `!GraceEligible` or `!TimeWindowOK`
- **Manual approval**: re-evaluates the policy for time-window and step-up auth checks (since these are time-dependent)

---

## Multi-approval

When `min_approvals > 1`, multiple distinct admins must approve before the challenge resolves:

1. First admin approves → partial approval recorded, challenge stays pending
2. Dashboard shows `1/2` progress pill
3. Same admin cannot approve twice (returns 409 Conflict)
4. Second admin approves → threshold met, challenge fully approved
5. Grace session created, PAM client unblocked

The pending bar and modal display approval progress and disable the button for admins who have already approved.

---

## Time windows

`allowed_hours` restricts when approvals can happen:

```json
"allowed_hours": "08:00-18:00"
```

- Times are UTC
- Wrap-around supported: `"22:00-06:00"` means 10 PM to 6 AM
- Enforced at both auto-approve and manual approval time
- Challenges created outside the window stay pending but cannot be approved until the window opens

`allowed_days` restricts which days:

```json
"allowed_days": "Mon-Fri"
```

- Supports ranges (`Mon-Fri`) and comma-separated (`Mon,Wed,Fri`)
- Combined with `allowed_hours` (both must be satisfied)

---

## Step-up authentication

`require_fresh_oidc` forces the approver to have a recent OIDC login:

```json
"require_fresh_oidc": "5m"
```

If the approver's last OIDC authentication was more than 5 minutes ago, the approval is rejected with a "re-authentication required" error. The approver must log in again via OIDC before approving.

Stale browser sessions cannot be used for sensitive approvals.

---

## Break-glass override

When `break_glass_bypass: true`, admins can force-approve a challenge that would otherwise be blocked by policy (outside time window, insufficient approvals, stale OIDC session):

- The override button appears in the dashboard for admin users
- Clicking it requires a confirmation dialog
- The override bypasses ALL policy checks
- A `break_glass_policy_override` audit event is emitted with the admin's identity
- The challenge is marked with `breakglass_override: true` for audit trail

When `break_glass_bypass: false` (default), the override endpoint returns 403.

---

## Notification channel routing

`notify_channels` routes notifications to specific channels when events occur on hosts matching this policy:

```json
"notify_channels": ["ops-oncall", "security-slack"]
```

These channels are merged with the org-level routing rules and per-admin preferences. Channel names must match entries in `notification-channels.json`.

---

## Examples

### Minimal (admin-required for production)

```json
[
  {
    "name": "production",
    "match_hosts": ["prod-*"],
    "require_admin": true
  }
]
```

### Full enterprise policy set

```json
[
  {
    "name": "production",
    "match_host_groups": ["production"],
    "require_admin": true,
    "min_approvals": 2,
    "auto_approve_grace": false,
    "allowed_hours": "08:00-18:00",
    "allowed_days": "Mon-Fri",
    "require_fresh_oidc": "15m",
    "break_glass_bypass": true,
    "notify_channels": ["ops-oncall"]
  },
  {
    "name": "staging",
    "match_host_groups": ["staging"],
    "require_admin": true,
    "min_approvals": 1,
    "auto_approve_grace": true
  },
  {
    "name": "default",
    "auto_approve_grace": true
  }
]
```

In this example:
- Production hosts need 2 admin approvals during business hours, with OIDC re-auth within 15 minutes. Emergency override available.
- Staging hosts need 1 admin approval, grace auto-approve allowed.
- Everything else uses the permissive default (any user can approve their own challenges).
