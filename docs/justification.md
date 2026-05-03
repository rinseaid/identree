# Justification

identree can require every `sudo` elevation to carry a written justification: a brief statement of why access was needed. The reason is recorded in the audit log and shown to the approver before they approve or deny the request.

---

## Configuration

```sh
# Require a justification for every approval (default: false)
IDENTREE_REQUIRE_JUSTIFICATION=true

# Comma-separated preset choices shown to the user and approver.
# Defaults to: Routine maintenance, Incident response, Deployment
IDENTREE_JUSTIFICATION_CHOICES="Routine maintenance,Incident response,Deployment,Other"
```

When `IDENTREE_REQUIRE_JUSTIFICATION=false` (the default), providing a justification is optional. The picker still appears in the approval UI; approvers may fill it in or leave it blank.

When set to `true`, the challenge API rejects requests with no reason (`HTTP 422`), and the approval UI blocks the Approve button until a justification is selected or entered.

---

## User flow: terminal

When justification is required and the user runs `sudo`, the PAM helper prompts for a reason before creating the challenge:

```
$ sudo systemctl restart nginx
  Justification required. Select a reason:
    [1] Routine maintenance
    [2] Incident response
    [3] Deployment
    [4] Other (enter custom reason)
  Choice [4]: 3

  Sudo requires identree approval.
  Approve at: https://identree.example.com/approve/ABCDEF-123456
  Code: ABCDEF-123456 (notification sent)
```

Selecting the last option prompts for free-form text:

```
  Choice [4]: 4
  Enter reason: Rolling back broken migration
```

### Non-interactive use

For scripted or automated contexts (CI pipelines, runbooks), set `SUDO_REASON` to skip the interactive prompt:

```sh
SUDO_REASON="Deploy release v1.4.2" sudo systemctl restart app
```

When `SUDO_REASON` is set, the reason is sent with the initial challenge request regardless of whether justification is required by the server. The reason is always recorded in the audit log and shown to approvers.

The value is passed directly to the challenge and recorded as the justification. If `IDENTREE_REQUIRE_JUSTIFICATION=true` and neither `SUDO_REASON` nor an interactive selection is provided, `sudo` fails with:

```
justification required, set SUDO_REASON=<reason> before running sudo
```

---

## Approver flow: dashboard

When a pending challenge has a reason, it is shown as **read-only** in the Reason column of the approval modal. The approver sees what the user stated and cannot change it.

When a challenge has no reason and justification is not required, the approver may optionally enter one from the same preset list. This approver-side note is stored with the challenge record.

---

## Audit log

Every challenge record stores the justification, whether provided by the user at the terminal or by the approver in the dashboard. It appears in:

- The challenge history table in the admin UI
- Notification webhook payloads (see [notifications.md](notifications.md))
- The structured server log (`reason` field on `CHALLENGE_CREATED` and `CHALLENGE_APPROVED` log lines)
