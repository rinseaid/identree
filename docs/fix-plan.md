# Fix Plan — 2026-04-01

Fixes derived from `audit-2026-04-01.md`. Ordered by risk/impact. Each section
lists the owner file(s) and concrete change.

---

## Phase 1 — Security (ship first)

### S1. One-tap GET → two-step (handlers_mutations.go, server.go, templates.go)
Split `handleOneTap` into GET (renders confirmation page) and POST (performs
approval). The confirmation page shows username, hostname, and a single "Approve"
button that POSTs to the same URL. Eliminates link-preview auto-approval.

### S2. `GET /signout` → `POST /signout` (server.go, templates.go)
Remove the GET route. Add a `POST /signout` route. Replace `<a href="/signout">`
in navHTML with a `<form method="POST" action="/signout">` button. Add CSRF token.

### S3. Remove `IDENTREE_DEV_LOGIN` from config UI (handlers_admin.go, templates.go)
Remove the `IDENTREE_DEV_LOGIN` entry from `configToValues()` and from the config
form in the template. The flag remains functional when set via env/TOML directly,
but must not be toggleable from the admin UI.

### S4. Fix `verifyAPIKey` timing leak (handlers_api.go)
Hash the token and each key with HMAC-SHA256 (keyed with a fixed label) before
`subtle.ConstantTimeCompare`. Pattern already established in `verifySharedSecret`.

### S5. Fix `LDAPDefaultHome` format string injection (ldap.go)
Replace `fmt.Sprintf(homePattern, u.Username)` with
`strings.Replace(homePattern, "%s", u.Username, 1)`. Validate the pattern at
config load to contain at most one `%s` and no other format verbs.

### S6. Fix `install.sh` shell injection (handlers_install.go)
Shell-quote `ServerURL` before embedding in the install script template, or
validate it as a URL-only value (scheme + host + path, no shell metacharacters).

### S7. Fix flash cookie delimiter injection (session.go, handlers_mutations.go, handlers_admin.go)
URL-encode (percent-encode) the error string in `config_error:` flash cookies.
URL-decode on read. Consider switching to base64-encoded JSON flash format to
make injection structurally impossible.

### S8. Fix CSRF window to be unidirectional (session.go)
Replace `time.Since(...).Abs() > 5*time.Minute` with `age < 0 || age > 5*time.Minute`
(already the pattern for session cookies). Reject future-dated CSRF timestamps.

### S9. `WebhookSecret == ""` → startup error (server.go)
Elevate the `slog.Warn` to a startup error (or at minimum `slog.Error`) when
`WebhookSecret` is not set. The unauthenticated webhook endpoint is a real-world
DoS vector.

### S10. Add startup warning for missing `SessionStateFile` (cmd.go or server.go)
Log a prominent warning when `SessionStateFile` is unset, explaining that
`revokeTokensBefore` and grace sessions will be lost on restart.

### S11. Remove legacy 3-part session cookie support (session.go)
Delete the `len(parts) == 3` branch in `getSessionUser`. Any existing legacy
cookies will simply fail to parse — users are re-prompted to log in, which is
the correct behavior.

### S12. Fix revocation race in `Approve()` (challenge.go)
In `store.Approve()`, after acquiring the write lock, check whether
`s.revokeTokensBefore[username]` was set after `c.CreatedAt`. If so, return
an error — do not approve.

### S13. Fix `subtle.ConstantTimeCompare` in `verifyWebhookSignature` (util.go)
Replace manual XOR loop with `subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) == 1`.

### S14. Fix `OIDCInsecureSkipVerify` to use `getBool()` (config.go)
Replace `get("IDENTREE_OIDC_INSECURE_SKIP_VERIFY") == "true"` with
`getBool("IDENTREE_OIDC_INSECURE_SKIP_VERIFY")` for consistency with all other booleans.

### S15. Fix `bytes.NewReader` allocation (util.go)
Replace `strings.NewReader(string(body))` with `bytes.NewReader(body)`.

---

## Phase 2 — Correctness

### C1. Define action log string constants (challenge.go)
Create `const` block: `ActionApproved`, `ActionDenied`, `ActionAutoApproved`,
`ActionRevoked`, `ActionExtended`, `ActionElevated`, `ActionRotatedBreakglass`,
`ActionRevealedBreakglass`, `ActionRemovedHost`, `ActionRemovedUser`,
`ActionRotationRequested`, `ActionDeployed`. Replace all raw string literals.

### C2. Log admin actions to action log (handlers_admin.go, handlers_api.go)
Add `s.store.LogAction(adminUser, ActionConfigChanged, "", "", adminUser)` to
`handleAdminConfig`. Same for `handleUpdateGroupClaims`, `handleUpdateUserClaims`,
`handleSudoRuleAdd/Update/Delete`, `handleAdminRestart`, `handleAdminRemoveUser`
(already has it), `handleBreakglassReveal`.

### C3. Send webhook for `revealed_breakglass` (handlers_api.go)
Call `s.sendEventNotification(...)` in `handleBreakglassReveal` after a successful
reveal. Use event type `"revealed_breakglass"`.

### C4. Fix `ExtendGraceSession` misleading log (challenge.go)
When the 75% guard fires, return a distinct error value so the HTTP handler can
log "session already sufficiently extended" rather than "extended".

### C5. Fix `os.Hostname()` silent drop (pamclient.go, breakglass.go)
Log a warning when `os.Hostname()` returns an error. Display the error in the
challenge creation response if hostname is empty.

### C6. Fix LDAP user deletion propagation (ldap.go, server.go)
Pass `removedUsers` exclusion list to `ldapSrv.Refresh()` so deleted users are
filtered from the LDAP directory snapshot.

### C7. Add `AllPendingChallenges()` admin view (handlers_dashboard.go, templates.go)
Surface `s.store.AllPendingChallenges()` as an admin-only pending queue panel.
Existing `buildPendingViews` logic can be reused; filter by admin scope.

### C8. Fix `IDENTREE_HISTORY_PAGE_SIZE` / `IDENTREE_PAGE_SIZE` mismatch (config.go, handlers_admin.go)
Rename `IDENTREE_PAGE_SIZE` to `IDENTREE_HISTORY_PAGE_SIZE` everywhere (config
loader, live-update keys, template). Or rename the UI key. Pick one name.

### C9. Fix `LDAPUIDBase` default documentation (config.go)
Change `getInt("IDENTREE_LDAP_UID_BASE", 0)` to `getInt("IDENTREE_LDAP_UID_BASE", 200000)`
so the config struct default matches the documented default and the UI shows
`200000` instead of `0`.

### C10. Fix `IssuerPublicURL` string-replace (handlers_oidc.go)
Parse the authorization URL with `url.Parse`, swap `Host`/`Scheme` from the
public URL, re-encode. Do not use `strings.Replace` on a raw URL string.

---

## Phase 3 — Performance

### P1. Decouple `saveStateLocked` disk I/O from write lock (challenge.go)
Marshal state under the lock, release the lock, then write to disk. Rename to
`marshalStateLocked` + `writeStateToDisk`. All callers updated.

### P2. Write-back buffer for `LogAction` (challenge.go)
Instead of syncing on every `LogAction`, mark the store dirty and flush on a
2-second timer (or on graceful shutdown). Bounded dirty window; survives crashes
by replaying from the last checkpoint at startup.

### P3. Add `limit` parameter to `ActionHistory` (challenge.go, handlers_dashboard.go)
Avoid allocating the full history just to take `[:5]`.

### P4. Fix `broadcastSSE` lock granularity (sse.go)
Copy channel slices under `sseMu.RLock()`, release, then send. Change `sseMu`
from `sync.Mutex` to `sync.RWMutex`.

### P5. Eliminate redundant `getSessionRole(r)` calls (handlers_admin.go)
Assign `role := s.getSessionRole(r)` once at the top of each handler; reuse.

---

## Phase 4 — Healthz & Config

### H1. Make `/healthz` meaningful (handlers_admin.go)
Check: LDAP server goroutine alive (boolean flag on Server), last LDAP refresh
within 2× `LDAPRefreshInterval`, `SessionStateFile` writable (if configured).
Return `503` with a JSON body listing failing checks when unhealthy.

### H2. Surface LDAP sync failures in admin UI (server.go, handlers_admin.go, templates.go)
Store `lastLDAPError` + timestamp on `Server`. Surface as a warning banner on
`/admin/info` when last refresh failed or is overdue.

### H3. Add `validSudoHostOrUser` length cap (ldap.go or handlers_admin.go)
Add `{1,253}` length constraint to the regex (currently unbounded).

### H4. Fix `IDENTREE_ADMIN_GROUPS` startup warning (server.go or cmd.go)
Log a warning when `AdminGroups` is empty in non-dev mode: admin UI will be
inaccessible.

### H5. Fix Dockerfile `/config` directory (Dockerfile)
Add `RUN mkdir -p /config && chown identree:identree /config` to match default
data paths.

### H6. Remove `parseCIDRs` dead code (config.go)
Delete the function; it is defined but never called.

---

## Phase 5 — UX & Usability

### U1. PocketID-down banner on dashboard (handlers_dashboard.go, templates.go)
Capture PocketID fetch errors; pass `PocketIDUnavailable bool` to template;
render a warning banner when true.

### U2. Admin sessions empty state (templates.go)
Add `{{if not .AllSessions}}..no active sessions..{{end}}` to the admin sessions
section, mirroring the user sessions empty state.

### U3. Single-reject confirm dialog in pending bar (templates.go)
Add `data-confirm="..."` to the single Reject button in `pendingBarHTML` and
ensure the `saction-confirm` JS listener is registered for it.

### U4. Fix "Remove User" label on Remove Host button (templates.go)
Change `{{call $.T "remove_user"}}` to `{{call $.T "remove_host"}}` (add
`remove_host` translation key if needed).

### U5. Fix deploy modal title i18n (templates.go)
Replace hardcoded `"Configure identree on host"` with `{{call .T "deploy_modal_title"}}`.
Add the key to all translation files.

### U6. Fix duplicate `class="tz-select"` attribute (templates.go:1438)
Remove the duplicate attribute.

### U7. Dashboard success banner auto-dismiss (templates.go)
Add the same 5-second auto-dismiss `setTimeout` to the dashboard template that
already exists on the admin and access pages.

### U8. Admin page `<title>` per-tab (templates.go)
Pass `AdminTabTitle` from each admin handler; use it in the `<title>` tag.

### U9. Focus trap for pending modal and deploy modal (templates.go)
Add focus-trap logic (same pattern as remove-modal and reveal-modal) to the
pending-modal and deploy-modal JavaScript initializers.

### U10. Submit-state feedback on approve/reject/revoke forms (templates.go)
Add a shared `preventDoubleSubmit(form)` JS helper that disables the submit
button and shows a "…" indicator on submit. Apply to all mutation forms.

### U11. PAM client human-readable errors (pamclient.go)
Map HTTP 429 → "Too many pending requests. Please wait before trying again."
Map HTTP 403/401 → "Authentication failed — check identree configuration."
Map HTTP 5xx → "Authentication server error — contact your admin."

### U12. Bulk-action zero-count flash (handlers_mutations.go)
When approve-all/reject-all/revoke-all results in count=0, either suppress the
flash or render "No pending requests to approve." instead of "Approved 0".

### U13. OIDC failure "Try again" link (handlers_oidc.go)
Use `revokeErrorPageWithLink` for `token_exchange_failed` pointing to `/sessions/login`.

---

## Phase 6 — Tests

### T1. `internal/challenge/challenge_test.go`
Table-driven tests for: `Create` (rate limits, code collision), `Approve` (normal,
double-approve, revoked-after-create race), `Deny`, `AutoApproveIfWithinGracePeriod`
(boundary, clock skew), `RevokeSession`, `KnownHosts`, `ActiveSessions`, state
persistence round-trip (save + load).

### T2. `internal/server/session_test.go`
Tests for: `getSessionUser` (valid, expired, wrong HMAC, future timestamp, legacy
format rejected after S11), `getSessionRole` (admin, user), `computeCSRFToken`
(valid, expired, future rejected).

### T3. `internal/server/auth_test.go`
Tests for: `verifySharedSecret` (valid, empty secret bypass), `verifyAPIKey`
(valid, wrong, timing), `requiresAdminApproval` (glob patterns, no-match, ALL).

---

## Phase 7 — Cleanup

- Migrate all `log.Printf` in `internal/server/` to `slog` (structured logging).
- Define `LDAPSudoNoAuthenticate` as a typed string or const set.
- Unify the two `sanitizeForTerminal` implementations into a shared `internal/sanitize` package.
- Unify the two `randomHex` implementations similarly.
- Replace `fmt.Sprintf("%d", x)` with `strconv.FormatInt(x, 10)` at 12 call sites.
- Replace `strings.LastIndex`-based dir extraction with `filepath.Dir`.
- Remove `goto` in `pamclient.go:156`; restructure with a boolean flag.
- Unify confirm-dialog patterns: `data-confirm` with delegated listener everywhere.
- Split `handleAdminUsers` (251 lines), `handleAdminHosts` (384 lines),
  `handleAdminConfig` (174 lines), `handleDashboard` (358 lines) into helpers.
