package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/notify"
)

// safeRedirectDest validates and returns a safe same-origin redirect destination
// from the "from" form field. It decodes percent-encoding before validation to
// prevent %2f%2f bypass of the "//" open-redirect guard. It returns the
// stripped version (all ASCII control chars and space removed) to ensure the
// result is safe for use in HTTP Location headers.
func safeRedirectDest(raw string) string {
	if raw == "" {
		return "/"
	}
	// Decode percent-encoding before validation so %2f%2fevil.com is caught.
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "/"
	}
	if !strings.HasPrefix(decoded, "/") {
		return "/"
	}
	// Strip all ASCII control chars and space (≤0x20) and DEL (0x7F).
	var b strings.Builder
	for _, ch := range decoded {
		if ch > 0x20 && ch != 0x7F {
			b.WriteRune(ch)
		}
	}
	norm := b.String()
	if strings.HasPrefix(norm, "//") || strings.ContainsAny(norm, "?#\\") {
		return "/"
	}
	return norm
}

// handleBulkApprove approves a pending challenge from the dashboard.
// POST /api/challenges/approve
func (s *Server) handleBulkApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	challengeID := r.FormValue("challenge_id")
	if challengeID == "" || len(challengeID) != 32 || !isHex(challengeID) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}

	// Verify the challenge exists and belongs to this user (or user is admin)
	challenge, ok := s.store.Get(challengeID)
	if !ok || challenge.Status != challpkg.StatusPending {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}
	if challenge.Username != username && s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	// Enforce admin-approval policy: only admins may approve policy-protected hosts.
	if s.requiresAdminApproval(challenge.Hostname) && s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "admin_approval_required")
		return
	}

	// Reject approval if the requesting user's account is disabled.
	if s.isUserDisabled(challenge.Username) {
		slog.Warn("APPROVAL_REJECTED account disabled", "user", challenge.Username, "host", challenge.Hostname, "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "account_disabled")
		return
	}

	// Collect and validate the justification from the approval form.
	// When RequireJustification is set, block the approval if no reason is given.
	approvalReason, _ := sanitizeReason(r.FormValue("reason"))
	s.cfgMu.RLock()
	requireJust := s.cfg.RequireJustification
	s.cfgMu.RUnlock()
	if requireJust && approvalReason == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "justification_required")
		return
	}

	// Approve the challenge
	if err := s.store.Approve(challengeID, username); err != nil {
		if errors.Is(err, challpkg.ErrDiskWriteFailed) {
			apiError(w, http.StatusServiceUnavailable, "approval persisted in memory but disk write failed, please retry")
			return
		}
		revokeErrorPage(w, r, http.StatusInternalServerError, "approval_failed", "approval_failed_message")
		return
	}

	challengesApproved.Inc()
	challpkg.ActiveChallenges.Dec()
	challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
	slog.Info("BULK_APPROVED", "user", challenge.Username, "approver", username, "host", challenge.Hostname, "challenge", challengeID[:8], "remote_addr", remoteAddr(r))

	// Log the action
	hostname := challenge.Hostname
	if hostname == "" {
		hostname = "(unknown)"
	}
	// Log the approval reason (from the form); fall back to the request reason
	// when no approval reason was provided (RequireJustification is off).
	logReason := approvalReason
	if logReason == "" {
		logReason = challenge.Reason
	}
	s.store.LogActionWithReason(challenge.Username, challpkg.ActionApproved, hostname, challenge.UserCode, username, logReason)
	s.sseBroadcaster.Broadcast(challenge.Username, "challenge_resolved")
	s.dispatchNotification(notify.WebhookData{
		Event:     "challenge_approved",
		Username:  challenge.Username,
		Hostname:  hostname,
		UserCode:  challenge.UserCode,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Reason:    logReason,
		Actor:     username,
	})

	// Redirect back to the dashboard with flash cookie
	expiry := time.Now().Add(s.store.GraceRemaining(challenge.Username, challenge.Hostname))
	s.setFlashCookie(w, fmt.Sprintf("approved:%s:%s:%d", hostname, challenge.Username, expiry.Unix()))
	http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
}

// handleOneTap processes a one-tap approval link from a notification.
// GET /api/onetap/{token}  — renders a confirmation page showing username/hostname.
// POST /api/onetap/{token} — performs the actual approval (submitted from the confirmation form).
//
// The two-step flow eliminates the risk of link previewers (Slack, Discord, iMessage)
// auto-approving challenges by fetching the URL in the background.
func (s *Server) handleOneTap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.hmacBase() == "" {
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/api/onetap/")
	if token == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}

	// Parse token: challenge_id.expires_unix.hmac_hex
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	challengeID, expiresStr, providedHMAC := parts[0], parts[1], parts[2]

	// Validate challenge ID format
	if len(challengeID) != 32 || !isHex(challengeID) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Check expiry
	expiresUnix, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || time.Now().Unix() > expiresUnix {
		revokeErrorPage(w, r, http.StatusGone, "challenge_expired_or_resolved", "challenge_expired_or_resolved")
		return
	}

	// Get challenge and verify it's still pending (before consuming the one-tap token,
	// so a stale-OIDC redirect doesn't permanently burn the single-use token).
	// Must be loaded before HMAC verification so challenge.Username can be included
	// in the MAC computation.
	challenge, ok := s.store.Get(challengeID)
	if !ok || challenge.Status != challpkg.StatusPending {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	// Verify HMAC — include challenge username and hostname to bind the token to a
	// specific user on a specific host, preventing cross-host token replay.
	// Use the same derived key as computeOneTapToken so the contexts match.
	mac := hmac.New(sha256.New, deriveKey(s.hmacBase(), "onetap"))
	mac.Write([]byte("onetap:" + challengeID + ":" + challenge.Username + ":" + expiresStr + ":" + challenge.Hostname))
	expectedHMAC := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expectedHMAC), []byte(providedHMAC)) != 1 {
		slog.Warn("SECURITY invalid one-tap token", "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusForbidden, "invalid_request", "invalid_csrf")
		return
	}

	// Admin-approval-required hosts cannot be approved via one-tap — there is no
	// session to verify admin role. The user must approve through the dashboard.
	if s.requiresAdminApproval(challenge.Hostname) {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "admin_approval_required")
		return
	}

	// Check OIDC freshness. If the user's last OIDC login is too old (or never
	// recorded), redirect to OIDC login and carry the token in a short-lived
	// cookie so we can resume here after authentication.
	// Use the session user's freshness when an admin (different from the challenge
	// owner) is visiting, so we check whether the admin themselves authenticated
	// recently, not the challenge owner.
	freshnessUser := challenge.Username
	if sessionUser := s.getSessionUser(r); sessionUser != "" && sessionUser != challenge.Username {
		freshnessUser = sessionUser
	}
	lastAuth := s.store.LastOIDCAuth(freshnessUser)
	oidcFresh := !lastAuth.IsZero() && time.Since(lastAuth) < s.cfg.OneTapMaxAge
	if !oidcFresh {
		secure := strings.HasPrefix(s.cfg.ExternalURL, "https://")
		s.cfgMu.RLock()
		ttl := s.cfg.ChallengeTTL
		s.cfgMu.RUnlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_onetap",
			Value:    token,
			Path:     "/",
			MaxAge:   int(ttl.Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   secure,
		})
		loginURL := s.baseURL + "/sessions/login"
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	hostname := challenge.Hostname
	if hostname == "" {
		hostname = "(unknown)"
	}

	if r.Method == http.MethodGet {
		// Render a confirmation page so the user explicitly clicks Approve.
		// This prevents link previewers from auto-approving the challenge.
		username := s.getSessionUser(r)
		csrfTs := strconv.FormatInt(time.Now().Unix(), 10)
		csrfToken := computeCSRFToken(s.hmacBase(), username, csrfTs)

		justChoices, requireJust := s.justificationTemplateData()

		w.Header().Set("Content-Type", "text/html")
		lang := detectLanguage(r)
		t := T(lang)
		theme := getTheme(r)
		themeClass := ""
		if theme == "dark" {
			themeClass = ` class="theme-dark"`
		} else if theme == "light" {
			themeClass = ` class="theme-light"`
		}
		actionURL := s.baseURL + "/api/onetap/" + template.HTMLEscapeString(token)

		// Build request reason display (if any)
		requestReasonHTML := ""
		if challenge.Reason != "" {
			requestReasonHTML = `<p style="margin:12px 0 0;font-size:0.875rem;color:var(--text-2)"><em>` +
				template.HTMLEscapeString(t("reason_optional")) + `:</em> ` +
				template.HTMLEscapeString(challenge.Reason) + `</p>`
		}

		// Build justification picker HTML when RequireJustification is enabled
		// or when we want to give the approver a chance to pick a reason.
		var justPickerHTML string
		if requireJust || challenge.Reason == "" {
			reqAttr := ""
			reqLabel := t("reason_optional")
			if requireJust {
				reqAttr = ` data-required="true"`
				reqLabel = t("reason_optional") // will be overridden client-side
			}
			var optionsHTML strings.Builder
			if !requireJust {
				optionsHTML.WriteString(`<option value="">` + template.HTMLEscapeString(t("reason_optional")) + `</option>`)
			}
			for _, c := range justChoices {
				optionsHTML.WriteString(`<option value="` + template.HTMLEscapeString(c) + `">` + template.HTMLEscapeString(c) + `</option>`)
			}
			optionsHTML.WriteString(`<option value="__custom__">` + template.HTMLEscapeString("Custom...") + `</option>`)
			justPickerHTML = `<div class="just-pick"` + reqAttr + ` style="margin-top:16px;display:flex;flex-direction:column;gap:6px;text-align:left">
  <label style="font-size:0.875rem;font-weight:600;color:var(--text)">` + template.HTMLEscapeString(reqLabel) + `</label>
  <select class="just-sel" style="font-size:0.875rem;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);width:100%">` +
				optionsHTML.String() + `</select>
  <input type="text" class="just-custom" maxlength="500" placeholder="` + template.HTMLEscapeString("Enter reason...") + `" style="display:none;font-size:0.875rem;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);width:100%">
  <input type="hidden" class="just-val" name="reason" value="">
</div>
<script>
(function(){
  var pick=document.querySelector('.just-pick');
  if(!pick)return;
  var sel=pick.querySelector('.just-sel');
  var custom=pick.querySelector('.just-custom');
  var hidden=pick.querySelector('.just-val');
  if(sel){
    sel.addEventListener('change',function(){
      if(sel.value==='__custom__'){if(custom)custom.style.display='';if(hidden)hidden.value='';}
      else{if(custom)custom.style.display='none';if(hidden)hidden.value=sel.value;}
    });
    if(hidden&&sel.value!=='__custom__')hidden.value=sel.value;
  }
  if(custom)custom.addEventListener('input',function(){if(hidden)hidden.value=custom.value.trim();});
  var form=pick.closest('form');
  if(form)form.addEventListener('submit',function(e){
    var val=sel&&sel.value==='__custom__'?(custom?custom.value.trim():''):(sel?sel.value:'');
    if(hidden)hidden.value=val;
    if(pick.dataset.required==='true'&&!val){
      e.preventDefault();
      var err=pick.querySelector('.just-err');
      if(!err){err=document.createElement('span');err.className='just-err';err.style.cssText='color:var(--danger,#c0392b);font-size:0.8125rem';pick.appendChild(err);}
      err.textContent='Please select a justification.';
    }
  });
})();
</script>`
		}

		fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="%s"%s>
<head>
  <title>%s</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>%s
    .icon-pending { background: var(--warn-bg,#fff8e1); border: 2px solid var(--warn-border,#f9a825); color: var(--warn,#f57f17); }
    h2 { color: var(--text); }
    .btn-approve { display:inline-block; margin-top:20px; padding:10px 28px; background:var(--success,#2e7d32); color:#fff; border:none; border-radius:6px; font-size:1rem; font-weight:600; cursor:pointer; width:100%%; }
    .btn-approve:hover { opacity:0.88; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-pending" aria-hidden="true">&#x3f;</div>
    <h2>Approve sudo access for %s on %s?</h2>
    %s
    <form method="POST" action="%s">
      <input type="hidden" name="username" value="%s">
      <input type="hidden" name="csrf_token" value="%s">
      <input type="hidden" name="csrf_ts" value="%s">
      <input type="hidden" name="token" value="%s">
      %s
      <button type="submit" class="btn-approve">%s</button>
    </form>
    <p style="margin-top:16px"><a href="/" style="color:var(--primary);text-decoration:underline">%s</a></p>
  </div>
</body>
</html>`, lang, themeClass, template.HTMLEscapeString(t("terminal_approved")), sharedCSS,
			template.HTMLEscapeString(challenge.Username), template.HTMLEscapeString(hostname),
			requestReasonHTML,
			actionURL,
			template.HTMLEscapeString(username),
			template.HTMLEscapeString(csrfToken),
			template.HTMLEscapeString(csrfTs),
			template.HTMLEscapeString(token),
			justPickerHTML,
			template.HTMLEscapeString(t("approve")),
			template.HTMLEscapeString(t("back_to_dashboard")))
		return
	}

	// POST — verify form auth and perform the approval.
	approver := s.verifyFormAuth(w, r)
	if approver == "" {
		return
	}

	// Ownership check: the one-tap link is a personal approval for the challenge
	// owner. Any authenticated user who obtains the URL must not be able to
	// approve a challenge that belongs to someone else.
	if approver != challenge.Username && s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "admin_approval_required")
		return
	}

	// Reject approval if the requesting user's account is disabled.
	if s.isUserDisabled(challenge.Username) {
		slog.Warn("ONETAP_REJECTED account disabled", "user", challenge.Username, "host", challenge.Hostname, "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "account_disabled")
		return
	}

	// Collect and validate the justification from the one-tap confirmation form.
	onetapReason, _ := sanitizeReason(r.FormValue("reason"))
	s.cfgMu.RLock()
	requireJust := s.cfg.RequireJustification
	s.cfgMu.RUnlock()
	if requireJust && onetapReason == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "justification_required")
		return
	}

	// OIDC is fresh — atomically consume the single-use token and approve the challenge
	// under a single lock to eliminate the TOCTOU window where another goroutine could
	// approve the same challenge between ConsumeOneTap and Approve.
	if err := s.store.ConsumeAndApprove(challengeID, approver); err != nil {
		if errors.Is(err, challpkg.ErrDiskWriteFailed) {
			apiError(w, http.StatusServiceUnavailable, "approval persisted in memory but disk write failed, please retry")
			return
		}
		revokeErrorPage(w, r, http.StatusConflict, "challenge_expired_or_resolved", "challenge_expired_or_resolved")
		return
	}

	challengesApproved.Inc()
	challpkg.ActiveChallenges.Dec()
	challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
	onetapLogReason := onetapReason
	if onetapLogReason == "" {
		onetapLogReason = challenge.Reason
	}
	s.store.LogActionWithReason(challenge.Username, challpkg.ActionApproved, hostname, challenge.UserCode, approver, onetapLogReason)
	s.sseBroadcaster.Broadcast(challenge.Username, "challenge_resolved")
	slog.Info("ONETAP_APPROVED", "user", challenge.Username, "approver", approver, "host", hostname, "challenge", challengeID[:8], "remote_addr", remoteAddr(r))

	// Render a simple success page
	w.Header().Set("Content-Type", "text/html")
	lang := detectLanguage(r)
	t := T(lang)
	theme := getTheme(r)
	themeClass := ""
	if theme == "dark" {
		themeClass = ` class="theme-dark"`
	} else if theme == "light" {
		themeClass = ` class="theme-light"`
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="%s"%s>
<head>
  <title>%s</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>%s
    .icon-success { background: var(--success-bg); border: 2px solid var(--success-border); color: var(--success); }
    h2 { color: var(--success); }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon icon-success" aria-hidden="true">&#x2713;</div>
    <h2>%s</h2>
    <p>%s %s</p>
    <p style="margin-top:16px"><a href="/" style="color:var(--primary);text-decoration:underline">%s</a></p>
  </div>
</body>
</html>`, lang, themeClass, template.HTMLEscapeString(t("terminal_approved")), sharedCSS,
		template.HTMLEscapeString(t("terminal_approved")),
		template.HTMLEscapeString(t("approved_sudo_on")), template.HTMLEscapeString(hostname),
		template.HTMLEscapeString(t("back_to_dashboard")))
}

// handleRevokeSession processes session revocation from the success page.
// POST /api/sessions/revoke
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	actor := s.verifyFormAuth(w, r)
	if actor == "" {
		return
	}
	sessionOwner := actor

	// Admin may revoke another user's session via a "session_username" form field.
	targetUsername := r.FormValue("session_username")
	if targetUsername != "" && s.getSessionRole(r) == "admin" {
		if !validUsername.MatchString(targetUsername) {
			revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_username_format")
			return
		}
		sessionOwner = targetUsername
	}

	displayHostname := r.FormValue("hostname")
	hostname := displayHostname
	if hostname == "(unknown)" {
		hostname = ""
	} else if hostname == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	} else if !validHostname.MatchString(hostname) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	if sessionOwner != actor {
		slog.Warn("CROSS_USER_SESSION_REVOKE",
			"actor", actor,
			"target_user", sessionOwner,
			"host", hostname,
			"remote_addr", remoteAddr(r))
	}

	s.store.RevokeSession(sessionOwner, hostname)
	slog.Info("SESSION_REVOKED", "user", sessionOwner, "host", hostname, "remote_addr", remoteAddr(r))

	// Log the action
	s.store.LogAction(sessionOwner, challpkg.ActionRevoked, displayHostname, "", actor)
	s.sseBroadcaster.Broadcast(sessionOwner, "session_changed")
	s.dispatchNotification(notify.WebhookData{
		Event:     "session_revoked",
		Username:  sessionOwner,
		Hostname:  displayHostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     actor,
	})

	// Redirect back to the referring page with flash cookie
	dest := safeRedirectDest(r.FormValue("from"))
	s.setFlashCookie(w, fmt.Sprintf("revoked:%s:%s", displayHostname, sessionOwner))
	http.Redirect(w, r, s.baseURL+dest, http.StatusSeeOther)
}

// handleBulkApproveAll approves all pending challenges for the authenticated user.
// POST /api/challenges/approve-all
func (s *Server) handleBulkApproveAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	// Approve all pending challenges for this user
	pending := s.store.PendingChallenges(username)
	isAdmin := s.getSessionRole(r) == "admin"
	// Build the disabled-user set once per request (O(1) per challenge instead of O(n)).
	disabledMap := s.buildDisabledMap()
	count := 0
	for _, c := range pending {
		// Skip admin-approval-required challenges if the approver is not an admin.
		if s.requiresAdminApproval(c.Hostname) && !isAdmin {
			continue
		}
		if disabledMap[c.Username] {
			slog.Warn("APPROVAL_REJECTED account disabled", "user", c.Username, "host", c.Hostname, "remote_addr", remoteAddr(r))
			continue
		}
		if err := s.store.Approve(c.ID, username); err == nil {
			challengesApproved.Inc()
			challpkg.ActiveChallenges.Dec()
			challengeDuration.Observe(time.Since(c.CreatedAt).Seconds())
			hostname := c.Hostname
			if hostname == "" {
				hostname = "(unknown)"
			}
			s.store.LogActionWithReason(username, challpkg.ActionApproved, hostname, c.UserCode, username, c.Reason)
			count++
			slog.Info("BULK_APPROVE_ALL", "user", c.Username, "host", c.Hostname, "challenge", c.ID[:8], "remote_addr", remoteAddr(r))
			s.dispatchNotification(notify.WebhookData{
				Event:     "challenge_approved",
				Username:  c.Username,
				Hostname:  hostname,
				UserCode:  c.UserCode,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Reason:    c.Reason,
				Actor:     username,
			})
		}
	}

	s.sseBroadcaster.Broadcast(username, "challenge_resolved")
	if count == 0 {
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	s.setFlashCookie(w, fmt.Sprintf("approved_all:%d", count))
	http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
}

// handleRevokeAll revokes all active sessions for the authenticated user.
// POST /api/sessions/revoke-all
func (s *Server) handleRevokeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	var sessions []challpkg.GraceSession
	targetUser := username
	if s.getSessionRole(r) == "admin" {
		if su := r.FormValue("session_username"); su != "" && validUsername.MatchString(su) {
			targetUser = su
			sessions = s.store.ActiveSessions(targetUser)
		} else {
			// Admin revoke-all without specific user: revoke all active sessions across all users
			sessions = s.store.AllActiveSessions()
			targetUser = ""
		}
	} else {
		sessions = s.store.ActiveSessions(targetUser)
	}

	// Revoke all collected sessions
	notified := make(map[string]bool)
	count := 0
	for _, sess := range sessions {
		sessUser := targetUser
		if sessUser == "" {
			sessUser = sess.Username
		}
		hostname := sess.Hostname
		if hostname == "(unknown)" {
			hostname = ""
		}
		s.store.RevokeSession(sessUser, hostname)
		s.store.LogAction(sessUser, challpkg.ActionRevoked, sess.Hostname, "", username)
		slog.Info("BULK_REVOKE_ALL", "user", sessUser, "host", sess.Hostname, "remote_addr", remoteAddr(r))
		count++
		if !notified[sessUser] {
			s.sseBroadcaster.Broadcast(sessUser, "session_changed")
			notified[sessUser] = true
		}
	}
	dest := safeRedirectDest(r.FormValue("from"))
	if count == 0 {
		http.Redirect(w, r, s.baseURL+dest, http.StatusSeeOther)
		return
	}
	s.dispatchNotification(notify.WebhookData{
		Event:     "sessions_revoked_bulk",
		Username:  targetUser,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     username,
	})
	s.setFlashCookie(w, fmt.Sprintf("revoked_all:%d", count))
	http.Redirect(w, r, s.baseURL+dest, http.StatusSeeOther)
}

// handleExtendSession extends an active grace session to the maximum allowed duration.
// POST /api/sessions/extend
func (s *Server) handleExtendSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor := s.verifyFormAuth(w, r)
	if actor == "" {
		return
	}
	// Admin may extend another user's session via a "session_username" form field.
	username := actor
	if s.getSessionRole(r) == "admin" {
		if su := r.FormValue("session_username"); su != "" && validUsername.MatchString(su) {
			username = su
		}
	}
	hostname := r.FormValue("hostname")
	if hostname == "(unknown)" {
		hostname = ""
	} else if hostname == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	} else if !validHostname.MatchString(hostname) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	if s.isUserDisabled(username) {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "account_disabled")
		return
	}

	// Extend to a specific duration if provided, otherwise to full grace period.
	var remaining time.Duration
	if durStr := r.FormValue("duration"); durStr != "" && durStr != "max" {
		if durSec, err := strconv.Atoi(durStr); err == nil && durSec > 0 {
			// Cap before multiplying to prevent int64 overflow in time.Duration arithmetic.
			if durSec > 604800 { // 7 days max, more than any reasonable grace period
				durSec = 604800
			}
			remaining = s.store.ExtendGraceSessionFor(username, hostname, time.Duration(durSec)*time.Second)
		}
	}
	if remaining == 0 {
		remaining = s.store.ForceExtendGraceSession(username, hostname)
	}
	if remaining == 0 {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	displayHostname := hostname
	if displayHostname == "" {
		displayHostname = "(unknown)"
	}
	s.store.LogAction(username, challpkg.ActionExtended, displayHostname, "", actor)
	slog.Info("EXTENDED", "user", username, "host", displayHostname, "remaining", remaining, "remote_addr", remoteAddr(r))
	s.dispatchNotification(notify.WebhookData{
		Event:     "session_extended",
		Username:  username,
		Hostname:  displayHostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     actor,
	})
	s.sseBroadcaster.Broadcast(username, "session_changed")

	dest := safeRedirectDest(r.FormValue("from"))
	expiry := time.Now().Add(remaining)
	s.setFlashCookie(w, fmt.Sprintf("extended:%s:%s:%d", displayHostname, username, expiry.Unix()))
	http.Redirect(w, r, s.baseURL+dest, http.StatusSeeOther)
}

// handleExtendAll extends all active sessions for the authenticated user to the maximum duration.
// POST /api/sessions/extend-all
func (s *Server) handleExtendAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}
	targetUser := username
	if s.getSessionRole(r) == "admin" {
		if su := r.FormValue("session_username"); su != "" && validUsername.MatchString(su) {
			targetUser = su
		}
	}
	sessions := s.store.ActiveSessions(targetUser)
	count := 0
	for _, sess := range sessions {
		hostname := sess.Hostname
		if hostname == "(unknown)" {
			hostname = ""
		}
		if s.store.ForceExtendGraceSession(targetUser, hostname) > 0 {
			s.store.LogAction(targetUser, challpkg.ActionExtended, sess.Hostname, "", username)
			count++
		}
	}
	s.sseBroadcaster.Broadcast(targetUser, "session_changed")
	slog.Info("BULK_EXTEND_ALL", "user", username, "count", count, "target_user", targetUser, "remote_addr", remoteAddr(r))
	s.dispatchNotification(notify.WebhookData{
		Event:     "session_extended",
		Username:  targetUser,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     username,
	})

	expiry := time.Now().Add(s.cfg.GracePeriod)
	s.setFlashCookie(w, fmt.Sprintf("extended_all:%d:%d", count, expiry.Unix()))
	dest := safeRedirectDest(r.FormValue("from"))
	http.Redirect(w, r, s.baseURL+dest, http.StatusSeeOther)
}

// handleRejectChallenge rejects a pending challenge from the dashboard.
// POST /api/challenges/reject
func (s *Server) handleRejectChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	challengeID := r.FormValue("challenge_id")
	if challengeID == "" || len(challengeID) != 32 || !isHex(challengeID) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}

	// Verify the challenge exists and belongs to this user (or user is admin)
	challenge, ok := s.store.Get(challengeID)
	if !ok || challenge.Status != challpkg.StatusPending {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}
	if challenge.Username != username && s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusNotFound, "challenge_not_found", "challenge_expired_or_resolved")
		return
	}

	// Deny the challenge
	if err := s.store.Deny(challengeID); err != nil {
		revokeErrorPage(w, r, http.StatusInternalServerError, "rejection_failed", "rejection_failed_message")
		return
	}

	challengesDenied.WithLabelValues("user_rejected").Inc()
	challpkg.ActiveChallenges.Dec()
	challengeDuration.Observe(time.Since(challenge.CreatedAt).Seconds())
	hostname := challenge.Hostname
	if hostname == "" {
		hostname = "(unknown)"
	}
	slog.Info("REJECTED", "user", challenge.Username, "host", hostname, "challenge", challengeID[:8], "remote_addr", remoteAddr(r))
	s.store.LogActionWithReason(challenge.Username, challpkg.ActionRejected, hostname, challenge.UserCode, username, challenge.Reason)
	s.sseBroadcaster.Broadcast(challenge.Username, "challenge_resolved")
	s.dispatchNotification(notify.WebhookData{
		Event:     "challenge_rejected",
		Username:  challenge.Username,
		Hostname:  hostname,
		UserCode:  challenge.UserCode,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Reason:    challenge.Reason,
		Actor:     username,
	})

	s.setFlashCookie(w, "rejected:"+hostname)
	http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
}

// handleRejectAll rejects all pending challenges for the authenticated user.
// POST /api/challenges/reject-all
func (s *Server) handleRejectAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	// Reject all pending challenges for this user
	pending := s.store.PendingChallenges(username)
	count := 0
	for _, c := range pending {
		if err := s.store.Deny(c.ID); err == nil {
			challengesDenied.WithLabelValues("user_rejected").Inc()
			challpkg.ActiveChallenges.Dec()
			challengeDuration.Observe(time.Since(c.CreatedAt).Seconds())
			hostname := c.Hostname
			if hostname == "" {
				hostname = "(unknown)"
			}
			s.store.LogActionWithReason(username, challpkg.ActionRejected, hostname, c.UserCode, username, c.Reason)
			count++
			slog.Info("BULK_REJECT_ALL", "user", c.Username, "host", c.Hostname, "challenge", c.ID[:8], "remote_addr", remoteAddr(r))
			s.dispatchNotification(notify.WebhookData{
				Event:     "challenge_rejected",
				Username:  c.Username,
				Hostname:  hostname,
				UserCode:  c.UserCode,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Reason:    c.Reason,
				Actor:     username,
			})
		}
	}

	s.sseBroadcaster.Broadcast(username, "challenge_resolved")
	if count == 0 {
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	s.setFlashCookie(w, fmt.Sprintf("rejected_all:%d", count))
	http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
}

// handleElevate creates a grace session for a host manually.
// POST /api/hosts/elevate
func (s *Server) handleElevate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}

	isAdmin := s.getSessionRole(r) == "admin"

	hostname := r.FormValue("hostname")
	durationStr := r.FormValue("duration")
	if hostname == "" || durationStr == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}
	if !validHostname.MatchString(hostname) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}

	// Admin may elevate any user; non-admins may only elevate themselves.
	targetUser := r.FormValue("target_user")
	if targetUser == "" {
		targetUser = username
	}
	if !validUsername.MatchString(targetUser) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	if !isAdmin && targetUser != username {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}

	// Verify target user is authorized for this host.
	// When the host registry is disabled there is no per-host authorization list, so
	// only admins may elevate — any authenticated user being able to create an arbitrary
	// grace session would be an auth bypass.
	if !s.hostRegistry.IsEnabled() {
		if !isAdmin {
			revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
			return
		}
	} else if !s.hostRegistry.IsUserAuthorized(hostname, targetUser) {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}

	// Parse and clamp duration
	durationSec, err := strconv.Atoi(durationStr)
	if err != nil || durationSec < 1 {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_duration")
		return
	}
	// Cap before multiplying to prevent int64 overflow in time.Duration arithmetic.
	// Max meaningful value is 24h (86400s); anything larger is clamped below.
	if durationSec > 86400 {
		durationSec = 86400
	}
	duration := time.Duration(durationSec) * time.Second
	// Clamp to [1h, GracePeriod]
	if duration < 1*time.Hour {
		duration = 1 * time.Hour
	}
	if s.cfg.GracePeriod > 0 && duration > s.cfg.GracePeriod {
		duration = s.cfg.GracePeriod
	}
	if duration > 24*time.Hour {
		duration = 24 * time.Hour
	}

	if s.isUserDisabled(targetUser) {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "account_disabled")
		return
	}

	s.store.CreateGraceSession(targetUser, hostname, duration)
	s.store.LogAction(targetUser, challpkg.ActionElevated, hostname, "", username)
	slog.Info("ELEVATED", "user", targetUser, "host", hostname, "duration", duration, "by", username, "remote_addr", remoteAddr(r))
	s.sseBroadcaster.Broadcast(targetUser, "session_changed")
	s.dispatchNotification(notify.WebhookData{
		Event:     "grace_elevated",
		Username:  targetUser,
		Hostname:  hostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     username,
	})

	expiry := time.Now().Add(duration)
	s.setFlashCookie(w, fmt.Sprintf("elevated:%s:%s:%d", hostname, targetUser, expiry.Unix()))
	from := safeRedirectDest(r.FormValue("from"))
	if from == "/" {
		from = "/admin/hosts"
	}
	http.Redirect(w, r, s.baseURL+from, http.StatusSeeOther)
}

// handleRotateHost requests breakglass rotation for a single host.
// POST /api/hosts/rotate
func (s *Server) handleRotateHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}
	hostname := r.FormValue("hostname")
	if hostname == "" {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "missing_fields")
		return
	}
	if !validHostname.MatchString(hostname) {
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_format")
		return
	}
	s.store.SetHostRotateBefore(hostname)
	s.store.LogAction(username, challpkg.ActionRotationRequested, hostname, "", username)
	slog.Info("ROTATE_BREAKGLASS", "user", username, "host", hostname, "remote_addr", remoteAddr(r))
	s.sseBroadcaster.Broadcast(username, "host_changed")
	s.dispatchNotification(notify.WebhookData{
		Event:     "breakglass_rotation_requested",
		Username:  username,
		Hostname:  hostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     username,
	})
	s.setFlashCookie(w, "rotated:"+hostname)
	http.Redirect(w, r, s.baseURL+"/admin/hosts", http.StatusSeeOther)
}

// handleRotateAllHosts requests breakglass rotation for all hosts.
// POST /api/hosts/rotate-all
func (s *Server) handleRotateAllHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := s.verifyFormAuth(w, r)
	if username == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		revokeErrorPage(w, r, http.StatusForbidden, "not_authorized", "not_authorized_message")
		return
	}
	// Get all known hosts for this user
	hosts := s.store.KnownHosts(username)
	if s.hostRegistry.IsEnabled() {
		for _, rh := range s.hostRegistry.HostsForUser(username) {
			found := false
			for _, h := range hosts {
				if h == rh {
					found = true
					break
				}
			}
			if !found {
				hosts = append(hosts, rh)
			}
		}
	}
	s.store.SetAllHostsRotateBefore(hosts)
	for _, h := range hosts {
		s.store.LogAction(username, challpkg.ActionRotationRequested, h, "", username)
	}
	slog.Info("ROTATE_ALL_BREAKGLASS", "user", username, "count", len(hosts), "remote_addr", remoteAddr(r))
	s.sseBroadcaster.Broadcast(username, "host_changed")
	s.setFlashCookie(w, fmt.Sprintf("rotated_all:%d", len(hosts)))
	http.Redirect(w, r, s.baseURL+"/admin/hosts", http.StatusSeeOther)
}
