package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/pocketid"
	"github.com/rinseaid/identree/internal/policy"
)

// newAdminTestServer builds a minimal *Server for admin handler tests.
func newAdminTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	notifyCfg := &notify.NotificationConfig{}
	return &Server{
		cfg: &config.ServerConfig{
			SharedSecret:  secret,
			SessionSecret: secret,
			ChallengeTTL:  5 * time.Minute,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      notifyCfg,
		notifyStore:    &memConfigStore{cfg: notifyCfg},
		revokedNonces:  make(map[string]time.Time),
		removedUsers:   make(map[string]time.Time),
	}
}

// buildJSONAdminReq constructs a POST request with a valid admin session cookie
// and CSRF headers for the verifyJSONAdminAuth path.
func buildJSONAdminReq(secret, username, path string) *http.Request {
	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, username, csrfTs)
	sessionCookie := makeCookie(secret, username, "admin", ts)
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	r.RemoteAddr = "10.0.0.1:12345"
	return r
}

// ── handleAdmin redirect tests ───────────────────────────────────────────────

func TestHandleAdmin_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	s.handleAdmin(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/admin/users" {
		t.Errorf("expected redirect to /admin/users, got %q", loc)
	}
}

// ── handleAdminInfo tests ────────────────────────────────────────────────────

func TestHandleAdminInfo_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/admin/info", nil)
	w := httptest.NewRecorder()
	s.handleAdminInfo(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminInfo_NoSession_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/admin/info", nil)
	w := httptest.NewRecorder()
	s.handleAdminInfo(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

func TestHandleAdminInfo_NonAdmin_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "bob", "user", ts)
	r := httptest.NewRequest(http.MethodGet, "/admin/info", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminInfo(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for non-admin, got %d", w.Code)
	}
}

func TestHandleAdminInfo_ValidAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "admin-user", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/admin/info", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminInfo(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected Content-Type text/html; charset=utf-8, got %q", ct)
	}
	// Verify the response body contains version info.
	body := w.Body.String()
	if !strings.Contains(body, "admin-user") {
		t.Error("expected response to contain the admin username")
	}
}

// ── handleAdminConfig tests ──────────────────────────────────────────────────

func TestHandleAdminConfig_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodDelete, "/admin/config", nil)
	w := httptest.NewRecorder()
	s.handleAdminConfig(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminConfig_NoSession_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/admin/config", nil)
	w := httptest.NewRecorder()
	s.handleAdminConfig(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for unauthenticated, got %d", w.Code)
	}
}

func TestHandleAdminConfig_NonAdmin_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "bob", "user", ts)
	r := httptest.NewRequest(http.MethodGet, "/admin/config", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminConfig(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for non-admin, got %d", w.Code)
	}
}

func TestHandleAdminConfig_GET_ValidAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "admin-user", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/admin/config", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminConfig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body length: %d", w.Code, w.Body.Len())
	}
}

// ── handleAdminTestNotification tests ────────────────────────────────────────

func TestHandleAdminTestNotification_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/admin/test-notification", nil)
	w := httptest.NewRecorder()
	s.handleAdminTestNotification(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminTestNotification_NoChannels(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := buildJSONAdminReq(secret, "admin-user", "/api/admin/test-notification")
	w := httptest.NewRecorder()
	s.handleAdminTestNotification(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["ok"] != false {
		t.Error("expected ok=false")
	}
}

func TestHandleAdminTestNotification_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	// Build request as a non-admin user.
	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "bob", csrfTs)
	sessionCookie := makeCookie(secret, "bob", "user", ts)
	r := httptest.NewRequest(http.MethodPost, "/api/admin/test-notification", nil)
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	w := httptest.NewRecorder()
	s.handleAdminTestNotification(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleAdminRestart tests ─────────────────────────────────────────────────

func TestHandleAdminRestart_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/admin/restart", nil)
	w := httptest.NewRecorder()
	s.handleAdminRestart(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminRestart_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	form := url.Values{}
	r := buildFormRequest(secret, "bob", "user", "/api/admin/restart", form)
	w := httptest.NewRecorder()
	s.handleAdminRestart(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleAdminUsers tests ───────────────────────────────────────────────────

func TestHandleAdminUsers_NoSession_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	w := httptest.NewRecorder()
	s.handleAdminUsers(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

func TestHandleAdminUsers_NonAdmin_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "bob", "user", ts)
	r := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminUsers(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for non-admin, got %d", w.Code)
	}
}

// ── handleAdminGroups tests ──────────────────────────────────────────────────

func TestHandleAdminGroups_NoSession_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/admin/groups", nil)
	w := httptest.NewRecorder()
	s.handleAdminGroups(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

// ── handleAdminHosts tests ───────────────────────────────────────────────────

func TestHandleAdminHosts_NoSession_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/admin/hosts", nil)
	w := httptest.NewRecorder()
	s.handleAdminHosts(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

// ── deriveEscrowLink tests ───────────────────────────────────────────────────

func TestDeriveEscrowLink_OnePasswordConnect(t *testing.T) {
	tests := []struct {
		name     string
		webURL   string
		itemID   string
		vaultID  string
		want     string
	}{
		{
			name:    "valid 1password link",
			webURL:  "https://my.1password.com/app#/ACCOUNTUUID",
			itemID:  "item123",
			vaultID: "vault456",
			want:    "https://my.1password.com/app#/ACCOUNTUUID/Vault/ACCOUNTUUID:vault456:item123",
		},
		{
			name:    "missing webURL",
			webURL:  "",
			itemID:  "item123",
			vaultID: "vault456",
			want:    "",
		},
		{
			name:    "missing itemID",
			webURL:  "https://my.1password.com/app#/ACCOUNTUUID",
			itemID:  "",
			vaultID: "vault456",
			want:    "",
		},
		{
			name:    "missing vaultID",
			webURL:  "https://my.1password.com/app#/ACCOUNTUUID",
			itemID:  "item123",
			vaultID: "",
			want:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveEscrowLink("1password-connect", "https://1password.example.com", "", tc.itemID, tc.vaultID, tc.webURL, "host1")
			if got != tc.want {
				t.Errorf("deriveEscrowLink: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveEscrowLink_Vault(t *testing.T) {
	got := deriveEscrowLink("vault", "https://vault.example.com", "secret/identree", "", "", "", "myhost")
	want := "https://vault.example.com/ui/vault/secrets/secret/kv/identree/myhost/details"
	if got != want {
		t.Errorf("deriveEscrowLink(vault): got %q, want %q", got, want)
	}
}

func TestDeriveEscrowLink_Vault_NoPrefix(t *testing.T) {
	got := deriveEscrowLink("vault", "https://vault.example.com", "secret", "", "", "", "myhost")
	want := "https://vault.example.com/ui/vault/secrets/secret/kv/myhost/details"
	if got != want {
		t.Errorf("deriveEscrowLink(vault, no prefix): got %q, want %q", got, want)
	}
}

func TestDeriveEscrowLink_Bitwarden(t *testing.T) {
	got := deriveEscrowLink("bitwarden", "https://api.bitwarden.com", "org123/proj", "item999", "", "", "host1")
	want := "https://vault.bitwarden.com/#/sm/org123/secrets/item999"
	if got != want {
		t.Errorf("deriveEscrowLink(bitwarden): got %q, want %q", got, want)
	}
}

func TestDeriveEscrowLink_Infisical(t *testing.T) {
	got := deriveEscrowLink("infisical", "https://infisical.example.com", "ws123/production", "", "", "", "host1")
	want := "https://infisical.example.com/ws123/secrets/production"
	if got != want {
		t.Errorf("deriveEscrowLink(infisical): got %q, want %q", got, want)
	}
}

func TestDeriveEscrowLink_Infisical_NoEnv(t *testing.T) {
	got := deriveEscrowLink("infisical", "https://infisical.example.com", "ws123", "", "", "", "host1")
	want := "https://infisical.example.com/ws123/secrets"
	if got != want {
		t.Errorf("deriveEscrowLink(infisical, no env): got %q, want %q", got, want)
	}
}

func TestDeriveEscrowLink_UnknownBackend(t *testing.T) {
	got := deriveEscrowLink("custom-cmd", "https://example.com", "", "", "", "", "host1")
	if got != "" {
		t.Errorf("expected empty link for unknown backend, got %q", got)
	}
}

func TestDeriveEscrowLink_RejectsNonHTTP(t *testing.T) {
	got := deriveEscrowLink("vault", "javascript:alert(1)", "secret/identree", "", "", "", "host1")
	if got != "" {
		t.Errorf("expected empty link for javascript: scheme, got %q", got)
	}
}

func TestDeriveEscrowLink_RejectsNonHTTPWebURL(t *testing.T) {
	got := deriveEscrowLink("1password-connect", "https://1password.example.com", "",
		"item123", "vault456", "javascript:alert(1)", "host1")
	if got != "" {
		t.Errorf("expected empty link for javascript: webURL scheme, got %q", got)
	}
}

// ── findRestartSections tests ────────────────────────────────────────────────

func TestFindRestartSections_NoChanges(t *testing.T) {
	submitted := map[string]string{"IDENTREE_CHALLENGE_TTL": "5m"}
	current := map[string]string{"IDENTREE_CHALLENGE_TTL": "5m"}
	sections := findRestartSections(submitted, current)
	if sections != nil {
		t.Errorf("expected nil for no changes, got %v", sections)
	}
}

func TestFindRestartSections_LiveUpdateOnly(t *testing.T) {
	submitted := map[string]string{"IDENTREE_CHALLENGE_TTL": "10m"}
	current := map[string]string{"IDENTREE_CHALLENGE_TTL": "5m"}
	sections := findRestartSections(submitted, current)
	if sections != nil {
		t.Errorf("expected nil for live-update-only change, got %v", sections)
	}
}

// ── configToValues tests ─────────────────────────────────────────────────────

func TestConfigToValues(t *testing.T) {
	cfg := &config.ServerConfig{
		SharedSecret:  "test-secret",
		SessionSecret: "test-secret",
		ChallengeTTL:  5 * time.Minute,
		GracePeriod:  10 * time.Minute,
		ListenAddr:   ":8080",
		ExternalURL:  "https://auth.example.com",
	}
	values := configToValues(cfg)
	if values["IDENTREE_EXTERNAL_URL"] != "https://auth.example.com" {
		t.Errorf("expected ExternalURL in values, got %q", values["IDENTREE_EXTERNAL_URL"])
	}
	if values["IDENTREE_LISTEN_ADDR"] != ":8080" {
		t.Errorf("expected ListenAddr in values, got %q", values["IDENTREE_LISTEN_ADDR"])
	}
}

// ── isEditableUserClaim / isEditableGroupClaim tests ─────────────────────────

func TestIsEditableUserClaim(t *testing.T) {
	if !isEditableUserClaim("loginShell") {
		t.Error("expected loginShell to be editable")
	}
	if !isEditableUserClaim("homeDirectory") {
		t.Error("expected homeDirectory to be editable")
	}
	if isEditableUserClaim("email") {
		t.Error("expected email to not be editable")
	}
}

func TestIsEditableGroupClaim(t *testing.T) {
	if !isEditableGroupClaim("sudoCommands") {
		t.Error("expected sudoCommands to be editable")
	}
	if !isEditableGroupClaim("accessHosts") {
		t.Error("expected accessHosts to be editable")
	}
	if isEditableGroupClaim("groupName") {
		t.Error("expected groupName to not be editable")
	}
}

// ── handleGetUserClaims tests ────────────────────────────────────────────────

func TestHandleGetUserClaims_NoSession(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/admin/user-claims?user_id=test", nil)
	w := httptest.NewRecorder()
	s.handleGetUserClaims(w, r)

	// Should return 401 since there's no session.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleGetUserClaims_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/api/admin/user-claims?user_id=test", nil)
	w := httptest.NewRecorder()
	s.handleGetUserClaims(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── isPrivateIP tests ────────────────────────────────────────────────────────

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fe80::1", true},
		{"2001:db8::1", false},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tc.ip)
			}
			got := isPrivateIP(ip)
			if got != tc.want {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// ── validateConfigValues tests ───────────────────────────────────────────────

func TestValidateConfigValues_ValidDuration(t *testing.T) {
	values := map[string]string{
		"IDENTREE_CHALLENGE_TTL": "10m",
		"IDENTREE_GRACE_PERIOD":  "1h",
		"IDENTREE_EXTERNAL_URL":  "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateConfigValues_InvalidDuration(t *testing.T) {
	values := map[string]string{
		"IDENTREE_CHALLENGE_TTL": "not-a-duration",
		"IDENTREE_EXTERNAL_URL":  "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{})
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestValidateConfigValues_InvalidInteger(t *testing.T) {
	values := map[string]string{
		"IDENTREE_DEFAULT_PAGE_SIZE": "not-a-number",
		"IDENTREE_EXTERNAL_URL":     "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{})
	if err == nil {
		t.Error("expected error for invalid integer")
	}
}

func TestValidateConfigValues_InvalidSudoNoAuth(t *testing.T) {
	values := map[string]string{
		"IDENTREE_LDAP_SUDO_NO_AUTHENTICATE": "invalid",
		"IDENTREE_EXTERNAL_URL":              "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{})
	if err == nil {
		t.Error("expected error for invalid sudo_no_authenticate")
	}
}

func TestValidateConfigValues_ValidSudoNoAuth(t *testing.T) {
	for _, val := range []string{"true", "false", "claims"} {
		values := map[string]string{
			"IDENTREE_LDAP_SUDO_NO_AUTHENTICATE": val,
			"IDENTREE_EXTERNAL_URL":              "https://auth.example.com",
		}
		err := validateConfigValues(values, &config.ServerConfig{})
		if err != nil {
			t.Errorf("expected no error for %q, got %v", val, err)
		}
	}
}

func TestValidateConfigValues_InvalidEscrowBackend(t *testing.T) {
	values := map[string]string{
		"IDENTREE_ESCROW_BACKEND": "nosuchbackend",
		"IDENTREE_EXTERNAL_URL":  "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{})
	if err == nil {
		t.Error("expected error for invalid escrow backend")
	}
}

func TestValidateConfigValues_ValidEscrowBackend(t *testing.T) {
	for _, val := range []string{"vault", "1password-connect", "bitwarden", "infisical"} {
		values := map[string]string{
			"IDENTREE_ESCROW_BACKEND": val,
			"IDENTREE_EXTERNAL_URL":  "https://auth.example.com",
		}
		err := validateConfigValues(values, &config.ServerConfig{})
		if err != nil {
			t.Errorf("expected no error for %q, got %v", val, err)
		}
	}
}

func TestValidateConfigValues_LocalEscrowWithoutKey(t *testing.T) {
	values := map[string]string{
		"IDENTREE_ESCROW_BACKEND": "local",
		"IDENTREE_EXTERNAL_URL":  "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{EscrowEncryptionKey: ""})
	if err == nil {
		t.Error("expected error for local escrow without encryption key")
	}
}

func TestValidateConfigValues_InvalidBreakglassPasswordType(t *testing.T) {
	values := map[string]string{
		"IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE": "badtype",
		"IDENTREE_EXTERNAL_URL":                    "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{})
	if err == nil {
		t.Error("expected error for invalid breakglass password type")
	}
}

func TestValidateConfigValues_ValidBreakglassPasswordType(t *testing.T) {
	for _, val := range []string{"random", "passphrase", "alphanumeric"} {
		values := map[string]string{
			"IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE": val,
			"IDENTREE_EXTERNAL_URL":                    "https://auth.example.com",
		}
		err := validateConfigValues(values, &config.ServerConfig{})
		if err != nil {
			t.Errorf("expected no error for %q, got %v", val, err)
		}
	}
}

func TestValidateConfigValues_InvalidHomePattern(t *testing.T) {
	values := map[string]string{
		"IDENTREE_LDAP_DEFAULT_HOME": "/home/%d/stuff",
		"IDENTREE_EXTERNAL_URL":     "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{})
	if err == nil {
		t.Error("expected error for invalid home pattern verb")
	}
}

func TestValidateConfigValues_ValidHomePattern(t *testing.T) {
	values := map[string]string{
		"IDENTREE_LDAP_DEFAULT_HOME": "/home/%s",
		"IDENTREE_EXTERNAL_URL":     "https://auth.example.com",
	}
	err := validateConfigValues(values, &config.ServerConfig{})
	if err != nil {
		t.Errorf("expected no error for valid home pattern, got %v", err)
	}
}

// ── validateWebhookURL tests ─────────────────────────────────────────────────

func TestValidateWebhookURL_NonHTTPScheme(t *testing.T) {
	err := validateWebhookURL("ftp://example.com/hook")
	if err == nil {
		t.Error("expected error for non-http scheme")
	}
}

func TestValidateWebhookURL_WithUserinfo(t *testing.T) {
	err := validateWebhookURL("https://user:pass@example.com/hook")
	if err == nil {
		t.Error("expected error for URL with userinfo")
	}
}

func TestValidateWebhookURL_EmptyHostname(t *testing.T) {
	err := validateWebhookURL("http:///path")
	if err == nil {
		t.Error("expected error for empty hostname")
	}
}

func TestValidateWebhookURL_LoopbackBlocked(t *testing.T) {
	err := validateWebhookURL("http://127.0.0.1/hook")
	if err == nil {
		t.Error("expected error for loopback address")
	}
}

// ── handleRemoveUser tests ───────────────────────────────────────────────────

func TestHandleRemoveUser_NoSession(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	form := url.Values{"user_id": {"testid"}}
	r := httptest.NewRequest(http.MethodPost, "/api/admin/users/remove", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleRemoveUser(w, r)

	// verifyFormAuth should fail since there's no session cookie.
	if w.Code == http.StatusOK || w.Code == http.StatusSeeOther {
		t.Errorf("expected error status for unauthenticated request, got %d", w.Code)
	}
}

func TestHandleRemoveUser_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	form := url.Values{"user_id": {"testid"}}
	r := buildFormRequest(secret, "bob", "user", "/api/admin/users/remove", form)
	w := httptest.NewRecorder()
	s.handleRemoveUser(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleUpdateGroupClaims tests ────────────────────────────────────────────

func TestHandleUpdateGroupClaims_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	form := url.Values{"group_id": {"testgroup"}}
	r := buildFormRequest(secret, "bob", "user", "/api/admin/groups/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateGroupClaims(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleUpdateUserClaims tests ─────────────────────────────────────────────

func TestHandleUpdateUserClaims_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	form := url.Values{"user_id": {"testuser"}}
	r := buildFormRequest(secret, "bob", "user", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── buildChecksJSON tests ────────────────────────────────────────────────────

func TestBuildChecksJSON_Minimal(t *testing.T) {
	res := healthCheckResult{disk: "ok"}
	got := buildChecksJSON(res)
	if got != `"disk":"ok"` {
		t.Errorf("expected minimal JSON, got %q", got)
	}
}

func TestBuildChecksJSON_WithLDAP(t *testing.T) {
	res := healthCheckResult{disk: "ok", ldapSync: "ok", ldapServer: "ok"}
	got := buildChecksJSON(res)
	if !strings.Contains(got, `"ldap_sync":"ok"`) {
		t.Errorf("expected ldap_sync in JSON, got %q", got)
	}
	if !strings.Contains(got, `"ldap_server":"ok"`) {
		t.Errorf("expected ldap_server in JSON, got %q", got)
	}
}

func TestBuildChecksJSON_WithDatabase(t *testing.T) {
	res := healthCheckResult{disk: "ok", database: "error"}
	got := buildChecksJSON(res)
	if !strings.Contains(got, `"database":"error"`) {
		t.Errorf("expected database in JSON, got %q", got)
	}
}

// ── configToValues expanded tests ────────────────────────────────────────────

func TestConfigToValues_BoolFields(t *testing.T) {
	cfg := &config.ServerConfig{
		LDAPEnabled:           true,
		RequireJustification:  true,
		LDAPProvisionEnabled:  false,
	}
	values := configToValues(cfg)
	if values["IDENTREE_LDAP_ENABLED"] != "true" {
		t.Errorf("expected LDAPEnabled=true, got %q", values["IDENTREE_LDAP_ENABLED"])
	}
	if values["IDENTREE_REQUIRE_JUSTIFICATION"] != "true" {
		t.Errorf("expected RequireJustification=true, got %q", values["IDENTREE_REQUIRE_JUSTIFICATION"])
	}
	if values["IDENTREE_LDAP_PROVISION_ENABLED"] != "false" {
		t.Errorf("expected LDAPProvisionEnabled=false, got %q", values["IDENTREE_LDAP_PROVISION_ENABLED"])
	}
}

func TestConfigToValues_TokenCacheEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	cfg := &config.ServerConfig{ClientTokenCacheEnabled: &trueVal}
	values := configToValues(cfg)
	if values["IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"] != "true" {
		t.Errorf("expected token cache true, got %q", values["IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"])
	}

	cfg2 := &config.ServerConfig{ClientTokenCacheEnabled: &falseVal}
	values2 := configToValues(cfg2)
	if values2["IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"] != "false" {
		t.Errorf("expected token cache false, got %q", values2["IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"])
	}

	cfg3 := &config.ServerConfig{ClientTokenCacheEnabled: nil}
	values3 := configToValues(cfg3)
	if values3["IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"] != "" {
		t.Errorf("expected token cache empty for nil, got %q", values3["IDENTREE_CLIENT_TOKEN_CACHE_ENABLED"])
	}
}

func TestConfigToValues_DurationFields(t *testing.T) {
	cfg := &config.ServerConfig{
		ChallengeTTL:       10 * time.Minute,
		GracePeriod:        1 * time.Hour,
		OneTapMaxAge:       5 * time.Minute,
		ClientPollInterval: 3 * time.Second,
		ClientTimeout:      30 * time.Second,
	}
	values := configToValues(cfg)
	if values["IDENTREE_CHALLENGE_TTL"] == "" {
		t.Error("expected non-empty ChallengeTTL")
	}
	if values["IDENTREE_GRACE_PERIOD"] == "" {
		t.Error("expected non-empty GracePeriod")
	}
	if values["IDENTREE_CLIENT_POLL_INTERVAL"] == "" {
		t.Error("expected non-empty ClientPollInterval")
	}
	if values["IDENTREE_CLIENT_TIMEOUT"] == "" {
		t.Error("expected non-empty ClientTimeout")
	}
}

func TestConfigToValues_ZeroDurationOmitted(t *testing.T) {
	cfg := &config.ServerConfig{
		ClientPollInterval: 0,
		ClientTimeout:      0,
	}
	values := configToValues(cfg)
	if values["IDENTREE_CLIENT_POLL_INTERVAL"] != "" {
		t.Errorf("expected empty for zero ClientPollInterval, got %q", values["IDENTREE_CLIENT_POLL_INTERVAL"])
	}
	if values["IDENTREE_CLIENT_TIMEOUT"] != "" {
		t.Errorf("expected empty for zero ClientTimeout, got %q", values["IDENTREE_CLIENT_TIMEOUT"])
	}
}

// ── boolToString / boolPtrToString tests ─────────────────────────────────────

func TestBoolToString(t *testing.T) {
	if boolToString(true) != "true" {
		t.Error("expected 'true'")
	}
	if boolToString(false) != "false" {
		t.Error("expected 'false'")
	}
}

func TestBoolPtrToString(t *testing.T) {
	trueVal := true
	falseVal := false
	if boolPtrToString(&trueVal) != "true" {
		t.Error("expected 'true' for *true")
	}
	if boolPtrToString(&falseVal) != "false" {
		t.Error("expected 'false' for *false")
	}
	if boolPtrToString(nil) != "" {
		t.Error("expected '' for nil")
	}
}

// ── configLockedKeys tests ───────────────────────────────────────────────────

func TestConfigLockedKeys_ReturnsMap(t *testing.T) {
	locked := configLockedKeys()
	// Should always return a map (possibly empty).
	if locked == nil {
		t.Error("expected non-nil map from configLockedKeys")
	}
}

// ── configSecretStatus tests ─────────────────────────────────────────────────

func TestConfigSecretStatus_AllSet(t *testing.T) {
	cfg := &config.ServerConfig{
		SharedSecret:       "secret",
		ClientSecret:       "secret",
		APIKey:             "key",
		LDAPBindPassword:   "pass",
		EscrowAuthSecret:   "auth",
		EscrowEncryptionKey: "enc",
		WebhookSecret:      "whsec",
	}
	status := configSecretStatus(cfg)
	if !status["IDENTREE_SHARED_SECRET"] {
		t.Error("expected SharedSecret to be set")
	}
	if !status["IDENTREE_OIDC_CLIENT_SECRET"] {
		t.Error("expected ClientSecret to be set")
	}
	if !status["IDENTREE_POCKETID_API_KEY"] {
		t.Error("expected APIKey to be set")
	}
	if !status["IDENTREE_LDAP_BIND_PASSWORD"] {
		t.Error("expected LDAPBindPassword to be set")
	}
	if !status["IDENTREE_ESCROW_AUTH_SECRET"] {
		t.Error("expected EscrowAuthSecret to be set")
	}
	if !status["IDENTREE_ESCROW_ENCRYPTION_KEY"] {
		t.Error("expected EscrowEncryptionKey to be set")
	}
	if !status["IDENTREE_WEBHOOK_SECRET"] {
		t.Error("expected WebhookSecret to be set")
	}
}

func TestConfigSecretStatus_NoneSet(t *testing.T) {
	cfg := &config.ServerConfig{}
	status := configSecretStatus(cfg)
	for key, val := range status {
		if val {
			t.Errorf("expected %s to be false for empty config", key)
		}
	}
}

// ── findRestartSections expanded tests ───────────────────────────────────────

func TestFindRestartSections_RestartRequired(t *testing.T) {
	// IDENTREE_LISTEN_ADDR is not in liveUpdateKeys, so changing it requires restart.
	submitted := map[string]string{
		"IDENTREE_LISTEN_ADDR": ":9090",
		"IDENTREE_EXTERNAL_URL": "https://auth.example.com",
	}
	current := map[string]string{
		"IDENTREE_LISTEN_ADDR": ":8080",
		"IDENTREE_EXTERNAL_URL": "https://auth.example.com",
	}
	sections := findRestartSections(submitted, current)
	if len(sections) == 0 {
		t.Error("expected restart sections for non-live config change")
	}
}

// ── handleAdminConfig POST tests ─────────────────────────────────────────────

func TestHandleAdminConfig_POST_MissingCSRF(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "admin-user", "admin", ts)
	r := httptest.NewRequest(http.MethodPost, "/admin/config", strings.NewReader("username=admin-user"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminConfig(w, r)

	// Should fail because csrf_token and csrf_ts are missing.
	if w.Code == http.StatusOK || w.Code == http.StatusSeeOther {
		// 400 for missing fields is acceptable
	}
	if w.Code != http.StatusBadRequest && w.Code != http.StatusForbidden {
		t.Errorf("expected 400 or 403 for missing CSRF, got %d", w.Code)
	}
}

func TestHandleAdminConfig_POST_InvalidCSRF(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	ts := time.Now().Unix()
	tsStr := fmt.Sprintf("%d", ts)
	cookieVal := makeCookie(secret, "admin-user", "admin", ts)
	form := url.Values{
		"username":   {"admin-user"},
		"csrf_token": {"bad-token"},
		"csrf_ts":    {tsStr},
	}
	r := httptest.NewRequest(http.MethodPost, "/admin/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminConfig(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid CSRF token, got %d", w.Code)
	}
}

func TestHandleAdminConfig_POST_ExpiredCSRF(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	// Use a timestamp 10 minutes in the past (exceeds 5-minute window).
	oldTs := time.Now().Add(-10 * time.Minute).Unix()
	tsStr := fmt.Sprintf("%d", oldTs)
	csrfToken := computeCSRFToken(secret, "admin-user", tsStr)
	cookieVal := makeCookie(secret, "admin-user", "admin", time.Now().Unix())
	form := url.Values{
		"username":   {"admin-user"},
		"csrf_token": {csrfToken},
		"csrf_ts":    {tsStr},
	}
	r := httptest.NewRequest(http.MethodPost, "/admin/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminConfig(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for expired CSRF, got %d", w.Code)
	}
}

func TestHandleAdminConfig_POST_UsernameMismatch(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	ts := time.Now().Unix()
	tsStr := fmt.Sprintf("%d", ts)
	// CSRF token is for "hacker" but session is for "admin-user"
	csrfToken := computeCSRFToken(secret, "hacker", tsStr)
	cookieVal := makeCookie(secret, "admin-user", "admin", ts)
	form := url.Values{
		"username":   {"hacker"},
		"csrf_token": {csrfToken},
		"csrf_ts":    {tsStr},
	}
	r := httptest.NewRequest(http.MethodPost, "/admin/config", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminConfig(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for username mismatch, got %d", w.Code)
	}
}

// ── handleAdminTestNotification with channel tests ───────────────────────────

func TestHandleAdminTestNotification_UnknownChannel(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	// Add a channel so channelMap is non-empty.
	s.notifyCfg.Channels = append(s.notifyCfg.Channels, notify.Channel{
		Name:    "existing",
		Backend: "ntfy",
	})

	r := buildJSONAdminReq(secret, "admin-user", "/api/admin/test-notification?channel=nonexistent")
	w := httptest.NewRecorder()
	s.handleAdminTestNotification(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── validateWebhookURL additional tests ──────────────────────────────────────

func TestValidateWebhookURL_ValidHTTPS(t *testing.T) {
	err := validateWebhookURL("https://hooks.slack.com/services/xxx")
	if err != nil {
		t.Errorf("expected no error for valid HTTPS URL, got %v", err)
	}
}

func TestValidateWebhookURL_ValidHTTP(t *testing.T) {
	// Use a known public hostname that resolves to non-private IPs.
	err := validateWebhookURL("http://example.com/webhook")
	if err != nil {
		t.Errorf("expected no error for valid HTTP URL, got %v", err)
	}
}

// ── isPrivateIP expanded tests ───────────────────────────────────────────────

func TestIsPrivateIP_Multicast(t *testing.T) {
	ip := net.ParseIP("224.0.0.1")
	if !isPrivateIP(ip) {
		t.Error("expected 224.0.0.1 (multicast) to be private")
	}
}

func TestIsPrivateIP_IPv6ULA(t *testing.T) {
	ip := net.ParseIP("fc00::1")
	if !isPrivateIP(ip) {
		t.Error("expected fc00::1 (ULA) to be private")
	}
}

func TestIsPrivateIP_ZeroNetwork(t *testing.T) {
	ip := net.ParseIP("0.0.0.1")
	if !isPrivateIP(ip) {
		t.Error("expected 0.0.0.1 to be private (this-host network)")
	}
}

func TestIsPrivateIP_IPv6Multicast(t *testing.T) {
	ip := net.ParseIP("ff02::1")
	if !isPrivateIP(ip) {
		t.Error("expected ff02::1 (IPv6 multicast) to be private")
	}
}

// ── stripSensitiveEnv tests ──────────────────────────────────────────────────

func TestStripSensitiveEnv(t *testing.T) {
	t.Setenv("IDENTREE_TEST_VAR", "secret-value")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")

	stripSensitiveEnv()

	// After stripping, IDENTREE_* env vars should be unset.
	if os.Getenv("IDENTREE_TEST_VAR") != "" {
		t.Error("expected IDENTREE_TEST_VAR to be unset")
	}
	if os.Getenv("LD_PRELOAD") != "" {
		t.Error("expected LD_PRELOAD to be unset")
	}
}

func TestHostRegistryPath_Default(t *testing.T) {
	t.Setenv("IDENTREE_HOST_REGISTRY_FILE", "")
	got := hostRegistryPath()
	if got != "/data/hosts.json" {
		t.Errorf("expected /data/hosts.json, got %q", got)
	}
}

func TestHostRegistryPath_Custom(t *testing.T) {
	t.Setenv("IDENTREE_HOST_REGISTRY_FILE", "/custom/hosts.json")
	got := hostRegistryPath()
	if got != "/custom/hosts.json" {
		t.Errorf("expected /custom/hosts.json, got %q", got)
	}
}

// ── Claims-mutation test infrastructure ──────────────────────────────────────

// newAdminClaimsTestServer wires newAdminTestServer to a real httptest PocketID
// backend so handlers reach their real work (claim persistence) rather than
// short-circuiting on a nil client.
func newAdminClaimsTestServer(t *testing.T, secret string, handler http.Handler) (*Server, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	s := newAdminTestServer(t, secret)
	s.cfg.APIKey = "test-api-key" // so isBridgeMode() is false
	s.pocketIDClient = pocketid.NewPocketIDClient(ts.URL, "test-api-key")
	return s, ts
}

// ── handleRemoveUser — privilege + side effects ──────────────────────────────

func TestHandleRemoveUser_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	r := httptest.NewRequest(http.MethodGet, "/api/admin/users/remove", nil)
	w := httptest.NewRecorder()
	s.handleRemoveUser(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleRemoveUser_InvalidUsername(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	form := url.Values{"target_user": {"bad user!@#"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/remove", form)
	w := httptest.NewRecorder()
	s.handleRemoveUser(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed username, got %d", w.Code)
	}
}

func TestHandleRemoveUser_SelfRemovalRejected(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	form := url.Values{"target_user": {"admin1"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/remove", form)
	w := httptest.NewRecorder()
	s.handleRemoveUser(w, r)
	// Admins can't remove themselves — guard against accidental self-lockout.
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for self-removal, got %d", w.Code)
	}
}

func TestHandleRemoveUser_HappyPath_ClearsSessionsAndLogsAction(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	// Pre-populate state that must be scrubbed.
	s.store.CreateGraceSession("target1", "host-a", 10*time.Minute)
	s.store.CreateGraceSession("target1", "host-b", 10*time.Minute)
	s.store.LogAction("target1", challpkg.ActionAutoApproved, "host-a", "code1", "target1")

	before := s.store.RevokeTokensBefore("target1")

	form := url.Values{"target_user": {"target1"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/remove", form)
	w := httptest.NewRecorder()
	s.handleRemoveUser(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d; body: %s", w.Code, w.Body.String())
	}

	// All sessions for the user must be gone.
	if sess := s.store.ActiveSessions("target1"); len(sess) != 0 {
		t.Errorf("expected 0 active sessions after removal, got %d", len(sess))
	}

	// A revoke-tokens-before timestamp must now exist (or be advanced). This
	// invalidates any previously-issued token the user had.
	after := s.store.RevokeTokensBefore("target1")
	if !after.After(before) && after.IsZero() {
		t.Errorf("expected RevokeTokensBefore to be set/advanced, before=%v after=%v", before, after)
	}

	// The target is recorded in removedUsers so PocketID re-merge suppresses it
	// for up to 10 minutes.
	s.removedUsersMu.Lock()
	_, recorded := s.removedUsers["target1"]
	s.removedUsersMu.Unlock()
	if !recorded {
		t.Error("expected target1 to be tracked in removedUsers")
	}
}

// ── handleUpdateUserClaims — privilege + validation ──────────────────────────

func TestHandleUpdateUserClaims_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	r := httptest.NewRequest(http.MethodGet, "/api/admin/users/claims", nil)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestHandleUpdateUserClaims_NonAdminCannotElevateSelf is the core privilege-
// escalation regression: a regular user submitting their own user_id with a
// crafted loginShell / ssh_keys payload must be rejected with 403, no matter
// how the form is built. This protects against a user flipping themselves into
// a privileged state by exploiting claim editing.
func TestHandleUpdateUserClaims_NonAdminCannotElevateSelf(t *testing.T) {
	const secret = "test-secret"
	// A pocketID backend that records any PUT so we can assert it never happened.
	var puts int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/custom-claims/user/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts++
		}
		w.WriteHeader(http.StatusOK)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	form := url.Values{
		"user_id":    {"a0000000-0000-0000-0000-000000000001"},
		"loginShell": {"/bin/evil"},
		"ssh_keys":   {"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHgpB example@evil"},
	}
	// Non-admin role; CSRF/session are otherwise valid.
	r := buildFormRequest(secret, "bob", "user", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d; body: %s", w.Code, w.Body.String())
	}
	if puts != 0 {
		t.Errorf("expected 0 PUTs to PocketID, got %d (privilege escalation)", puts)
	}
}

func TestHandleUpdateUserClaims_InvalidUserID(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	s.cfg.APIKey = "test-api-key"
	s.pocketIDClient = pocketid.NewPocketIDClient("http://127.0.0.1:0", "key")
	form := url.Values{"user_id": {"../../etc/passwd"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid user_id, got %d", w.Code)
	}
}

func TestHandleUpdateUserClaims_PocketIDNotConfigured(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	// pocketIDClient is nil.
	form := url.Values{"user_id": {"a0000000-0000-0000-0000-000000000001"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHandleUpdateUserClaims_LoginShellTooLong(t *testing.T) {
	const secret = "test-secret"
	userID := "a0000000-0000-0000-0000-000000000001"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/"+userID, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{"id": userID, "username": "alice"})
		w.Write(b)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	form := url.Values{
		"user_id":    {userID},
		"loginShell": {"/" + strings.Repeat("a", 300)},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for over-long loginShell, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateUserClaims_BadLoginShellChars(t *testing.T) {
	const secret = "test-secret"
	userID := "a0000000-0000-0000-0000-000000000001"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/"+userID, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{"id": userID, "username": "alice"})
		w.Write(b)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	// Shell with shell-metacharacters must be rejected — prevents injection into
	// the LDAP-sourced loginShell attribute.
	form := url.Values{
		"user_id":    {userID},
		"loginShell": {"/bin/sh; rm -rf /"},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for shell with metachars, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateUserClaims_HomeDirectoryTraversal(t *testing.T) {
	const secret = "test-secret"
	userID := "a0000000-0000-0000-0000-000000000001"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/"+userID, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{"id": userID, "username": "alice"})
		w.Write(b)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	form := url.Values{
		"user_id":       {userID},
		"homeDirectory": {"/home/../etc"},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for .. traversal, got %d", w.Code)
	}
}

func TestHandleUpdateUserClaims_InvalidSSHKey(t *testing.T) {
	const secret = "test-secret"
	userID := "a0000000-0000-0000-0000-000000000001"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/"+userID, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{"id": userID, "username": "alice"})
		w.Write(b)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	form := url.Values{
		"user_id":  {userID},
		"ssh_keys": {"not-a-real-ssh-key"},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid SSH key, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateUserClaims_HappyPath_PreservesUnmanagedClaims(t *testing.T) {
	const secret = "test-secret"
	userID := "a0000000-0000-0000-0000-000000000001"
	var putBody []pocketid.Claim
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/"+userID, func(w http.ResponseWriter, r *http.Request) {
		// Existing user has an SSH key AND a non-managed claim; the latter MUST
		// survive the PUT.
		b, _ := json.Marshal(map[string]any{
			"id": userID, "username": "alice",
			"customClaims": []map[string]string{
				{"key": "sshPublicKey", "value": "old-key"},
				{"key": "loginShell", "value": "/bin/sh"},
				{"key": "unmanagedCustom", "value": "preserve-me"},
			},
		})
		w.Write(b)
	})
	mux.HandleFunc("/api/custom-claims/user/"+userID, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&putBody)
		w.WriteHeader(http.StatusOK)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	form := url.Values{
		"user_id":    {userID},
		"loginShell": {"/bin/bash"},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/users/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateUserClaims(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the request body PUT back to PocketID contains the preserved
	// unmanaged claim AND the new loginShell, but NOT the stale SSH key (it's
	// an editable-user-claim class so it gets rewritten from the form).
	foundUnmanaged := false
	foundShell := false
	for _, c := range putBody {
		if c.Key == "unmanagedCustom" && c.Value == "preserve-me" {
			foundUnmanaged = true
		}
		if c.Key == "loginShell" && c.Value == "/bin/bash" {
			foundShell = true
		}
	}
	if !foundUnmanaged {
		t.Errorf("unmanaged claim not preserved in PUT body: %+v", putBody)
	}
	if !foundShell {
		t.Errorf("new loginShell not present in PUT body: %+v", putBody)
	}

	// Audit: an action log entry was recorded for the change. The handler logs
	// under the acting admin's username with the target's username in the
	// hostname column, so we fetch by admin and check both hostname and action.
	hist := s.store.ActionHistory("admin1", 10)
	foundAudit := false
	for _, e := range hist {
		if e.Action == challpkg.ActionClaimsUpdated && e.Hostname == "alice" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Errorf("expected claims_updated audit entry for target 'alice' by admin1, got %+v", hist)
	}
}

// ── handleUpdateGroupClaims — privilege + side effects ───────────────────────

func TestHandleUpdateGroupClaims_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	r := httptest.NewRequest(http.MethodGet, "/api/admin/groups/claims", nil)
	w := httptest.NewRecorder()
	s.handleUpdateGroupClaims(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// Non-admin cannot modify group sudoCommands to grant themselves ALL.
func TestHandleUpdateGroupClaims_NonAdminCannotElevate(t *testing.T) {
	const secret = "test-secret"
	var puts int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/custom-claims/user-group/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts++
		}
		w.WriteHeader(http.StatusOK)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)
	form := url.Values{
		"group_id":     {"b0000000-0000-0000-0000-000000000001"},
		"sudoCommands": {"ALL"},
	}
	r := buildFormRequest(secret, "bob", "user", "/api/admin/groups/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateGroupClaims(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", w.Code)
	}
	if puts != 0 {
		t.Errorf("expected no PUT calls on non-admin rejection, got %d", puts)
	}
}

func TestHandleUpdateGroupClaims_InvalidGroupID(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	s.cfg.APIKey = "test-api-key"
	s.pocketIDClient = pocketid.NewPocketIDClient("http://127.0.0.1:0", "key")
	form := url.Values{"group_id": {"' OR 1=1 --"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/groups/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateGroupClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdateGroupClaims_PocketIDNotConfigured(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	form := url.Values{"group_id": {"b0000000-0000-0000-0000-000000000001"}}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/groups/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateGroupClaims(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHandleUpdateGroupClaims_RejectsOverlongSudoCommands(t *testing.T) {
	const secret = "test-secret"
	groupID := "b0000000-0000-0000-0000-000000000001"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user-groups/"+groupID, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{"id": groupID, "name": "g"})
		w.Write(b)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	form := url.Values{
		"group_id":     {groupID},
		"sudoCommands": {strings.Repeat("a", 5000)},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/groups/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateGroupClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversize sudoCommands, got %d", w.Code)
	}
}

func TestHandleUpdateGroupClaims_RejectsInjectionCharacters(t *testing.T) {
	const secret = "test-secret"
	groupID := "b0000000-0000-0000-0000-000000000001"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user-groups/"+groupID, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{"id": groupID, "name": "g"})
		w.Write(b)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	// A newline in a sudoers claim value would let an attacker inject a new
	// sudoers line. Must be rejected.
	form := url.Values{
		"group_id":     {groupID},
		"sudoCommands": {"/bin/ls\nALL=(ALL) NOPASSWD: ALL"},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/groups/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateGroupClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for newline in claim, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateGroupClaims_HappyPath(t *testing.T) {
	const secret = "test-secret"
	groupID := "b0000000-0000-0000-0000-000000000001"
	var putBody []pocketid.Claim
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user-groups/"+groupID, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{
			"id": groupID, "name": "ops",
			"customClaims": []map[string]string{
				{"key": "unmanagedCustom", "value": "keep-me"},
				{"key": "sudoCommands", "value": "/old"},
			},
		})
		w.Write(b)
	})
	mux.HandleFunc("/api/custom-claims/user-group/"+groupID, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&putBody)
		w.WriteHeader(http.StatusOK)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	form := url.Values{
		"group_id":     {groupID},
		"sudoCommands": {"/usr/bin/ls,/usr/bin/cat"},
	}
	r := buildFormRequest(secret, "admin1", "admin", "/api/admin/groups/claims", form)
	w := httptest.NewRecorder()
	s.handleUpdateGroupClaims(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	foundUnmanaged := false
	foundNewCmds := false
	for _, c := range putBody {
		if c.Key == "unmanagedCustom" && c.Value == "keep-me" {
			foundUnmanaged = true
		}
		if c.Key == "sudoCommands" && c.Value == "/usr/bin/ls,/usr/bin/cat" {
			foundNewCmds = true
		}
	}
	if !foundUnmanaged {
		t.Errorf("unmanaged claim not preserved: %+v", putBody)
	}
	if !foundNewCmds {
		t.Errorf("new sudoCommands not present: %+v", putBody)
	}
}

// ── handleGetUserClaims ──────────────────────────────────────────────────────

func TestHandleGetUserClaims_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/user-claims?user_id=a0000000-0000-0000-0000-000000000001", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "bob", "user", ts)})
	w := httptest.NewRecorder()
	s.handleGetUserClaims(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetUserClaims_RefererRequired(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	s.cfg.ExternalURL = "https://auth.example.com"
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/user-claims?user_id=a0000000-0000-0000-0000-000000000001", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin1", "admin", ts)})
	// Wrong Referer should be forbidden.
	r.Header.Set("Referer", "https://evil.example.com/attack")
	w := httptest.NewRecorder()
	s.handleGetUserClaims(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for foreign referer, got %d", w.Code)
	}
}

func TestHandleGetUserClaims_PocketIDNotConfigured(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	s.cfg.ExternalURL = "https://auth.example.com"
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/user-claims?user_id=a0000000-0000-0000-0000-000000000001", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin1", "admin", ts)})
	r.Header.Set("Referer", "https://auth.example.com/admin/users")
	w := httptest.NewRecorder()
	s.handleGetUserClaims(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHandleGetUserClaims_InvalidUserID(t *testing.T) {
	const secret = "test-secret"
	mux := http.NewServeMux()
	s, _ := newAdminClaimsTestServer(t, secret, mux)
	s.cfg.ExternalURL = "https://auth.example.com"
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/user-claims?user_id=../../etc/passwd", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin1", "admin", ts)})
	r.Header.Set("Referer", "https://auth.example.com/admin/users")
	w := httptest.NewRecorder()
	s.handleGetUserClaims(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleGetUserClaims_HappyPath_SplitsClaimClasses(t *testing.T) {
	const secret = "test-secret"
	userID := "a0000000-0000-0000-0000-000000000001"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/"+userID, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{
			"id": userID, "username": "alice",
			"customClaims": []map[string]string{
				{"key": "sshPublicKey", "value": "ssh-ed25519 AAAA alice@host"},
				{"key": "sshPublicKey1", "value": "ssh-ed25519 BBBB alice@host2"},
				{"key": "loginShell", "value": "/bin/bash"},
				{"key": "organization", "value": "Acme"},
			},
		})
		w.Write(b)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)
	s.cfg.ExternalURL = "https://auth.example.com"

	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/user-claims?user_id="+userID, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin1", "admin", ts)})
	r.Header.Set("Referer", "https://auth.example.com/admin/users")
	w := httptest.NewRecorder()
	s.handleGetUserClaims(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		SSHKeys     []string         `json:"ssh_keys"`
		OtherClaims []pocketid.Claim `json:"other_claims"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.SSHKeys) != 2 {
		t.Errorf("expected 2 SSH keys, got %d: %v", len(resp.SSHKeys), resp.SSHKeys)
	}
	if len(resp.OtherClaims) != 2 {
		t.Errorf("expected 2 other claims, got %d: %v", len(resp.OtherClaims), resp.OtherClaims)
	}
}

// ── handleAdminUsers & handleAdminGroups — admin-role rendering ──────────────

func TestHandleAdminUsers_AdminRenders(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	s.cfg.ExternalURL = "https://auth.example.com"
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin-user", "admin", ts)})
	w := httptest.NewRecorder()
	s.handleAdminUsers(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin GET, got %d; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html; charset=utf-8, got %q", ct)
	}
}

func TestHandleAdminUsers_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	r := httptest.NewRequest(http.MethodPost, "/admin/users", nil)
	w := httptest.NewRecorder()
	s.handleAdminUsers(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminUsers_RendersFlashMessage(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin-user", "admin", ts)})
	r.AddCookie(&http.Cookie{Name: "pam_flash", Value: "removed_user:bob"})
	w := httptest.NewRecorder()
	s.handleAdminUsers(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "bob") {
		t.Error("expected flash message containing 'bob' in rendered page")
	}
}

func TestHandleAdminUsers_NoSession_RedirectsWithExpiredFlash(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	r := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	w := httptest.NewRecorder()
	s.handleAdminUsers(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	// Flash cookie must be set to "expired:" so the login page shows the
	// "session expired" banner instead of silently redirecting.
	var found bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "pam_flash" && strings.HasPrefix(c.Value, "expired") {
			found = true
		}
	}
	if !found {
		t.Error("expected pam_flash=expired cookie on no-session redirect")
	}
}

func TestHandleAdminUsers_NonAdmin_Redirects(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "bob", "user", ts)})
	w := httptest.NewRecorder()
	s.handleAdminUsers(w, r)
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 for non-admin, got %d", w.Code)
	}
}

func TestHandleAdminUsers_WithPocketIDAndSort(t *testing.T) {
	const secret = "test-secret"
	// PocketID backend: return two users with claims (SSH key, loginShell,
	// homeDirectory, other) plus group permissions so that pidUsers merging,
	// claim classification, sudoGroups filtering, and all sort branches are
	// exercised.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		page := map[string]any{
			"data": []map[string]any{
				{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice",
					"customClaims": []map[string]string{
						{"key": "sshPublicKey", "value": "ssh-ed25519 AAAA..."},
						{"key": "loginShell", "value": "/bin/bash"},
						{"key": "homeDirectory", "value": "/home/alice"},
						{"key": "department", "value": "eng"},
					}},
				{"id": "a0000000-0000-0000-0000-000000000002", "username": "bob",
					"customClaims": []map[string]string{}},
			},
			"pagination": map[string]int{"totalPages": 1},
		}
		b, _ := json.Marshal(page)
		w.Write(b)
	})
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		// Per-user detail endpoint hit by AllAdminUsers.
		w.Write([]byte(`{"id":"x","username":"x","customClaims":[]}`))
	})
	mux.HandleFunc("/api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		page := map[string]any{
			"data": []map[string]any{
				{"id": "b0000000-0000-0000-0000-000000000001", "name": "ops"},
			},
			"pagination": map[string]int{"totalPages": 1},
		}
		b, _ := json.Marshal(page)
		w.Write(b)
	})
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		// GetUserPermissions fetches group details + members.
		w.Write([]byte(`{"id":"b0000000-0000-0000-0000-000000000001","name":"ops","customClaims":[{"key":"sudoCommands","value":"ALL"}]}`))
	})
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000001/users", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"id":"a0000000-0000-0000-0000-000000000001","username":"alice"}],"pagination":{"totalPages":1}}`))
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	// Give bob some identree activity so he isn't filtered out for lacking sudo groups.
	s.store.LogAction("bob", challpkg.ActionApproved, "hostname", "", "")

	ts := time.Now().Unix()
	for _, sortQ := range []string{"name", "sessions", "lastactive"} {
		for _, dir := range []string{"asc", "desc"} {
			u := "/admin/users?sort=" + sortQ + "&dir=" + dir
			r := httptest.NewRequest(http.MethodGet, u, nil)
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin1", "admin", ts)})
			r.AddCookie(&http.Cookie{Name: "pam_tz", Value: "America/New_York"})
			w := httptest.NewRecorder()
			s.handleAdminUsers(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("sort=%s dir=%s: expected 200, got %d", sortQ, dir, w.Code)
			}
		}
	}
}

func TestHandleAdminGroups_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	r := httptest.NewRequest(http.MethodPost, "/admin/groups", nil)
	w := httptest.NewRecorder()
	s.handleAdminGroups(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminGroups_NonAdminForbidden(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/admin/groups", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "bob", "user", ts)})
	w := httptest.NewRecorder()
	s.handleAdminGroups(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleAdminGroups_BridgeMode_Redirects(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)
	// APIKey empty -> isBridgeMode true -> redirect to /admin/sudo-rules.
	ts := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/admin/groups", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin1", "admin", ts)})
	w := httptest.NewRecorder()
	s.handleAdminGroups(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 in bridge mode, got %d", w.Code)
	}
	if !strings.HasSuffix(w.Header().Get("Location"), "/admin/sudo-rules") {
		t.Errorf("expected redirect to /admin/sudo-rules, got %q", w.Header().Get("Location"))
	}
}

func TestHandleAdminGroups_AdminRenders(t *testing.T) {
	const secret = "test-secret"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		page := map[string]any{
			"data": []map[string]any{
				{"id": "b0000000-0000-0000-0000-000000000001", "name": "ops"},
				{"id": "b0000000-0000-0000-0000-000000000002", "name": "no-sudo"},
			},
			"pagination": map[string]int{"totalPages": 1},
		}
		b, _ := json.Marshal(page)
		w.Write(b)
	})
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{
			"id": "b0000000-0000-0000-0000-000000000001", "name": "ops",
			"customClaims": []map[string]string{{"key": "sudoCommands", "value": "ALL"}},
		})
		w.Write(b)
	})
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000002", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{
			"id": "b0000000-0000-0000-0000-000000000002", "name": "no-sudo",
			"customClaims": []map[string]string{{"key": "other", "value": "x"}},
		})
		w.Write(b)
	})
	s, _ := newAdminClaimsTestServer(t, secret, mux)

	tsu := time.Now().Unix()
	r := httptest.NewRequest(http.MethodGet, "/admin/groups", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: makeCookie(secret, "admin1", "admin", tsu)})
	w := httptest.NewRecorder()
	s.handleAdminGroups(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ops") {
		t.Error("expected 'ops' group in rendered page")
	}
}

// ── applyLiveConfigUpdates — observable side effects ─────────────────────────

// newLiveConfigTestServer returns a server with ApprovalPoliciesFile set to a
// non-empty path. applyLiveConfigUpdates holds cfgMu.Lock() and calls
// reloadPolicies(path); when the path is empty, reloadPolicies falls back to
// reading cfg under RLock, which deadlocks against the held write lock. Real
// deployments almost always have a path set, so this mirrors production.
func newLiveConfigTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	s := newAdminTestServer(t, secret)
	s.cfg.ApprovalPoliciesFile = "/nonexistent-policies.yaml"
	return s
}

// applyLiveCfg is a test helper that merges the policies-file key into vals so
// the handler doesn't clobber s.cfg.ApprovalPoliciesFile to "" (which would then
// cause reloadPolicies to take RLock under the held write Lock = deadlock).
func applyLiveCfg(s *Server, vals map[string]string, actor string) {
	if _, ok := vals["IDENTREE_APPROVAL_POLICIES_FILE"]; !ok {
		vals["IDENTREE_APPROVAL_POLICIES_FILE"] = "/nonexistent-policies.yaml"
	}
	s.applyLiveConfigUpdates(vals, actor)
}

func TestApplyLiveConfigUpdates_UpdatesDurations(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	s.cfg.ChallengeTTL = 5 * time.Minute
	s.cfg.GracePeriod = 10 * time.Minute
	s.cfg.OneTapMaxAge = 5 * time.Minute

	vals := map[string]string{
		"IDENTREE_CHALLENGE_TTL":   "15m",
		"IDENTREE_GRACE_PERIOD":    "30m",
		"IDENTREE_ONE_TAP_MAX_AGE": "20m",
	}
	applyLiveCfg(s, vals, "admin1")

	if s.cfg.ChallengeTTL != 15*time.Minute {
		t.Errorf("ChallengeTTL: got %v, want 15m", s.cfg.ChallengeTTL)
	}
	if s.cfg.GracePeriod != 30*time.Minute {
		t.Errorf("GracePeriod: got %v, want 30m", s.cfg.GracePeriod)
	}
	if s.cfg.OneTapMaxAge != 20*time.Minute {
		t.Errorf("OneTapMaxAge: got %v, want 20m", s.cfg.OneTapMaxAge)
	}
}

func TestApplyLiveConfigUpdates_IgnoresOutOfBounds(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	s.cfg.ChallengeTTL = 5 * time.Minute
	// 1s is below the 30s minimum; should be ignored.
	applyLiveCfg(s, map[string]string{"IDENTREE_CHALLENGE_TTL": "1s"}, "admin1")
	if s.cfg.ChallengeTTL != 5*time.Minute {
		t.Errorf("expected ChallengeTTL to stay 5m after out-of-bounds update, got %v", s.cfg.ChallengeTTL)
	}
}

func TestApplyLiveConfigUpdates_AdminGroupsLockoutPrevention(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	s.cfg.AdminGroups = []string{"admins", "ops"}
	// Submitting an empty value must NOT wipe AdminGroups, or the last admin
	// would lock themselves out.
	applyLiveCfg(s, map[string]string{"IDENTREE_ADMIN_GROUPS": ""}, "admin1")
	if len(s.cfg.AdminGroups) != 2 {
		t.Errorf("expected AdminGroups preserved against lockout, got %v", s.cfg.AdminGroups)
	}
}

func TestApplyLiveConfigUpdates_AdminGroupsUpdated(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	s.cfg.AdminGroups = []string{"old-admins"}
	applyLiveCfg(s, map[string]string{"IDENTREE_ADMIN_GROUPS": "admins, ops"}, "admin1")
	if len(s.cfg.AdminGroups) != 2 || s.cfg.AdminGroups[0] != "admins" || s.cfg.AdminGroups[1] != "ops" {
		t.Errorf("expected [admins ops], got %v", s.cfg.AdminGroups)
	}
}

func TestApplyLiveConfigUpdates_RequireJustification(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	s.cfg.RequireJustification = false
	applyLiveCfg(s, map[string]string{"IDENTREE_REQUIRE_JUSTIFICATION": "true"}, "admin1")
	if !s.cfg.RequireJustification {
		t.Error("expected RequireJustification=true")
	}
	applyLiveCfg(s, map[string]string{"IDENTREE_REQUIRE_JUSTIFICATION": "false"}, "admin1")
	if s.cfg.RequireJustification {
		t.Error("expected RequireJustification=false")
	}
}

func TestApplyLiveConfigUpdates_JustificationChoices(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	applyLiveCfg(s, map[string]string{
		"IDENTREE_JUSTIFICATION_CHOICES": "incident, maintenance , rotation",
	}, "admin1")
	if len(s.cfg.JustificationChoices) != 3 {
		t.Fatalf("expected 3 justification choices, got %d: %v", len(s.cfg.JustificationChoices), s.cfg.JustificationChoices)
	}
	if s.cfg.JustificationChoices[1] != "maintenance" {
		t.Errorf("expected trimmed value 'maintenance', got %q", s.cfg.JustificationChoices[1])
	}
}

func TestApplyLiveConfigUpdates_EscrowFields(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	applyLiveCfg(s, map[string]string{
		"IDENTREE_ESCROW_BACKEND": "vault",
		"IDENTREE_ESCROW_URL":     "https://vault.example.com",
		"IDENTREE_ESCROW_AUTH_ID": "role-id",
		"IDENTREE_ESCROW_PATH":    "secret/identree",
		"IDENTREE_ESCROW_WEB_URL": "https://vault.example.com/ui",
	}, "admin1")
	if string(s.cfg.EscrowBackend) != "vault" {
		t.Errorf("EscrowBackend: got %q, want vault", s.cfg.EscrowBackend)
	}
	if s.cfg.EscrowURL != "https://vault.example.com" {
		t.Errorf("EscrowURL: got %q", s.cfg.EscrowURL)
	}
	if s.cfg.EscrowAuthID != "role-id" {
		t.Errorf("EscrowAuthID: got %q", s.cfg.EscrowAuthID)
	}
	if s.cfg.EscrowPath != "secret/identree" {
		t.Errorf("EscrowPath: got %q", s.cfg.EscrowPath)
	}
}

func TestApplyLiveConfigUpdates_DefaultPageSizeClamped(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	applyLiveCfg(s, map[string]string{"IDENTREE_DEFAULT_PAGE_SIZE": "10000"}, "admin1")
	if s.cfg.DefaultPageSize != 500 {
		t.Errorf("expected clamp to 500, got %d", s.cfg.DefaultPageSize)
	}
	applyLiveCfg(s, map[string]string{"IDENTREE_DEFAULT_PAGE_SIZE": "0"}, "admin1")
	if s.cfg.DefaultPageSize != 1 {
		t.Errorf("expected clamp to 1, got %d", s.cfg.DefaultPageSize)
	}
}

func TestApplyLiveConfigUpdates_BreakglassToggle(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	applyLiveCfg(s, map[string]string{"IDENTREE_CLIENT_BREAKGLASS_ENABLED": "true"}, "admin1")
	if s.cfg.ClientBreakglassEnabled == nil || !*s.cfg.ClientBreakglassEnabled {
		t.Error("expected ClientBreakglassEnabled=true")
	}
	applyLiveCfg(s, map[string]string{"IDENTREE_CLIENT_BREAKGLASS_ENABLED": ""}, "admin1")
	if s.cfg.ClientBreakglassEnabled != nil {
		t.Error("expected ClientBreakglassEnabled=nil after empty value")
	}
}

func TestApplyLiveConfigUpdates_LDAPDefaultShellRejectsMetacharacters(t *testing.T) {
	const secret = "test-secret"
	s := newLiveConfigTestServer(t, secret)
	s.cfg.LDAPDefaultShell = "/bin/bash"
	// Shell with ';' should be rejected (injection guard) — original value preserved.
	applyLiveCfg(s, map[string]string{"IDENTREE_LDAP_DEFAULT_SHELL": "/bin/sh; echo pwn"}, "admin1")
	if s.cfg.LDAPDefaultShell != "/bin/bash" {
		t.Errorf("expected shell unchanged after injection attempt, got %q", s.cfg.LDAPDefaultShell)
	}
	// Valid absolute path should be accepted.
	applyLiveCfg(s, map[string]string{"IDENTREE_LDAP_DEFAULT_SHELL": "/bin/zsh"}, "admin1")
	if s.cfg.LDAPDefaultShell != "/bin/zsh" {
		t.Errorf("expected shell updated to /bin/zsh, got %q", s.cfg.LDAPDefaultShell)
	}
}
