package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// newAdminTestServer builds a minimal *Server for admin handler tests.
func newAdminTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, filepath.Join(t.TempDir(), "state.json"))
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
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("expected Content-Type text/html, got %q", ct)
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

func TestBuildChecksJSON_WithRedis(t *testing.T) {
	res := healthCheckResult{disk: "ok", redis: "error"}
	got := buildChecksJSON(res)
	if !strings.Contains(got, `"redis":"error"`) {
		t.Errorf("expected redis in JSON, got %q", got)
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
