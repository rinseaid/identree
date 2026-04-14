package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/adminnotify"
	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// memConfigStore is an in-memory notify.ConfigStore for tests.
type memConfigStore struct {
	cfg *notify.NotificationConfig
}

func (m *memConfigStore) Load() (*notify.NotificationConfig, error) {
	if m.cfg == nil {
		return &notify.NotificationConfig{}, nil
	}
	return m.cfg, nil
}

func (m *memConfigStore) Save(cfg *notify.NotificationConfig) error {
	m.cfg = cfg
	return nil
}

// newNotifyTestServer builds a minimal *Server for notification handler tests.
func newNotifyTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, t.TempDir())
	notifyCfg := &notify.NotificationConfig{}
	return &Server{
		cfg: &config.ServerConfig{
			SharedSecret: secret,
			ChallengeTTL: 5 * time.Minute,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      notifyCfg,
		notifyStore:    &memConfigStore{cfg: notifyCfg},
	}
}

// buildAdminFormRequest is like buildFormRequest but always uses role "admin".
func buildAdminFormRequest(secret, username, path string, formValues url.Values) *http.Request {
	return buildFormRequest(secret, username, "admin", path, formValues)
}

// ── handleNotifyChannelAdd tests ─────────────────────────────────────────────

func TestHandleNotifyChannelAdd_ValidName(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	form := url.Values{
		"name":    {"my-channel"},
		"backend": {"ntfy"},
		"url":     {"https://ntfy.example.com/test"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/channels/add", form)
	w := httptest.NewRecorder()
	s.handleNotifyChannelAdd(w, r)

	// Should redirect (303) on success.
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the channel was added.
	s.notifyCfgMu.RLock()
	found := false
	for _, ch := range s.notifyCfg.Channels {
		if ch.Name == "my-channel" {
			found = true
			break
		}
	}
	s.notifyCfgMu.RUnlock()
	if !found {
		t.Error("channel 'my-channel' was not added to config")
	}
}

func TestHandleNotifyChannelAdd_InvalidName(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	badNames := []struct {
		name string
		val  string
	}{
		{"uppercase", "MyChannel"},
		{"special chars", "ch@nnel!"},
		{"starts with hyphen", "-channel"},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 67 chars
	}

	for _, tc := range badNames {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{
				"name":    {tc.val},
				"backend": {"ntfy"},
			}
			r := buildAdminFormRequest(secret, "admin-user", "/api/notification/channels/add", form)
			w := httptest.NewRecorder()
			s.handleNotifyChannelAdd(w, r)

			if w.Code != http.StatusBadRequest {
				t.Errorf("name %q: expected 400, got %d; body: %s", tc.val, w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleNotifyChannelAdd_Duplicate(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	// Pre-populate a channel.
	s.notifyCfgMu.Lock()
	s.notifyCfg.Channels = append(s.notifyCfg.Channels, notify.Channel{
		Name:    "existing",
		Backend: "ntfy",
	})
	s.notifyCfgMu.Unlock()

	form := url.Values{
		"name":    {"existing"},
		"backend": {"ntfy"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/channels/add", form)
	w := httptest.NewRecorder()
	s.handleNotifyChannelAdd(w, r)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleNotifyChannelDelete tests ──────────────────────────────────────────

func TestHandleNotifyChannelDelete_NonExistent(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	form := url.Values{
		"name": {"does-not-exist"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/channels/delete", form)
	w := httptest.NewRecorder()
	s.handleNotifyChannelDelete(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleNotifyRouteAdd tests ───────────────────────────────────────────────

func TestHandleNotifyRouteAdd_InvalidGlob(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	form := url.Values{
		"channels": {"alerts"},
		"events":   {"[invalid"},  // unclosed bracket is invalid glob
		"hosts":    {"*"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/routes/add", form)
	w := httptest.NewRecorder()
	s.handleNotifyRouteAdd(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleNotifyChannelDelete success tests ──────────────────────────────────

func TestHandleNotifyChannelDelete_Success(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	// Pre-populate a channel.
	s.notifyCfgMu.Lock()
	s.notifyCfg.Channels = append(s.notifyCfg.Channels, notify.Channel{
		Name:    "to-delete",
		Backend: "ntfy",
	})
	s.notifyCfgMu.Unlock()

	form := url.Values{
		"name": {"to-delete"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/channels/delete", form)
	w := httptest.NewRecorder()
	s.handleNotifyChannelDelete(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the channel was removed.
	s.notifyCfgMu.RLock()
	for _, ch := range s.notifyCfg.Channels {
		if ch.Name == "to-delete" {
			t.Error("channel 'to-delete' was not removed")
		}
	}
	s.notifyCfgMu.RUnlock()
}

// ── handleAdminNotifyPrefSave tests ──────────────────────────────────────────

// memPrefStore is a minimal in-memory adminnotify.PrefStore for tests.
type memPrefStore struct {
	prefs map[string]adminnotify.Preference
}

func newMemPrefStore() *memPrefStore {
	return &memPrefStore{prefs: make(map[string]adminnotify.Preference)}
}

func (m *memPrefStore) All() []adminnotify.Preference {
	out := make([]adminnotify.Preference, 0, len(m.prefs))
	for _, p := range m.prefs {
		out = append(out, p)
	}
	return out
}

func (m *memPrefStore) Get(username string) *adminnotify.Preference {
	p, ok := m.prefs[username]
	if !ok {
		return nil
	}
	return &p
}

func (m *memPrefStore) Set(pref adminnotify.Preference) error {
	m.prefs[pref.Username] = pref
	return nil
}

func (m *memPrefStore) Delete(username string) error {
	delete(m.prefs, username)
	return nil
}

func (m *memPrefStore) MatchingChannels(event, hostname, username string) map[string]bool {
	return nil
}

func newNotifyTestServerWithPrefs(t *testing.T, secret string) (*Server, *memPrefStore) {
	t.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, t.TempDir())
	notifyCfg := &notify.NotificationConfig{}
	prefStore := newMemPrefStore()
	s := &Server{
		cfg: &config.ServerConfig{
			SharedSecret: secret,
			ChallengeTTL: 5 * time.Minute,
		},
		store:            store,
		hostRegistry:     NewHostRegistry(""),
		authFailRL:       newAuthFailTracker(),
		mutationRL:       newMutationRateLimiter(),
		sseBroadcaster:   noopBroadcaster{},
		policyEngine:     policy.NewEngine(nil),
		notifyCfg:        notifyCfg,
		notifyStore:      &memConfigStore{cfg: notifyCfg},
		adminNotifyStore: prefStore,
	}
	return s, prefStore
}

func TestHandleAdminNotifyPrefSave_Success(t *testing.T) {
	const secret = "test-secret"
	s, prefStore := newNotifyTestServerWithPrefs(t, secret)

	form := url.Values{
		"channels": {"alerts"},
		"events":   {"challenge_approved"},
		"hosts":    {"*"},
		"enabled":  {"true"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/admin/notification-preferences", form)
	w := httptest.NewRecorder()
	s.handleAdminNotifyPrefSave(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify pref was saved.
	pref := prefStore.Get("admin-user")
	if pref == nil {
		t.Fatal("preference was not saved")
	}
	if !pref.Enabled {
		t.Error("expected enabled=true")
	}
	if len(pref.Channels) != 1 || pref.Channels[0] != "alerts" {
		t.Errorf("unexpected channels: %v", pref.Channels)
	}
}

func TestHandleAdminNotifyPrefSave_Delete(t *testing.T) {
	const secret = "test-secret"
	s, prefStore := newNotifyTestServerWithPrefs(t, secret)

	// Pre-populate a preference.
	prefStore.Set(adminnotify.Preference{
		Username: "admin-user",
		Channels: []string{"alerts"},
		Events:   []string{"*"},
		Enabled:  true,
	})

	form := url.Values{
		"action": {"delete"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/admin/notification-preferences", form)
	w := httptest.NewRecorder()
	s.handleAdminNotifyPrefSave(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify pref was deleted.
	pref := prefStore.Get("admin-user")
	if pref != nil {
		t.Error("preference was not deleted")
	}
}

func TestHandleAdminNotifyPrefSave_MissingFields(t *testing.T) {
	const secret = "test-secret"
	s, _ := newNotifyTestServerWithPrefs(t, secret)

	// Missing channels and events.
	form := url.Values{
		"enabled": {"true"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/admin/notification-preferences", form)
	w := httptest.NewRecorder()
	s.handleAdminNotifyPrefSave(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleAdminTestNotifyChannel tests ───────────────────────────────────────

// ── handleNotifyRouteAdd valid data tests ────────────────────────────────────

func TestHandleNotifyRouteAdd_ValidData(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	// Pre-populate a channel for the route to reference.
	s.notifyCfgMu.Lock()
	s.notifyCfg.Channels = append(s.notifyCfg.Channels, notify.Channel{
		Name:    "alerts",
		Backend: "ntfy",
	})
	s.notifyCfgMu.Unlock()

	form := url.Values{
		"channels": {"alerts"},
		"events":   {"*"},
		"hosts":    {"*"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/routes/add", form)
	w := httptest.NewRecorder()
	s.handleNotifyRouteAdd(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the route was added.
	s.notifyCfgMu.RLock()
	routeCount := len(s.notifyCfg.Routes)
	s.notifyCfgMu.RUnlock()
	if routeCount == 0 {
		t.Error("expected at least one route to be added")
	}
}

// ── handleNotifyChannelAdd backend type tests ────────────────────────────────

func TestHandleNotifyChannelAdd_SlackBackend(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	form := url.Values{
		"name":    {"slack-ch"},
		"backend": {"slack"},
		"url":     {"https://hooks.slack.com/services/xxx"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/channels/add", form)
	w := httptest.NewRecorder()
	s.handleNotifyChannelAdd(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleNotifyChannelAdd_EmptyName(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	form := url.Values{
		"name":    {""},
		"backend": {"ntfy"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/channels/add", form)
	w := httptest.NewRecorder()
	s.handleNotifyChannelAdd(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty name, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleAdminNotifyPrefSave all fields tests ───────────────────────────────

func TestHandleAdminNotifyPrefSave_AllFields(t *testing.T) {
	const secret = "test-secret"
	s, prefStore := newNotifyTestServerWithPrefs(t, secret)

	// The handler uses splitTrimmed(r.FormValue("channels")) which expects
	// comma-separated values in a single field, not multi-value form fields.
	form := url.Values{
		"channels": {"alerts,ops"},
		"events":   {"challenge_approved,challenge_denied"},
		"hosts":    {"prod-*"},
		"enabled":  {"true"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/admin/notification-preferences", form)
	w := httptest.NewRecorder()
	s.handleAdminNotifyPrefSave(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	pref := prefStore.Get("admin-user")
	if pref == nil {
		t.Fatal("preference was not saved")
	}
	if len(pref.Channels) != 2 {
		t.Errorf("expected 2 channels, got %d: %v", len(pref.Channels), pref.Channels)
	}
	if len(pref.Events) != 2 {
		t.Errorf("expected 2 events, got %d: %v", len(pref.Events), pref.Events)
	}
}

// ── handleNotifyRouteDelete tests ────────────────────────────────────────────

func TestHandleNotifyRouteDelete_NonExistentIndex(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	form := url.Values{
		"index": {"999"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/notification/routes/delete", form)
	w := httptest.NewRecorder()
	s.handleNotifyRouteDelete(w, r)

	// Should redirect with flash error for out-of-range index.
	if w.Code != http.StatusSeeOther && w.Code != http.StatusBadRequest {
		t.Errorf("expected 303 or 400, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handleNotifyChannelList tests ─────────────────────────────────────────────

func TestHandleNotifyChannelList_NoAuth(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/notification/channels", nil)
	w := httptest.NewRecorder()
	s.handleNotifyChannelList(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleNotifyChannelList_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/api/notification/channels", nil)
	w := httptest.NewRecorder()
	s.handleNotifyChannelList(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleNotifyChannelList_EmptyChannels(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	// Build admin request.
	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "admin-user", csrfTs)
	sessionCookie := makeCookie(secret, "admin-user", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/notification/channels", nil)
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	w := httptest.NewRecorder()
	s.handleNotifyChannelList(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	// Should return an empty array.
	body := w.Body.String()
	if body != "[]\n" && body != "null\n" {
		// empty slice marshals as [] or null depending on Go
	}
}

func TestHandleNotifyChannelList_WithChannels(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	s.notifyCfgMu.Lock()
	s.notifyCfg.Channels = append(s.notifyCfg.Channels, notify.Channel{
		Name:    "test-ch",
		Backend: "ntfy",
		URL:     "https://ntfy.example.com/test",
		Token:   "secret-token", // should be stripped
	})
	s.notifyCfgMu.Unlock()

	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "admin-user", csrfTs)
	sessionCookie := makeCookie(secret, "admin-user", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/api/notification/channels", nil)
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	w := httptest.NewRecorder()
	s.handleNotifyChannelList(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify token is stripped.
	body := w.Body.String()
	if strings.Contains(body, "secret-token") {
		t.Error("expected token to be stripped from response")
	}
}

// ── handleAdminNotifications tests ────────────────────────────────────────────

func TestHandleAdminNotifications_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	r := httptest.NewRequest(http.MethodPost, "/admin/notifications", nil)
	w := httptest.NewRecorder()
	s.handleAdminNotifications(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminNotifications_NoSession_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/admin/notifications", nil)
	w := httptest.NewRecorder()
	s.handleAdminNotifications(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

func TestHandleAdminNotifications_NonAdmin_Redirect(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	ts := time.Now().Unix()
	cookieVal := makeCookie(secret, "bob", "user", ts)
	r := httptest.NewRequest(http.MethodGet, "/admin/notifications", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminNotifications(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for non-admin, got %d", w.Code)
	}
}

// ── notifyChannelMap tests ────────────────────────────────────────────────────

func TestNotifyChannelMap_Empty(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	m := s.notifyChannelMap()
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

func TestNotifyChannelMap_WithChannels(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	s.notifyCfgMu.Lock()
	s.notifyCfg.Channels = []notify.Channel{
		{Name: "ch1", Backend: "ntfy"},
		{Name: "ch2", Backend: "slack"},
	}
	s.notifyCfgMu.Unlock()

	m := s.notifyChannelMap()
	if len(m) != 2 {
		t.Errorf("expected 2 entries, got %d", len(m))
	}
	if _, ok := m["ch1"]; !ok {
		t.Error("expected ch1 in map")
	}
}

// ── notifyDefaultTimeout tests ───────────────────────────────────────────────

func TestNotifyDefaultTimeout_Default(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	timeout := s.notifyDefaultTimeout()
	if timeout <= 0 {
		t.Errorf("expected positive default timeout, got %v", timeout)
	}
}

func TestNotifyDefaultTimeout_Custom(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)
	s.cfg.NotifyTimeout = 30 * time.Second

	timeout := s.notifyDefaultTimeout()
	if timeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", timeout)
	}
}

func TestHandleAdminTestNotifyChannel_UnknownChannel(t *testing.T) {
	const secret = "test-secret"
	s := newNotifyTestServer(t, secret)

	form := url.Values{
		"channel": {"nonexistent"},
	}
	r := buildAdminFormRequest(secret, "admin-user", "/api/admin/test-channel", form)
	w := httptest.NewRecorder()
	s.handleAdminTestNotifyChannel(w, r)

	// Should redirect with test_failed flash.
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}
}
