package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

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
