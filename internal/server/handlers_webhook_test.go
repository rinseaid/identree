package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// newWebhookTestServer builds a minimal *Server suitable for webhook handler tests.
func newWebhookTestServer(t *testing.T, webhookSecret string) *Server {
	t.Helper()
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	return &Server{
		cfg: &config.ServerConfig{
			WebhookSecret: webhookSecret,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
		ldapRefreshCh:  make(chan struct{}, 1),
	}
}

// signPayload computes the HMAC-SHA256 signature for a payload using the given secret
// and returns it in the "sha256=<hex>" format expected by verifyWebhookSignature.
func signPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestHandlePocketIDWebhook_MethodNotAllowed(t *testing.T) {
	s := newWebhookTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodGet, "/api/webhook/pocketid", nil)
	w := httptest.NewRecorder()
	s.handlePocketIDWebhook(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandlePocketIDWebhook_WrongContentType(t *testing.T) {
	s := newWebhookTestServer(t, "test-secret")

	r := httptest.NewRequest(http.MethodPost, "/api/webhook/pocketid", bytes.NewReader([]byte("{}")))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.handlePocketIDWebhook(w, r)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandlePocketIDWebhook_NoWebhookSecret(t *testing.T) {
	s := newWebhookTestServer(t, "") // empty secret

	body := []byte(`{"event":"user.updated"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/webhook/pocketid", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handlePocketIDWebhook(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got == "" || !bytes.Contains([]byte(got), []byte("webhook not configured")) {
		t.Errorf("expected body to contain 'webhook not configured', got %q", got)
	}
}

func TestHandlePocketIDWebhook_InvalidSignature(t *testing.T) {
	s := newWebhookTestServer(t, "test-secret")

	body := []byte(`{"event":"user.updated"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/webhook/pocketid", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Webhook-Signature", "sha256=0000000000000000000000000000000000000000000000000000000000000000")
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePocketIDWebhook(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got == "" || !bytes.Contains([]byte(got), []byte("invalid signature")) {
		t.Errorf("expected body to contain 'invalid signature', got %q", got)
	}
}

func TestHandlePocketIDWebhook_Success(t *testing.T) {
	const secret = "test-webhook-secret"
	s := newWebhookTestServer(t, secret)

	body := []byte(`{"event":"user.updated","data":{"id":"abc123"}}`)
	sig := signPayload(secret, body)

	r := httptest.NewRequest(http.MethodPost, "/api/webhook/pocketid", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Webhook-Signature", sig)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePocketIDWebhook(w, r)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the refresh channel received a signal.
	select {
	case <-s.ldapRefreshCh:
		// expected
	default:
		t.Error("expected ldapRefreshCh to receive a signal, but it was empty")
	}
}

func TestHandlePocketIDWebhook_DuplicateRefresh(t *testing.T) {
	const secret = "test-webhook-secret"
	s := newWebhookTestServer(t, secret)

	// Pre-fill the channel to simulate a pending refresh.
	s.ldapRefreshCh <- struct{}{}

	body := []byte(`{"event":"group.updated"}`)
	sig := signPayload(secret, body)

	r := httptest.NewRequest(http.MethodPost, "/api/webhook/pocketid", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Webhook-Signature", sig)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handlePocketIDWebhook(w, r)

	// Should still return 204 even when the channel is full (non-blocking send).
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d; body: %s", w.Code, w.Body.String())
	}

	// Channel should still have exactly one pending signal (the original one).
	select {
	case <-s.ldapRefreshCh:
		// Drain the one signal.
	default:
		t.Error("expected channel to still contain the original signal")
	}

	// Channel should now be empty (the duplicate was dropped).
	select {
	case <-s.ldapRefreshCh:
		t.Error("expected channel to be empty after draining, but got a second signal")
	default:
		// expected
	}
}
