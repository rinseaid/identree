package pam

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
)

// computeVerifyToken mirrors verifyStatusToken's HMAC format so tests can
// produce valid tokens. Kept in-sync with pamclient.go.
func computeVerifyToken(secret, challengeID, username, status, rotateBefore, revokeTokensBefore string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d:%s%d:%s%d:%s", len(challengeID), challengeID, len(status), status, len(username), username)
	if rotateBefore != "" {
		fmt.Fprintf(mac, "%d:%s", len(rotateBefore), rotateBefore)
	}
	if revokeTokensBefore != "" {
		fmt.Fprintf(mac, "r%d:%s", len(revokeTokensBefore), revokeTokensBefore)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func TestNewPAMClient_RejectsPlainHTTP(t *testing.T) {
	cfg := &config.ClientConfig{ServerURL: "http://insecure.example"}
	if _, err := NewPAMClient(cfg, nil, "host"); err == nil {
		t.Errorf("expected error when ServerURL is http://")
	}

	cfg.InsecureAllowHTTPEscrow = true
	if _, err := NewPAMClient(cfg, nil, "host"); err != nil {
		t.Errorf("InsecureAllowHTTPEscrow should permit http://, got %v", err)
	}
}

func TestNewPAMClient_NormalizesHostname(t *testing.T) {
	cfg := &config.ClientConfig{ServerURL: "https://idp.example"}
	p, err := NewPAMClient(cfg, nil, "HOST.example.COM.")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	if p.hostname != "host.example.com" {
		t.Errorf("hostname = %q; want lowercase, trailing-dot stripped", p.hostname)
	}
}

func TestVerifyStatusToken(t *testing.T) {
	p := &PAMClient{cfg: &config.ClientConfig{SharedSecret: "s3cret"}}

	good := computeVerifyToken("s3cret", "chall1", "alice", "approved", "", "")
	if !p.verifyStatusToken("chall1", "alice", "approved", good, "", "") {
		t.Errorf("good token should verify")
	}

	// Empty token always rejected.
	if p.verifyStatusToken("chall1", "alice", "approved", "", "", "") {
		t.Errorf("empty token must be rejected")
	}

	// Wrong status — forged.
	if p.verifyStatusToken("chall1", "alice", "denied", good, "", "") {
		t.Errorf("status mismatch must fail")
	}

	// Wrong username — cross-user replay.
	if p.verifyStatusToken("chall1", "bob", "approved", good, "", "") {
		t.Errorf("username mismatch must fail")
	}

	// Wrong challenge ID — cross-challenge replay.
	if p.verifyStatusToken("chall2", "alice", "approved", good, "", "") {
		t.Errorf("challengeID mismatch must fail")
	}

	// Garbage token — wrong length.
	if p.verifyStatusToken("chall1", "alice", "approved", "deadbeef", "", "") {
		t.Errorf("short token must fail")
	}

	// Token bound to rotateBefore must include it on verify.
	withRotate := computeVerifyToken("s3cret", "chall1", "alice", "approved", "2026-01-01T00:00:00Z", "")
	if !p.verifyStatusToken("chall1", "alice", "approved", withRotate, "2026-01-01T00:00:00Z", "") {
		t.Errorf("rotateBefore token should verify when rotateBefore matches")
	}
	if p.verifyStatusToken("chall1", "alice", "approved", withRotate, "", "") {
		t.Errorf("rotateBefore token must fail without rotateBefore")
	}

	// revokeTokensBefore uses 'r'-prefixed format.
	withRevoke := computeVerifyToken("s3cret", "chall1", "alice", "approved", "", "2026-03-01T00:00:00Z")
	if !p.verifyStatusToken("chall1", "alice", "approved", withRevoke, "", "2026-03-01T00:00:00Z") {
		t.Errorf("revokeTokensBefore token should verify")
	}
	if p.verifyStatusToken("chall1", "alice", "approved", withRevoke, "2026-03-01T00:00:00Z", "") {
		t.Errorf("revoke token must not verify when passed as rotate")
	}
}

func TestCreateChallenge_SendsSecretAndHostname(t *testing.T) {
	var gotSecret, gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSecret = r.Header.Get("X-Shared-Secret")
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"challenge_id":     strings.Repeat("a", 32),
			"user_code":        "ABCD-1234",
			"verification_url": "https://example/approve/ABCD-1234",
			"expires_in":       120,
		})
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:    srv.URL,
		SharedSecret: "hunter2",
	}
	p, err := NewPAMClient(cfg, nil, "web01")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srv.Client() // trust the httptest TLS cert

	cr, err := p.createChallenge("alice", "installing patches")
	if err != nil {
		t.Fatalf("createChallenge: %v", err)
	}
	if cr.ChallengeID != strings.Repeat("a", 32) {
		t.Errorf("ChallengeID = %q", cr.ChallengeID)
	}
	if gotSecret != "hunter2" {
		t.Errorf("X-Shared-Secret = %q; want hunter2", gotSecret)
	}
	if !strings.Contains(gotBody, `"hostname":"web01"`) {
		t.Errorf("body missing hostname: %s", gotBody)
	}
	if !strings.Contains(gotBody, `"reason":"installing patches"`) {
		t.Errorf("body missing reason: %s", gotBody)
	}
}

func TestCreateChallenge_JustificationRequired(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":                  "justification_required",
			"justification_choices": []string{"incident", "maintenance", "other"},
		})
	}))
	defer srv.Close()

	p, err := NewPAMClient(&config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x"}, nil, "h")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()

	_, err = p.createChallenge("alice", "")
	if err == nil {
		t.Fatalf("expected justification_required error")
	}
	jre, ok := err.(*justificationRequiredError)
	if !ok {
		t.Fatalf("expected *justificationRequiredError, got %T (%v)", err, err)
	}
	if len(jre.Choices) != 3 || jre.Choices[0] != "incident" {
		t.Errorf("unexpected choices: %v", jre.Choices)
	}
}

func TestCreateChallenge_RejectsBadChallengeID(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"challenge_id":     "not-hex", // violates the 32-hex regex
			"user_code":        "ABCD-1234",
			"verification_url": "https://example/approve",
			"expires_in":       120,
		})
	}))
	defer srv.Close()

	p, err := NewPAMClient(&config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x"}, nil, "h")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()

	_, err = p.createChallenge("alice", "")
	if err == nil || !strings.Contains(err.Error(), "invalid challenge ID") {
		t.Errorf("expected invalid challenge ID error, got %v", err)
	}
}

func TestCreateChallenge_ServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	p, err := NewPAMClient(&config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x"}, nil, "h")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()

	_, err = p.createChallenge("alice", "")
	if err == nil {
		t.Fatalf("expected error")
	}
	var httpErr *serverHTTPError
	// strings.Contains falls back if errors.As doesn't apply (serverHTTPError's Error method).
	if !strings.Contains(err.Error(), "forbidden") && err.(*serverHTTPError) == httpErr {
		t.Errorf("unexpected error %v", err)
	}
}

func TestPollChallenge_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "hostname=web01") {
			t.Errorf("hostname not in poll query: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "pending",
			"expires_in": 90,
		})
	}))
	defer srv.Close()

	p, err := NewPAMClient(&config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x"}, nil, "web01")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()

	pr, err := p.pollChallenge(strings.Repeat("b", 32))
	if err != nil {
		t.Fatalf("pollChallenge: %v", err)
	}
	if pr.Status != "pending" || pr.ExpiresIn != 90 {
		t.Errorf("unexpected poll response: %+v", pr)
	}
}

func TestPollChallenge_ServerExpired(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p, err := NewPAMClient(&config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x"}, nil, "h")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()

	pr, err := p.pollChallenge(strings.Repeat("c", 32))
	if err != nil {
		t.Fatalf("pollChallenge: %v", err)
	}
	if !pr.serverExpired {
		t.Errorf("expected serverExpired flag on 404")
	}
}

func TestApplyClientConfig_ClampsTimeoutAndPollInterval(t *testing.T) {
	trueVal, falseVal := true, false
	cfg := &config.ClientConfig{PollInterval: 0, Timeout: 0}
	p := &PAMClient{cfg: cfg, tokenCache: &TokenCache{}}

	applyClientConfig(p, &challengeResponse{
		ClientConfig: &clientConfigResponse{
			PollInterval:           "100ms", // below 1s floor → clamped
			Timeout:                "2m",
			BreakglassEnabled:      &trueVal,
			BreakglassPasswordType: "words",
			BreakglassRotationDays: 7,
			TokenCacheEnabled:      &falseVal,
		},
	})
	if cfg.PollInterval != time.Second {
		t.Errorf("PollInterval = %v; want 1s floor", cfg.PollInterval)
	}
	if cfg.Timeout != 2*time.Minute {
		t.Errorf("Timeout = %v; want 2m", cfg.Timeout)
	}
	if !cfg.BreakglassEnabled {
		t.Errorf("BreakglassEnabled not applied")
	}
	if cfg.BreakglassPasswordType != "words" || cfg.BreakglassRotationDays != 7 {
		t.Errorf("breakglass fields not applied: %+v", cfg)
	}
	if cfg.TokenCacheEnabled {
		t.Errorf("TokenCacheEnabled should be false")
	}
	if p.tokenCache != nil {
		t.Errorf("tokenCache should be cleared when server disables it")
	}

	// Timeout above max gets clamped to 10 minutes.
	cfg2 := &config.ClientConfig{}
	p2 := &PAMClient{cfg: cfg2}
	applyClientConfig(p2, &challengeResponse{ClientConfig: &clientConfigResponse{Timeout: "99h"}})
	if cfg2.Timeout != 10*time.Minute {
		t.Errorf("Timeout = %v; want clamp to 10m", cfg2.Timeout)
	}

	// Timeout below 5s floor gets raised to 5s.
	cfg3 := &config.ClientConfig{}
	p3 := &PAMClient{cfg: cfg3}
	applyClientConfig(p3, &challengeResponse{ClientConfig: &clientConfigResponse{Timeout: "2s"}})
	if cfg3.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v; want raise to 5s", cfg3.Timeout)
	}
}

func TestHandleCacheInvalidation_DeletesWhenRevoked(t *testing.T) {
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "h"}
	// Seed a cache file with an old mtime.
	jwt := makeJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "preferred_username": "alice"})
	if err := tc.Write("alice", jwt); err != nil {
		t.Fatalf("Write: %v", err)
	}

	p := &PAMClient{tokenCache: tc}

	// Revoke timestamp in the future of the file mtime → cache must be deleted.
	futureRevoke := time.Now().Add(time.Hour).Format(time.RFC3339)
	handleCacheInvalidation(p, &challengeResponse{RevokeTokensBefore: futureRevoke}, "alice")
	if _, err := tc.ModTime("alice"); err == nil {
		t.Errorf("cache should be deleted after future-dated revoke")
	}

	// Re-seed and test that a revoke in the past does NOT delete.
	if err := tc.Write("alice", jwt); err != nil {
		t.Fatal(err)
	}
	pastRevoke := time.Now().Add(-time.Hour).Format(time.RFC3339)
	handleCacheInvalidation(p, &challengeResponse{RevokeTokensBefore: pastRevoke}, "alice")
	if _, err := tc.ModTime("alice"); err != nil {
		t.Errorf("cache should be kept when revoke is older than mtime: %v", err)
	}

	// Empty RevokeTokensBefore → no-op.
	handleCacheInvalidation(p, &challengeResponse{RevokeTokensBefore: ""}, "alice")
	if _, err := tc.ModTime("alice"); err != nil {
		t.Errorf("cache should be untouched for empty revoke")
	}

	// Nil tokenCache → no panic.
	handleCacheInvalidation(&PAMClient{}, &challengeResponse{RevokeTokensBefore: futureRevoke}, "alice")
}
