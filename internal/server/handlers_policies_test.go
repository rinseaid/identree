package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
)

// newPolicyTestServer builds a minimal *Server for policy handler tests.
// The ApprovalPoliciesFile is set to a temp directory so SavePolicies works.
func newPolicyTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := challpkg.NewChallengeStore(5*time.Minute, 10*time.Minute, t.TempDir())
	policyFile := filepath.Join(t.TempDir(), "policies.json")
	return &Server{
		cfg: &config.ServerConfig{
			SharedSecret:         secret,
			SessionSecret:        secret,
			ChallengeTTL:         5 * time.Minute,
			ApprovalPoliciesFile: policyFile,
		},
		store:          store,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
	}
}

// ── handlePolicyAdd tests ────────────────────────────────────────────────────

func TestHandlePolicyAdd_ValidData(t *testing.T) {
	const secret = "test-secret"
	s := newPolicyTestServer(t, secret)

	form := url.Values{
		"name":          {"prod-policy"},
		"match_hosts":   {"prod-*"},
		"require_admin": {"on"},
	}
	r := buildFormRequest(secret, "admin-user", "admin", "/api/policies/add", form)
	w := httptest.NewRecorder()
	s.handlePolicyAdd(w, r)

	// Should redirect (303) on success.
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the policy was added.
	s.policyCfgMu.RLock()
	policies := s.policyEngine.Policies()
	s.policyCfgMu.RUnlock()

	found := false
	for _, p := range policies {
		if p.Name == "prod-policy" {
			found = true
			if !p.RequireAdmin {
				t.Error("expected RequireAdmin=true")
			}
			break
		}
	}
	if !found {
		t.Error("policy 'prod-policy' was not added")
	}
}

func TestHandlePolicyAdd_DuplicateName(t *testing.T) {
	const secret = "test-secret"
	s := newPolicyTestServer(t, secret)

	// Pre-populate a policy.
	s.policyCfgMu.Lock()
	s.policyEngine = policy.NewEngine([]policy.Policy{
		{Name: "existing", MatchHosts: []string{"*"}},
	})
	s.policyCfgMu.Unlock()

	form := url.Values{
		"name":        {"existing"},
		"match_hosts": {"web-*"},
	}
	r := buildFormRequest(secret, "admin-user", "admin", "/api/policies/add", form)
	w := httptest.NewRecorder()
	s.handlePolicyAdd(w, r)

	// Duplicate name should redirect with flash error, not add the policy.
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect with flash error, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify only one policy exists (the original).
	s.policyCfgMu.RLock()
	policies := s.policyEngine.Policies()
	s.policyCfgMu.RUnlock()

	count := 0
	for _, p := range policies {
		if p.Name == "existing" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 policy named 'existing', got %d", count)
	}
}

func TestHandlePolicyAdd_InvalidName(t *testing.T) {
	const secret = "test-secret"
	s := newPolicyTestServer(t, secret)

	form := url.Values{
		"name":        {"INVALID-UPPER"},
		"match_hosts": {"web-*"},
	}
	r := buildFormRequest(secret, "admin-user", "admin", "/api/policies/add", form)
	w := httptest.NewRecorder()
	s.handlePolicyAdd(w, r)

	// Invalid name should redirect with flash error.
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect with flash error, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify no policy was added.
	s.policyCfgMu.RLock()
	policies := s.policyEngine.Policies()
	s.policyCfgMu.RUnlock()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}
}

func TestHandlePolicyAdd_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newPolicyTestServer(t, secret)

	form := url.Values{
		"name":        {"new-policy"},
		"match_hosts": {"*"},
	}
	r := buildFormRequest(secret, "regular-user", "user", "/api/policies/add", form)
	w := httptest.NewRecorder()
	s.handlePolicyAdd(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ── handlePolicyDelete tests ─────────────────────────────────────────────────

func TestHandlePolicyDelete_Success(t *testing.T) {
	const secret = "test-secret"
	s := newPolicyTestServer(t, secret)

	// Pre-populate a policy and save it to disk so delete can reload.
	policies := []policy.Policy{
		{Name: "to-delete", MatchHosts: []string{"*"}},
	}
	s.cfgMu.RLock()
	path := s.cfg.ApprovalPoliciesFile
	s.cfgMu.RUnlock()
	if err := policy.SavePolicies(path, policies); err != nil {
		t.Fatalf("failed to save policies: %v", err)
	}
	s.policyCfgMu.Lock()
	s.policyEngine = policy.NewEngine(policies)
	s.policyCfgMu.Unlock()

	form := url.Values{
		"name": {"to-delete"},
	}
	r := buildFormRequest(secret, "admin-user", "admin", "/api/policies/delete", form)
	w := httptest.NewRecorder()
	s.handlePolicyDelete(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify the policy was removed.
	s.policyCfgMu.RLock()
	remaining := s.policyEngine.Policies()
	s.policyCfgMu.RUnlock()
	for _, p := range remaining {
		if p.Name == "to-delete" {
			t.Error("policy 'to-delete' was not removed")
		}
	}
}

func TestHandlePolicyDelete_NonExistent(t *testing.T) {
	const secret = "test-secret"
	s := newPolicyTestServer(t, secret)

	form := url.Values{
		"name": {"ghost-policy"},
	}
	r := buildFormRequest(secret, "admin-user", "admin", "/api/policies/delete", form)
	w := httptest.NewRecorder()
	s.handlePolicyDelete(w, r)

	// Non-existent policy delete redirects with flash error (not 404 HTTP status).
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect with flash error, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandlePolicyDelete_NonAdmin(t *testing.T) {
	const secret = "test-secret"
	s := newPolicyTestServer(t, secret)

	form := url.Values{
		"name": {"some-policy"},
	}
	r := buildFormRequest(secret, "regular-user", "user", "/api/policies/delete", form)
	w := httptest.NewRecorder()
	s.handlePolicyDelete(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandlePolicyAdd_WithMinApprovals(t *testing.T) {
	const secret = "test-secret"
	s := newPolicyTestServer(t, secret)

	form := url.Values{
		"name":          {"dual-approve"},
		"match_hosts":   {"prod-*"},
		"min_approvals": {"3"},
	}
	r := buildFormRequest(secret, "admin-user", "admin", "/api/policies/add", form)
	w := httptest.NewRecorder()
	s.handlePolicyAdd(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	s.policyCfgMu.RLock()
	policies := s.policyEngine.Policies()
	s.policyCfgMu.RUnlock()
	for _, p := range policies {
		if p.Name == "dual-approve" {
			if p.MinApprovals != 3 {
				t.Errorf("expected MinApprovals=3, got %d", p.MinApprovals)
			}
			return
		}
	}
	t.Error("policy 'dual-approve' was not added")
}
