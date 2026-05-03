package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/policy"
	"github.com/rinseaid/identree/internal/sudorules"
)

func TestValidateSudoRuleFields_Valid(t *testing.T) {
	rule := sudorules.SudoRule{
		Hosts:    "ALL",
		Commands: "/usr/bin/apt, /usr/bin/systemctl",
	}
	if !validateSudoRuleFields(rule) {
		t.Error("expected valid rule")
	}
}

func TestValidateSudoRuleFields_TooLong(t *testing.T) {
	rule := sudorules.SudoRule{
		Hosts: strings.Repeat("a", maxSudoFieldLen+1),
	}
	if validateSudoRuleFields(rule) {
		t.Error("expected invalid for too-long field")
	}
}

func TestValidateSudoRuleFields_NullByte(t *testing.T) {
	rule := sudorules.SudoRule{
		Commands: "/bin/bash\x00",
	}
	if validateSudoRuleFields(rule) {
		t.Error("expected invalid for null byte")
	}
}

func TestValidateSudoRuleFields_Newline(t *testing.T) {
	rule := sudorules.SudoRule{
		Hosts: "web01\nweb02",
	}
	if validateSudoRuleFields(rule) {
		t.Error("expected invalid for newline")
	}
}

func TestValidateSudoRuleFields_CarriageReturn(t *testing.T) {
	rule := sudorules.SudoRule{
		RunAsUser: "root\r",
	}
	if validateSudoRuleFields(rule) {
		t.Error("expected invalid for carriage return")
	}
}

func TestPosixGroupName_Valid(t *testing.T) {
	valid := []string{"admins", "web_admins", "_private", "group.with.dots", "a"}
	for _, name := range valid {
		if !posixGroupName.MatchString(name) {
			t.Errorf("expected %q to be valid POSIX group name", name)
		}
	}
}

// ── handleAdminSudoRules tests ────────────────────────────────────────────────

func TestHandleAdminSudoRules_MethodNotAllowed(t *testing.T) {
	s := &Server{cfg: &config.ServerConfig{}}
	r := httptest.NewRequest(http.MethodPost, "/admin/sudo-rules", nil)
	w := httptest.NewRecorder()
	s.handleAdminSudoRules(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAdminSudoRules_NotBridgeMode(t *testing.T) {
	s := &Server{
		cfg:           &config.ServerConfig{APIKey: "some-key", SharedSecret: "test", SessionSecret: "test"},
		revokedNonces: make(map[string]time.Time),
		mutationRL:    newMutationRateLimiter(),
	}
	// With APIKey set, not bridge mode → redirect.
	ts := time.Now().Unix()
	cookieVal := makeCookie("test", "admin-user", "admin", ts)
	r := httptest.NewRequest(http.MethodGet, "/admin/sudo-rules", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieVal})
	w := httptest.NewRecorder()
	s.handleAdminSudoRules(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect when not bridge mode, got %d", w.Code)
	}
}

func TestPosixGroupName_Invalid(t *testing.T) {
	invalid := []string{"Admin", "123group", "-group", "with space", ""}
	for _, name := range invalid {
		if posixGroupName.MatchString(name) {
			t.Errorf("expected %q to be invalid POSIX group name", name)
		}
	}
}

// ── sudo CRUD handler helper ─────────────────────────────────────────────────

// newSudoTestServer builds a minimal *Server suitable for sudo CRUD handler
// tests. Bridge mode is enabled (APIKey == "") and the sudoRules store is
// backed by a temp file.
func newSudoTestServer(t *testing.T, secret string) *Server {
	t.Helper()
	store := newTestStore(t, 5*time.Minute, 10*time.Minute)
	sudoStore, err := sudorules.NewStore(filepath.Join(t.TempDir(), "sudorules.json"))
	if err != nil {
		t.Fatalf("failed to create sudo store: %v", err)
	}
	return &Server{
		cfg: &config.ServerConfig{
			// APIKey deliberately empty → bridge mode.
			SharedSecret:  secret,
			SessionSecret: secret,
			ChallengeTTL:  5 * time.Minute,
		},
		store:          store,
		sudoRules:      sudoStore,
		hostRegistry:   NewHostRegistry(""),
		authFailRL:     newAuthFailTracker(),
		mutationRL:     newMutationRateLimiter(),
		sseBroadcaster: noopBroadcaster{},
		policyEngine:   policy.NewEngine(nil),
		notifyCfg:      &notify.NotificationConfig{},
		revokedNonces:  make(map[string]time.Time),
	}
}

// ── handleSudoRuleAdd tests ──────────────────────────────────────────────────

func TestHandleSudoRuleAdd_Success(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group":    {"webadmins"},
		"hosts":    {"ALL"},
		"commands": {"/usr/bin/systemctl restart nginx"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleAdd(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	rules := s.sudoRules.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Group != "webadmins" {
		t.Errorf("expected group webadmins, got %q", rules[0].Group)
	}
	if rules[0].Commands != "/usr/bin/systemctl restart nginx" {
		t.Errorf("unexpected commands: %q", rules[0].Commands)
	}
}

func TestHandleSudoRuleAdd_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/sudo-rules/add", nil)
	w := httptest.NewRecorder()
	s.handleSudoRuleAdd(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleSudoRuleAdd_NotBridgeMode(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)
	s.cfg.APIKey = "some-key" // disable bridge mode

	form := url.Values{
		"group":    {"webadmins"},
		"commands": {"/usr/bin/apt"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleAdd(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when not bridge mode, got %d", w.Code)
	}
}

func TestHandleSudoRuleAdd_NonAdminRejected(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group":    {"webadmins"},
		"commands": {"/usr/bin/apt"},
	}
	r := buildFormRequest(secret, "regular_user", "user", "/api/sudo-rules/add", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleAdd(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestHandleSudoRuleAdd_MissingFields(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	// Missing commands.
	form := url.Values{
		"group": {"webadmins"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleAdd(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing commands, got %d", w.Code)
	}

	// Missing group.
	form2 := url.Values{
		"commands": {"/usr/bin/apt"},
	}
	r2 := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form2)
	w2 := httptest.NewRecorder()
	s.handleSudoRuleAdd(w2, r2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing group, got %d", w2.Code)
	}
}

func TestHandleSudoRuleAdd_InvalidGroupName(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	invalid := []string{"Admin", "123group", "-group", "with space"}
	for _, name := range invalid {
		form := url.Values{
			"group":    {name},
			"commands": {"/usr/bin/apt"},
		}
		r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form)
		w := httptest.NewRecorder()
		s.handleSudoRuleAdd(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("group %q: expected 400, got %d", name, w.Code)
		}
	}
}

func TestHandleSudoRuleAdd_GroupTooLong(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	longGroup := "a" + strings.Repeat("b", 256) // 257 chars
	form := url.Values{
		"group":    {longGroup},
		"commands": {"/usr/bin/apt"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleAdd(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for too-long group, got %d", w.Code)
	}
}

func TestHandleSudoRuleAdd_DuplicateGroup(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	// Seed an existing rule.
	if err := s.sudoRules.Add(sudorules.SudoRule{Group: "webadmins", Commands: "/usr/bin/apt"}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	form := url.Values{
		"group":    {"webadmins"},
		"commands": {"/usr/bin/systemctl"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleAdd(w, r)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate group, got %d", w.Code)
	}
}

func TestHandleSudoRuleAdd_ControlCharsInFields(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	tests := []struct {
		name  string
		field string
		value string
	}{
		{"null byte in hosts", "hosts", "web01\x00evil"},
		{"newline in commands", "commands", "/bin/bash\n/bin/sh"},
		{"field too long", "hosts", strings.Repeat("x", maxSudoFieldLen+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{
				"group":    {"testgroup"},
				"commands": {"/usr/bin/apt"},
			}
			form.Set(tc.field, tc.value)
			// Ensure commands is set if the field being tested is commands.
			if tc.field == "commands" {
				form.Set("commands", tc.value)
			}
			r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form)
			w := httptest.NewRecorder()
			s.handleSudoRuleAdd(w, r)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for %s, got %d", tc.name, w.Code)
			}
		})
	}
}

func TestHandleSudoRuleAdd_AllOptionalFields(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group":        {"db_admins"},
		"hosts":        {"db01, db02"},
		"commands":     {"/usr/bin/pg_dump, /usr/bin/pg_restore"},
		"run_as_user":  {"postgres"},
		"run_as_group": {"postgres"},
		"options":      {"!authenticate"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/add", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleAdd(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	rules := s.sudoRules.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r0 := rules[0]
	if r0.Hosts != "db01, db02" {
		t.Errorf("hosts = %q", r0.Hosts)
	}
	if r0.RunAsUser != "postgres" {
		t.Errorf("run_as_user = %q", r0.RunAsUser)
	}
	if r0.RunAsGroup != "postgres" {
		t.Errorf("run_as_group = %q", r0.RunAsGroup)
	}
	if r0.Options != "!authenticate" {
		t.Errorf("options = %q", r0.Options)
	}
}

// ── handleSudoRuleUpdate tests ───────────────────────────────────────────────

func TestHandleSudoRuleUpdate_Success(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	// Seed a rule to update.
	if err := s.sudoRules.Add(sudorules.SudoRule{
		Group:    "webadmins",
		Hosts:    "ALL",
		Commands: "/usr/bin/apt",
	}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	form := url.Values{
		"group":       {"webadmins"},
		"hosts":       {"web01, web02"},
		"commands":    {"/usr/bin/apt, /usr/bin/systemctl"},
		"run_as_user": {"root"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/update", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleUpdate(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	rules := s.sudoRules.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Hosts != "web01, web02" {
		t.Errorf("expected updated hosts, got %q", rules[0].Hosts)
	}
	if rules[0].Commands != "/usr/bin/apt, /usr/bin/systemctl" {
		t.Errorf("expected updated commands, got %q", rules[0].Commands)
	}
}

func TestHandleSudoRuleUpdate_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/sudo-rules/update", nil)
	w := httptest.NewRecorder()
	s.handleSudoRuleUpdate(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleSudoRuleUpdate_NotBridgeMode(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)
	s.cfg.APIKey = "some-key"

	form := url.Values{
		"group":    {"webadmins"},
		"commands": {"/usr/bin/apt"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/update", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleUpdate(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when not bridge mode, got %d", w.Code)
	}
}

func TestHandleSudoRuleUpdate_NotFound(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group":    {"nonexistent"},
		"commands": {"/usr/bin/apt"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/update", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleUpdate(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent group, got %d", w.Code)
	}
}

func TestHandleSudoRuleUpdate_NonAdminRejected(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group":    {"webadmins"},
		"commands": {"/usr/bin/apt"},
	}
	r := buildFormRequest(secret, "regular_user", "user", "/api/sudo-rules/update", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleUpdate(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestHandleSudoRuleUpdate_MissingFields(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group": {"webadmins"},
		// commands missing
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/update", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleUpdate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing commands, got %d", w.Code)
	}
}

func TestHandleSudoRuleUpdate_InvalidGroupName(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group":    {"Invalid-Group"},
		"commands": {"/usr/bin/apt"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/update", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleUpdate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid group, got %d", w.Code)
	}
}

func TestHandleSudoRuleUpdate_ControlCharsRejected(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	if err := s.sudoRules.Add(sudorules.SudoRule{Group: "webadmins", Commands: "/usr/bin/apt"}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	form := url.Values{
		"group":    {"webadmins"},
		"commands": {"/usr/bin/apt"},
		"options":  {"!authenticate\x00"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/update", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleUpdate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for control chars, got %d", w.Code)
	}
}

// ── handleSudoRuleDelete tests ───────────────────────────────────────────────

func TestHandleSudoRuleDelete_Success(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	if err := s.sudoRules.Add(sudorules.SudoRule{Group: "webadmins", Commands: "/usr/bin/apt"}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	form := url.Values{
		"group": {"webadmins"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/delete", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleDelete(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d; body: %s", w.Code, w.Body.String())
	}

	if len(s.sudoRules.Rules()) != 0 {
		t.Error("expected 0 rules after delete")
	}
}

func TestHandleSudoRuleDelete_MethodNotAllowed(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	r := httptest.NewRequest(http.MethodGet, "/api/sudo-rules/delete", nil)
	w := httptest.NewRecorder()
	s.handleSudoRuleDelete(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleSudoRuleDelete_NotBridgeMode(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)
	s.cfg.APIKey = "some-key"

	form := url.Values{
		"group": {"webadmins"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/delete", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleDelete(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when not bridge mode, got %d", w.Code)
	}
}

func TestHandleSudoRuleDelete_NotFound(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group": {"nonexistent"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/delete", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleDelete(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent group, got %d", w.Code)
	}
}

func TestHandleSudoRuleDelete_NonAdminRejected(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group": {"webadmins"},
	}
	r := buildFormRequest(secret, "regular_user", "user", "/api/sudo-rules/delete", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleDelete(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestHandleSudoRuleDelete_MissingGroup(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/delete", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleDelete(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing group, got %d", w.Code)
	}
}

func TestHandleSudoRuleDelete_InvalidGroupName(t *testing.T) {
	const secret = "test-secret"
	s := newSudoTestServer(t, secret)

	form := url.Values{
		"group": {"Invalid-Group"},
	}
	r := buildFormRequest(secret, "admin_user", "admin", "/api/sudo-rules/delete", form)
	w := httptest.NewRecorder()
	s.handleSudoRuleDelete(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid group name, got %d", w.Code)
	}
}
