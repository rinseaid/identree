package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
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
		cfg:           &config.ServerConfig{APIKey: "some-key", SharedSecret: "test"},
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
