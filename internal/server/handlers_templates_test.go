package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/config"
)

// loginAdminCookie attaches a valid admin session cookie to r.
func loginAdminCookie(t *testing.T, secret, username string, r *http.Request) {
	t.Helper()
	cookie := makeCookie(secret, username, "admin", time.Now().Unix())
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
}

// ── /admin/hosts template renders the new agent column + expandable row ───

func TestHandleAdminHosts_RendersAgentColumn(t *testing.T) {
	const secret = "test-secret"
	s := newAdminTestServer(t, secret)

	// Seed an action_log entry so the host appears, then a heartbeat so
	// it gets the chevron + detail row.
	s.store.LogAction(context.Background(), "alice", challpkg.ActionApproved, "prod-web-01", "ABC123", "")
	s.store.RecordHeartbeat(context.Background(), challpkg.AgentHeartbeat{
		Hostname: "prod-web-01", Version: "0.42.0",
		OSInfo: "Ubuntu 24.04.4 LTS (arm64)", IP: "10.0.0.1",
	})
	// Also seed an action-only host (no heartbeat) so we can assert it
	// renders without a chevron and shows "--" in last seen.
	s.store.LogAction(context.Background(), "alice", challpkg.ActionApproved, "no-agent-host", "DEF456", "")

	r := httptest.NewRequest(http.MethodGet, "/admin/hosts", nil)
	loginAdminCookie(t, secret, "alice", r)
	w := httptest.NewRecorder()
	s.handleAdminHosts(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()

	// Last-seen column header must be present.
	if !strings.Contains(body, "gtcol-hlastseen") {
		t.Errorf("expected gtcol-hlastseen column class in body")
	}
	// Reported host gets the expand chevron + detail row.
	if !strings.Contains(body, `class="host-expand-btn"`) {
		t.Errorf("expected host-expand-btn for reported host")
	}
	if !strings.Contains(body, `id="host-detail-prod-web-01"`) {
		t.Errorf("expected detail row for prod-web-01")
	}
	// Detail row collapsed by default.
	if !strings.Contains(body, `id="host-detail-prod-web-01" style="display:none"`) {
		t.Errorf("detail row should default to display:none")
	}
	// Detail content rendered.
	for _, want := range []string{"0.42.0", "Ubuntu 24.04.4 LTS", "10.0.0.1"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail row missing %q", want)
		}
	}
	// Status pill with the right class.
	if !strings.Contains(body, "agent-pill green") {
		t.Errorf("expected green agent-pill for fresh heartbeat")
	}

	// no-agent-host appears but without a chevron or detail row.
	if !strings.Contains(body, ">no-agent-host<") {
		t.Errorf("expected no-agent-host to render")
	}
	if strings.Contains(body, `id="host-detail-no-agent-host"`) {
		t.Errorf("no-agent-host should NOT have a detail row")
	}
}

func TestHandleAdminHosts_StatusPillBuckets(t *testing.T) {
	const secret = "test-secret"
	cases := []struct {
		name     string
		ageSec   int64 // how long ago last_seen was
		wantPill string
	}{
		{"green if fresh", 60, "agent-pill green"},
		{"amber after 10m", 15 * 60, "agent-pill amber"},
		{"red after 60m", 90 * 60, "agent-pill red"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAdminTestServer(t, secret)
			s.store.LogAction(context.Background(), "alice", challpkg.ActionApproved, "h", "C", "")
			s.store.RecordHeartbeat(context.Background(), challpkg.AgentHeartbeat{Hostname: "h"})
			// Backdate last_seen by directly writing the agents row.
			db := s.store.(*challpkg.SQLStore).DB()
			past := time.Now().Add(-time.Duration(tc.ageSec) * time.Second).Unix()
			if _, err := db.Exec(`UPDATE agents SET last_seen = $1 WHERE hostname = 'h'`, past); err != nil {
				t.Fatalf("backdate: %v", err)
			}

			r := httptest.NewRequest(http.MethodGet, "/admin/hosts", nil)
			loginAdminCookie(t, secret, "alice", r)
			w := httptest.NewRecorder()
			s.handleAdminHosts(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.wantPill) {
				t.Errorf("expected pill class %q in body", tc.wantPill)
			}
		})
	}
}

// ── /history empty-state still renders the table chrome ───────────────────

func TestHandleHistoryPage_EmptyKeepsTableChrome(t *testing.T) {
	const secret = "test-secret"
	cfg := emptyConfig(secret)
	s := newDashboardTestServer(t, &cfg)

	r := httptest.NewRequest(http.MethodGet, "/history?hostname=does-not-exist", nil)
	loginAdminCookie(t, secret, "alice", r)
	w := httptest.NewRecorder()
	s.handleHistoryPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// Table wrapper must still be present even with zero rows.
	if !strings.Contains(body, `class="history-gtable"`) {
		t.Error("expected history-gtable wrapper to render in empty state")
	}
	// Column headers must still be present.
	for _, want := range []string{"gtcol-htime", "gtcol-haction", "gtcol-hhost", "gtcol-hcode", "gtcol-hreason"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected column class %q in empty-state body", want)
		}
	}
	// "No activity found" message inside the table.
	if !strings.Contains(body, "No activity found") {
		t.Error("expected 'No activity found' inside table chrome")
	}
}

func TestHandleHistoryPage_RendersRows(t *testing.T) {
	const secret = "test-secret"
	cfg := emptyConfig(secret)
	s := newDashboardTestServer(t, &cfg)

	s.store.LogAction(context.Background(), "alice", challpkg.ActionApproved, "host1", "CODE-X", "admin")
	s.store.LogAction(context.Background(), "alice", challpkg.ActionRevoked, "host1", "CODE-Y", "admin")

	r := httptest.NewRequest(http.MethodGet, "/history", nil)
	loginAdminCookie(t, secret, "alice", r)
	w := httptest.NewRecorder()
	s.handleHistoryPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"CODE-X", "CODE-Y", "host1"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in rendered body", want)
		}
	}
	// Empty-state message should NOT appear when there are entries.
	if strings.Contains(body, "No activity found") {
		t.Error("'No activity found' should not render when there are rows")
	}
}

// emptyConfig returns a minimal ServerConfig for dashboard handler tests.
func emptyConfig(secret string) config.ServerConfig {
	return config.ServerConfig{
		SharedSecret:    secret,
		SessionSecret:   secret,
		ChallengeTTL:    5 * time.Minute,
		DefaultPageSize: 50,
	}
}
