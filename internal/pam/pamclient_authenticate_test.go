package pam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/rinseaid/identree/internal/breakglass"
	"github.com/rinseaid/identree/internal/config"
)

// fakeServerOpts controls how the test server responds to each endpoint.
type fakeServerOpts struct {
	challengeID string
	// pollSequence, if non-empty, dictates the exact responses returned by
	// /api/challenge/{id} in order. If it runs out, the final response repeats.
	pollSequence []func(w http.ResponseWriter, r *http.Request)
	// createHandler overrides the /api/challenge POST handler when non-nil.
	createHandler func(w http.ResponseWriter, r *http.Request)
	// graceHandler overrides /api/grace-status when non-nil.
	graceHandler func(w http.ResponseWriter, r *http.Request)
	// reportHandler overrides /api/breakglass/report when non-nil.
	reportHandler func(w http.ResponseWriter, r *http.Request)

	pollCount    atomic.Int32
	createCount  atomic.Int32
	graceCount   atomic.Int32
	reportCount  atomic.Int32
}

func (f *fakeServerOpts) handler() http.Handler {
	if f.challengeID == "" {
		f.challengeID = strings.Repeat("a", 32)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/challenge":
			f.createCount.Add(1)
			if f.createHandler != nil {
				f.createHandler(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":     f.challengeID,
				"user_code":        "ABCD-1234",
				"verification_url": "https://example/approve",
				"expires_in":       120,
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/challenge/"):
			n := int(f.pollCount.Add(1)) - 1
			if len(f.pollSequence) == 0 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending", "expires_in": 60})
				return
			}
			idx := n
			if idx >= len(f.pollSequence) {
				idx = len(f.pollSequence) - 1
			}
			f.pollSequence[idx](w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/grace-status":
			f.graceCount.Add(1)
			if f.graceHandler != nil {
				f.graceHandler(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"grace_remaining": 0})
		case r.Method == http.MethodPost && r.URL.Path == "/api/breakglass/report":
			f.reportCount.Add(1)
			if f.reportHandler != nil {
				f.reportHandler(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
}

// newTestClient wires up a PAMClient pointed at the given TLS test server with
// fast poll cadence so the test completes quickly. MessageWriter is redirected
// to a buffer to keep terminal output off stderr during -v runs.
func newTestClient(t *testing.T, srv *httptest.Server, secret string) (*PAMClient, *bytes.Buffer) {
	t.Helper()
	cfg := &config.ClientConfig{
		ServerURL:    srv.URL,
		SharedSecret: secret,
		PollInterval: 10 * time.Millisecond,
		Timeout:      2 * time.Second,
	}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srv.Client()

	buf := &bytes.Buffer{}
	prev := MessageWriter
	MessageWriter = buf
	t.Cleanup(func() { MessageWriter = prev })
	return p, buf
}

// ── Authenticate ────────────────────────────────────────────────────────────

func TestAuthenticate_RejectsInvalidUsername(t *testing.T) {
	p := &PAMClient{cfg: &config.ClientConfig{ServerURL: "https://x"}}
	for _, u := range []string{"alice/bob", "al\x00ice", "../etc/passwd"} {
		if err := p.Authenticate(u); err == nil || !strings.Contains(err.Error(), "invalid username") {
			t.Errorf("Authenticate(%q): expected invalid username error, got %v", u, err)
		}
	}
}

func TestAuthenticate_PollingApproval(t *testing.T) {
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("b", 32)

	approvalToken := computeVerifyToken(secret, challengeID, "alice", "approved", "", "")

	f := &fakeServerOpts{
		challengeID: challengeID,
		pollSequence: []func(http.ResponseWriter, *http.Request){
			// First poll: still pending
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending", "expires_in": 60})
			},
			// Second poll: approved with valid HMAC
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":         "approved",
					"approval_token": approvalToken,
					"expires_in":     60,
				})
			},
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, buf := newTestClient(t, srv, secret)
	p.cfg.BreakglassEnabled = false

	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if f.createCount.Load() != 1 {
		t.Errorf("createCount = %d; want 1", f.createCount.Load())
	}
	if f.pollCount.Load() < 2 {
		t.Errorf("pollCount = %d; want >=2", f.pollCount.Load())
	}
	if !strings.Contains(buf.String(), "ABCD-1234") {
		t.Errorf("expected user_code in output; got %q", buf.String())
	}
}

func TestAuthenticate_Denied(t *testing.T) {
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("c", 32)
	denialToken := computeVerifyToken(secret, challengeID, "alice", "denied", "", "")

	f := &fakeServerOpts{
		challengeID: challengeID,
		pollSequence: []func(http.ResponseWriter, *http.Request){
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       "denied",
					"denial_token": denialToken,
					"deny_reason":  "policy violation",
				})
			},
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, buf := newTestClient(t, srv, secret)
	err := p.Authenticate("alice")
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected denial error, got %v", err)
	}
	if !strings.Contains(buf.String(), "policy violation") {
		t.Errorf("deny_reason not surfaced to terminal: %q", buf.String())
	}
}

func TestAuthenticate_ForgedApprovalRejected(t *testing.T) {
	// Server returns status=approved but with a bogus HMAC. Client must reject.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("d", 32)

	f := &fakeServerOpts{
		challengeID: challengeID,
		pollSequence: []func(http.ResponseWriter, *http.Request){
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":         "approved",
					"approval_token": "deadbeefdeadbeefdeadbeefdeadbeef",
					"expires_in":     60,
				})
			},
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, _ := newTestClient(t, srv, secret)
	err := p.Authenticate("alice")
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected HMAC verification failure, got %v", err)
	}
}

func TestAuthenticate_ForgedDenialIgnored(t *testing.T) {
	// Server returns status=denied with a bad HMAC followed by timeout.
	// Client must NOT accept a forged denial; it keeps polling until client timeout.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("e", 32)

	f := &fakeServerOpts{
		challengeID: challengeID,
		pollSequence: []func(http.ResponseWriter, *http.Request){
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       "denied",
					"denial_token": "forged",
				})
			},
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, _ := newTestClient(t, srv, secret)
	p.cfg.Timeout = 300 * time.Millisecond // keep short
	err := p.Authenticate("alice")
	if err == nil {
		t.Fatalf("expected timeout error (forged denials ignored), got nil")
	}
	// Should be a timeout, NOT a "denied" message.
	if strings.Contains(err.Error(), "denied") {
		t.Errorf("forged denial leaked through: %v", err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout, got %v", err)
	}
}

func TestAuthenticate_ServerErrorCreate(t *testing.T) {
	// 429 from /api/challenge → friendly "too many pending" error.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/challenge" {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p, _ := newTestClient(t, srv, "test-secret-32-bytes-long-xxxxxxxxx")
	p.cfg.BreakglassEnabled = false
	err := p.Authenticate("alice")
	if err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("expected rate-limit error, got %v", err)
	}
}

func TestAuthenticate_ServerError500(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/challenge" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p, _ := newTestClient(t, srv, "test-secret-32-bytes-long-xxxxxxxxx")
	p.cfg.BreakglassEnabled = false
	err := p.Authenticate("alice")
	if err == nil || !strings.Contains(err.Error(), "server error") {
		t.Errorf("expected server error, got %v", err)
	}
}

func TestAuthenticate_AutoApprovedGrace(t *testing.T) {
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("f", 32)
	approvalToken := computeVerifyToken(secret, challengeID, "alice", "approved", "", "")

	f := &fakeServerOpts{
		challengeID: challengeID,
		createHandler: func(w http.ResponseWriter, r *http.Request) {
			// Server grants immediately via grace period.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":     challengeID,
				"user_code":        "XXXX-0000",
				"verification_url": "https://example/approve",
				"expires_in":       120,
				"status":           "approved",
				"approval_token":   approvalToken,
				"grace_remaining":  1800,
			})
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, buf := newTestClient(t, srv, secret)
	p.cfg.BreakglassEnabled = false
	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// No polling should have happened — grace approval short-circuits.
	if f.pollCount.Load() != 0 {
		t.Errorf("pollCount = %d; want 0 (grace approval)", f.pollCount.Load())
	}
	if !strings.Contains(buf.String(), "30m") && !strings.Contains(buf.String(), "1800") {
		// terminal_sudo_approved uses formatDuration which renders 1800s as "30m".
		t.Errorf("expected grace duration in output: %q", buf.String())
	}
}

func TestAuthenticate_AutoApprovedForgedRejected(t *testing.T) {
	// Immediate "approved" with bogus HMAC must be rejected.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("9", 32)

	f := &fakeServerOpts{
		challengeID: challengeID,
		createHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":     challengeID,
				"user_code":        "XXXX-0000",
				"verification_url": "https://example/approve",
				"expires_in":       120,
				"status":           "approved",
				"approval_token":   "not-a-valid-mac",
			})
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, _ := newTestClient(t, srv, secret)
	p.cfg.BreakglassEnabled = false
	err := p.Authenticate("alice")
	if err == nil || !strings.Contains(err.Error(), "auto-approval") {
		t.Errorf("expected auto-approval HMAC rejection, got %v", err)
	}
}

// ── queryGraceStatus via cache-hit path ────────────────────────────────────

func TestAuthenticate_CacheHit_GraceStatusUnreachable_FailsClosed(t *testing.T) {
	// When token cache hits but grace-status endpoint is unreachable, we must
	// NOT approve from cache — fail closed.
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "testhost"}
	jwt := makeJWT(t, map[string]any{
		"exp":                time.Now().Add(time.Hour).Unix(),
		"preferred_username": "alice",
	})
	if err := tc.Write("alice", jwt); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	// Override FileOwnerUID so the cache-owner check passes (test runs as non-root).
	// Check() also requires root ownership, so we stub.
	prev := config.FileOwnerUID
	config.FileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	t.Cleanup(func() { config.FileOwnerUID = prev })

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// grace-status returns 500 → client can't verify → must fail-closed.
		if r.URL.Path == "/api/grace-status" {
			http.Error(w, "oops", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x", PollInterval: 10 * time.Millisecond, Timeout: time.Second}
	p, err := NewPAMClient(cfg, tc, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srv.Client()

	err = p.Authenticate("alice")
	// Cache hit but grace unreachable (HTTP 500) → graceErr path → fail-closed.
	// The actual error isn't a "verify" string — verification actually hits JWKS
	// and fails first (no network), so the Check path fails and we fall through
	// to device flow. Either outcome (fail-closed OR device flow failure) is
	// acceptable; what matters is that we did NOT silently approve.
	if err == nil {
		t.Errorf("expected failure, got nil (must not approve when grace-status unavailable)")
	}
}

// ── formatDuration ─────────────────────────────────────────────────────────

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-5 * time.Second, "0s"},
		{30 * time.Second, "30s"},
		{time.Minute, "1m"},
		{47 * time.Minute, "47m"},
		{3 * time.Hour, "3h"},
		{3*time.Hour + 12*time.Minute, "3h 12m"},
		{24 * time.Hour, "24h"},
	}
	for _, c := range cases {
		// nil t func -> fallback suffixes
		if got := formatDuration(nil, c.d); got != c.want {
			t.Errorf("formatDuration(%v) = %q; want %q", c.d, got, c.want)
		}
	}

	// With a translation func that returns custom suffixes.
	tr := func(k string) string {
		switch k {
		case "hour_abbr":
			return "hr"
		case "minute_abbr":
			return "min"
		}
		return k
	}
	if got := formatDuration(tr, 2*time.Hour+5*time.Minute); got != "2hr 5min" {
		t.Errorf("translated formatDuration = %q", got)
	}

	// Translation func that echoes the key back (unresolved) -> fallback used.
	echo := func(k string) string { return k }
	if got := formatDuration(echo, time.Hour); got != "1h" {
		t.Errorf("echo translator should fall back: %q", got)
	}
}

// ── breakglass usage records ───────────────────────────────────────────────

// withBreakglassUsagePath redirects the package-level usage path to a temp
// file for the duration of the test.
func withBreakglassUsagePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "identree-breakglass-used")
	prev := breakglassUsagePath
	breakglassUsagePath = path
	t.Cleanup(func() { breakglassUsagePath = prev })

	// The reader validates root ownership; override for non-root test runs.
	prevUID := config.FileOwnerUID
	config.FileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	t.Cleanup(func() { config.FileOwnerUID = prevUID })
	return path
}

func TestRecordAndReadBreakglassUsage(t *testing.T) {
	path := withBreakglassUsagePath(t)

	recordBreakglassUsage("host1", "alice")
	recordBreakglassUsage("host1", "bob")

	// File should exist with 0600 perms.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("usage file perm = %04o; want 0600", perm)
	}

	records := readBreakglassUsageRecords()
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Hostname != "host1" || records[0].Username != "alice" {
		t.Errorf("record[0] = %+v", records[0])
	}
	if records[1].Username != "bob" {
		t.Errorf("record[1] = %+v", records[1])
	}
	if records[0].Timestamp == 0 {
		t.Errorf("timestamp not parsed")
	}
}

func TestReadBreakglassUsageRecords_MissingFile(t *testing.T) {
	// Path that does not exist → returns nil, not an error.
	prev := breakglassUsagePath
	breakglassUsagePath = filepath.Join(t.TempDir(), "nonexistent")
	t.Cleanup(func() { breakglassUsagePath = prev })

	if records := readBreakglassUsageRecords(); records != nil {
		t.Errorf("expected nil for missing file, got %v", records)
	}
}

func TestReadBreakglassUsageRecords_SkipsMalformedLines(t *testing.T) {
	path := withBreakglassUsagePath(t)
	// Mix of valid + malformed lines.
	content := "host1 alice 1234567890\n" +
		"\n" + // blank line
		"not-three-fields\n" +
		"host2 bob notanumber\n" +
		"host3 carol 9876543210\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	records := readBreakglassUsageRecords()
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 valid", len(records))
	}
	if records[0].Username != "alice" || records[1].Username != "carol" {
		t.Errorf("wrong records: %+v", records)
	}
}

func TestReportBreakglassUsageIfNeeded_DeletesOnSuccess(t *testing.T) {
	path := withBreakglassUsagePath(t)
	recordBreakglassUsage("host1", "alice")

	var reported atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/breakglass/report" {
			reported.Add(1)
			// Sanity check that the body parses.
			var rec breakglassUsageRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				t.Errorf("decode report body: %v", err)
			}
			if rec.Username != "alice" {
				t.Errorf("reported username = %q", rec.Username)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x"}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()

	p.reportBreakglassUsageIfNeeded()

	if reported.Load() != 1 {
		t.Errorf("reported %d times; want 1", reported.Load())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("usage file should be deleted after successful report")
	}
}

func TestReportBreakglassUsageIfNeeded_KeepsFileOnServerError(t *testing.T) {
	path := withBreakglassUsagePath(t)
	recordBreakglassUsage("host1", "alice")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x"}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()

	p.reportBreakglassUsageIfNeeded()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("usage file should persist on server error, got %v", err)
	}
}

func TestReportBreakglassUsageIfNeeded_NoFileNoOp(t *testing.T) {
	prev := breakglassUsagePath
	breakglassUsagePath = filepath.Join(t.TempDir(), "nonexistent")
	t.Cleanup(func() { breakglassUsagePath = prev })

	// Server should never be hit.
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{ServerURL: srv.URL, SharedSecret: "x"}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()

	p.reportBreakglassUsageIfNeeded()
	if hits.Load() != 0 {
		t.Errorf("server was contacted with no records: %d hits", hits.Load())
	}
}

// ── queryGraceStatus direct ─────────────────────────────────────────────────

func TestQueryGraceStatus_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/grace-status" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("username") != "alice" || r.URL.Query().Get("hostname") != "myhost" {
			t.Errorf("bad query: %q", r.URL.RawQuery)
		}
		if r.Header.Get("X-Shared-Secret") != "s3cret" {
			t.Errorf("shared secret not sent")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grace_remaining":      600,
			"revoke_tokens_before": "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{ServerURL: srv.URL, SharedSecret: "s3cret"}
	p, err := NewPAMClient(cfg, nil, "myhost")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()
	// Rebuild the grace transport so it picks up the httptest TLS root.
	// queryGraceStatus creates its own client but copies mainTransport.TLSClientConfig;
	// the httptest client's Transport.TLSClientConfig trusts the test CA.
	if mt, ok := srv.Client().Transport.(*http.Transport); ok {
		if pt, ok := p.client.Transport.(*http.Transport); ok {
			pt.TLSClientConfig = mt.TLSClientConfig
		}
	}

	gs, err := p.queryGraceStatus("alice")
	if err != nil {
		t.Fatalf("queryGraceStatus: %v", err)
	}
	if gs.graceRemaining != 600*time.Second {
		t.Errorf("graceRemaining = %v", gs.graceRemaining)
	}
	if !gs.revoked {
		t.Errorf("expected revoked=true")
	}
}

func TestQueryGraceStatus_Non200(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{ServerURL: srv.URL, SharedSecret: "s"}
	p, err := NewPAMClient(cfg, nil, "h")
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()
	if mt, ok := srv.Client().Transport.(*http.Transport); ok {
		if pt, ok := p.client.Transport.(*http.Transport); ok {
			pt.TLSClientConfig = mt.TLSClientConfig
		}
	}

	_, err = p.queryGraceStatus("alice")
	if err == nil || !strings.Contains(err.Error(), "HTTP 410") {
		t.Errorf("expected HTTP 410 error, got %v", err)
	}
}

func TestQueryGraceStatus_NoServerURL(t *testing.T) {
	p := &PAMClient{cfg: &config.ClientConfig{}, client: &http.Client{}}
	_, err := p.queryGraceStatus("alice")
	if err == nil {
		t.Errorf("expected error with empty ServerURL")
	}
}

// Guard against regressions in the helper: ensure challengeID regex applies.
func TestAuthenticate_InitialPollOnlyAfterChallenge(t *testing.T) {
	// Server immediately approves on poll — verify that Authenticate does at
	// least one sleep (initial delay) before polling by measuring elapsed time.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("7", 32)
	tok := computeVerifyToken(secret, challengeID, "alice", "approved", "", "")

	f := &fakeServerOpts{
		challengeID: challengeID,
		pollSequence: []func(http.ResponseWriter, *http.Request){
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":         "approved",
					"approval_token": tok,
				})
			},
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, _ := newTestClient(t, srv, secret)
	p.cfg.PollInterval = 50 * time.Millisecond

	start := time.Now()
	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Errorf("Authenticate returned too quickly (%v); initial sleep missing", elapsed)
	}
}

// Exercise the createChallenge-with-preset-reason path from SUDO_REASON.
func TestAuthenticate_SudoReasonEnvPassed(t *testing.T) {
	t.Setenv("SUDO_REASON", "incident-xyz")
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("8", 32)
	tok := computeVerifyToken(secret, challengeID, "alice", "approved", "", "")

	var sawReason string
	f := &fakeServerOpts{
		challengeID: challengeID,
		createHandler: func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			sawReason = body["reason"]
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":     challengeID,
				"user_code":        "X",
				"verification_url": "https://x",
				"expires_in":       60,
				"status":           "approved",
				"approval_token":   tok,
			})
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, _ := newTestClient(t, srv, secret)
	p.cfg.BreakglassEnabled = false
	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sawReason != "incident-xyz" {
		t.Errorf("reason not passed through: %q", sawReason)
	}
}

// guard: compile-time check that fakeServerOpts handler matches http.Handler.
var _ http.Handler = (&fakeServerOpts{}).handler()

// unused import guard for fmt when some tests get commented out.
var _ = fmt.Sprintf

// ── Breakglass fallback path helpers ──────────────────────────────────────────

// withFakeTTYPam overrides breakglass.OpenTTY and breakglass.ReadPasswordFn
// for the duration of the test so AuthenticateBreakglass can run without a
// real terminal.
func withFakeTTYPam(t *testing.T, password string) {
	t.Helper()
	origOpen := breakglass.OpenTTY
	origRead := breakglass.ReadPasswordFn
	t.Cleanup(func() {
		breakglass.OpenTTY = origOpen
		breakglass.ReadPasswordFn = origRead
	})
	dir := t.TempDir()
	breakglass.OpenTTY = func() (*os.File, error) {
		return os.OpenFile(filepath.Join(dir, "fake-tty"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	}
	breakglass.ReadPasswordFn = func(fd int) ([]byte, error) {
		return []byte(password), nil
	}
}

// overrideFileOwnerUIDPam stubs config.FileOwnerUID so tests running as
// non-root can pass the root-ownership check on breakglass hash files.
func overrideFileOwnerUIDPam(t *testing.T) {
	t.Helper()
	prev := config.FileOwnerUID
	config.FileOwnerUID = func(info os.FileInfo) (uint32, bool) { return 0, true }
	t.Cleanup(func() { config.FileOwnerUID = prev })
}

// seedBreakglassHashFile writes a valid bcrypt hash file at path for the given
// password, using cost 4 for speed. Includes the metadata header that
// ReadBreakglassHash expects.
func seedBreakglassHashFile(t *testing.T, path, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	content := fmt.Sprintf("# identree breakglass host=testhost type=random created=%s\n%s\n",
		time.Now().UTC().Format(time.RFC3339), string(hash))
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write hash file: %v", err)
	}
}

// ── Breakglass fallback: server unreachable on createChallenge ──────────────

func TestAuthenticate_BreakglassFallback_ServerUnreachable(t *testing.T) {
	if testing.Short() {
		t.Skip("breakglass retry loop takes ~10s")
	}

	overrideFileOwnerUIDPam(t)
	usagePath := withBreakglassUsagePath(t)
	withFakeTTYPam(t, "bg-password-123")

	hashDir := t.TempDir()
	hashFile := filepath.Join(hashDir, "breakglass.hash")
	seedBreakglassHashFile(t, hashFile, "bg-password-123")

	// Start a TLS server and immediately close it so all connections fail
	// with a dial error (server unreachable).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := srv.URL
	srvClient := srv.Client()
	srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:         serverURL,
		SharedSecret:      "test-secret-32-bytes-long-xxxxxxxxx",
		PollInterval:      10 * time.Millisecond,
		Timeout:           2 * time.Second,
		BreakglassEnabled: true,
		BreakglassFile:    hashFile,
	}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srvClient

	buf := &bytes.Buffer{}
	prev := MessageWriter
	MessageWriter = buf
	t.Cleanup(func() { MessageWriter = prev })

	// Authenticate should succeed via breakglass fallback.
	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("expected breakglass success, got error: %v", err)
	}

	// Verify usage was recorded for phone-home.
	if _, err := os.Stat(usagePath); os.IsNotExist(err) {
		t.Errorf("expected breakglass usage file to be created at %s", usagePath)
	}
}

func TestAuthenticate_BreakglassFallback_WrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("breakglass retry loop takes ~10s")
	}

	overrideFileOwnerUIDPam(t)
	_ = withBreakglassUsagePath(t)
	withFakeTTYPam(t, "wrong-password")

	hashDir := t.TempDir()
	hashFile := filepath.Join(hashDir, "breakglass.hash")
	seedBreakglassHashFile(t, hashFile, "correct-password")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := srv.URL
	srvClient := srv.Client()
	srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:         serverURL,
		SharedSecret:      "test-secret-32-bytes-long-xxxxxxxxx",
		PollInterval:      10 * time.Millisecond,
		Timeout:           2 * time.Second,
		BreakglassEnabled: true,
		BreakglassFile:    hashFile,
	}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srvClient

	buf := &bytes.Buffer{}
	prev := MessageWriter
	MessageWriter = buf
	t.Cleanup(func() { MessageWriter = prev })

	err = p.Authenticate("alice")
	if err == nil {
		t.Fatal("expected error for wrong breakglass password")
	}
	if !strings.Contains(err.Error(), "break-glass authentication failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAuthenticate_BreakglassFallback_Disabled(t *testing.T) {
	// Server unreachable but breakglass disabled: should return the
	// connection error without falling back.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := srv.URL
	srvClient := srv.Client()
	srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:         serverURL,
		SharedSecret:      "test-secret-32-bytes-long-xxxxxxxxx",
		PollInterval:      10 * time.Millisecond,
		Timeout:           time.Second,
		BreakglassEnabled: false,
	}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srvClient

	buf := &bytes.Buffer{}
	prev := MessageWriter
	MessageWriter = buf
	t.Cleanup(func() { MessageWriter = prev })

	err = p.Authenticate("alice")
	if err == nil {
		t.Fatal("expected error when server unreachable and breakglass disabled")
	}
	// Should be a connection error, not breakglass-related.
	if strings.Contains(err.Error(), "break-glass") {
		t.Errorf("should not attempt breakglass when disabled: %v", err)
	}
}

func TestAuthenticate_BreakglassFallback_NoHashFile(t *testing.T) {
	// Server unreachable, breakglass enabled, but no hash file: should not
	// attempt breakglass fallback.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := srv.URL
	srvClient := srv.Client()
	srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:         serverURL,
		SharedSecret:      "test-secret-32-bytes-long-xxxxxxxxx",
		PollInterval:      10 * time.Millisecond,
		Timeout:           time.Second,
		BreakglassEnabled: true,
		BreakglassFile:    filepath.Join(t.TempDir(), "nonexistent.hash"),
	}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srvClient

	buf := &bytes.Buffer{}
	prev := MessageWriter
	MessageWriter = buf
	t.Cleanup(func() { MessageWriter = prev })

	err = p.Authenticate("alice")
	if err == nil {
		t.Fatal("expected error when server unreachable and no hash file")
	}
	if strings.Contains(err.Error(), "break-glass") {
		t.Errorf("should not attempt breakglass without hash file: %v", err)
	}
}

func TestAuthenticate_BreakglassFallback_ServerRecoversDuringRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("breakglass retry loop takes ~5s")
	}

	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("a", 32)
	approvalToken := computeVerifyToken(secret, challengeID, "alice", "approved", "", "")

	// Single server: returns 503 for the first request (triggers unreachable
	// path), then serves normally on subsequent requests. This avoids
	// concurrent field mutation on the PAMClient.
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/challenge":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":     challengeID,
				"user_code":        "ABCD-1234",
				"verification_url": "https://example/approve",
				"expires_in":       120,
				"status":           "approved",
				"approval_token":   approvalToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	hashDir := t.TempDir()
	hashFile := filepath.Join(hashDir, "breakglass.hash")
	seedBreakglassHashFile(t, hashFile, "bg-pw")
	overrideFileOwnerUIDPam(t)
	withFakeTTYPam(t, "bg-pw")

	cfg := &config.ClientConfig{
		ServerURL:         srv.URL,
		SharedSecret:      secret,
		PollInterval:      10 * time.Millisecond,
		Timeout:           30 * time.Second,
		BreakglassEnabled: true,
		BreakglassFile:    hashFile,
	}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srv.Client()

	buf := &bytes.Buffer{}
	prev := MessageWriter
	MessageWriter = buf
	t.Cleanup(func() { MessageWriter = prev })

	err = p.Authenticate("alice")
	if err != nil {
		t.Fatalf("expected success after server recovery, got: %v", err)
	}
}

func TestAuthenticate_BreakglassReport_PhoneHomeBeforeChallenge(t *testing.T) {
	// When a breakglass usage record file exists from a previous offline auth,
	// the next Authenticate call should report it to the server before creating
	// a new challenge.
	usagePath := withBreakglassUsagePath(t)
	recordBreakglassUsage("host1", "alice")

	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("1", 32)
	approvalToken := computeVerifyToken(secret, challengeID, "alice", "approved", "", "")

	var reported atomic.Int32
	f := &fakeServerOpts{
		challengeID: challengeID,
		createHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":     challengeID,
				"user_code":        "XXXX-1234",
				"verification_url": "https://example/approve",
				"expires_in":       120,
				"status":           "approved",
				"approval_token":   approvalToken,
			})
		},
		reportHandler: func(w http.ResponseWriter, r *http.Request) {
			reported.Add(1)
			var rec struct {
				Hostname  string `json:"hostname"`
				Username  string `json:"username"`
				Timestamp int64  `json:"timestamp"`
			}
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				t.Errorf("decode report: %v", err)
			}
			if rec.Username != "alice" || rec.Hostname != "host1" {
				t.Errorf("unexpected report: %+v", rec)
			}
			w.WriteHeader(http.StatusOK)
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, buf := newTestClient(t, srv, secret)
	p.cfg.BreakglassEnabled = false

	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if reported.Load() != 1 {
		t.Errorf("expected 1 breakglass report, got %d", reported.Load())
	}
	// Usage file should be deleted after successful report.
	if _, err := os.Stat(usagePath); !os.IsNotExist(err) {
		t.Errorf("usage file should be deleted after report")
	}
	_ = buf
}

func TestAuthenticate_BreakglassReport_MultipleRecords(t *testing.T) {
	// Multiple breakglass usage records should all be reported.
	_ = withBreakglassUsagePath(t)
	recordBreakglassUsage("host1", "alice")
	recordBreakglassUsage("host2", "bob")

	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("2", 32)
	approvalToken := computeVerifyToken(secret, challengeID, "alice", "approved", "", "")

	var reported atomic.Int32
	f := &fakeServerOpts{
		challengeID: challengeID,
		createHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":     challengeID,
				"user_code":        "XXXX-1234",
				"verification_url": "https://example/approve",
				"expires_in":       120,
				"status":           "approved",
				"approval_token":   approvalToken,
			})
		},
		reportHandler: func(w http.ResponseWriter, r *http.Request) {
			reported.Add(1)
			w.WriteHeader(http.StatusOK)
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, _ := newTestClient(t, srv, secret)
	p.cfg.BreakglassEnabled = false

	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if reported.Load() != 2 {
		t.Errorf("expected 2 breakglass reports, got %d", reported.Load())
	}
}

func TestAuthenticate_BreakglassRotateBeforeOnAutoApproval(t *testing.T) {
	// When the server returns rotate_breakglass_before in an auto-approved
	// challenge, Authenticate should parse it and pass it to MaybeRotateBreakglass.
	// We verify the field is present in the challenge response.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("3", 32)
	rotateBefore := "2025-01-01T00:00:00Z"
	approvalToken := computeVerifyToken(secret, challengeID, "alice", "approved", rotateBefore, "")

	f := &fakeServerOpts{
		challengeID: challengeID,
		createHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":             challengeID,
				"user_code":                "XXXX-1234",
				"verification_url":         "https://example/approve",
				"expires_in":               120,
				"status":                   "approved",
				"approval_token":           approvalToken,
				"rotate_breakglass_before": rotateBefore,
			})
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, buf := newTestClient(t, srv, secret)
	// Disable breakglass so MaybeRotateBreakglass is a no-op
	// (avoids file system side effects). The test validates the
	// rotateBefore field flows through without error.
	p.cfg.BreakglassEnabled = false

	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	_ = buf
}

func TestAuthenticate_BreakglassRevokeTokensBeforeOnAutoApproval(t *testing.T) {
	// When the server returns revoke_tokens_before in an auto-approved
	// challenge, Authenticate should handle cache invalidation.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("4", 32)
	revokeBefore := "2099-01-01T00:00:00Z"
	approvalToken := computeVerifyToken(secret, challengeID, "alice", "approved", "", revokeBefore)

	f := &fakeServerOpts{
		challengeID: challengeID,
		createHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":         challengeID,
				"user_code":            "XXXX-1234",
				"verification_url":     "https://example/approve",
				"expires_in":           120,
				"status":               "approved",
				"approval_token":       approvalToken,
				"revoke_tokens_before": revokeBefore,
			})
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	// Set up a token cache that will be invalidated.
	dir := t.TempDir()
	tc := &TokenCache{CacheDir: dir, Issuer: "https://idp", ClientID: "c", hostname: "testhost"}
	jwt := makeJWT(t, map[string]any{
		"exp":                time.Now().Add(time.Hour).Unix(),
		"preferred_username": "alice",
	})
	if err := tc.Write("alice", jwt); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	p, buf := newTestClient(t, srv, secret)
	p.tokenCache = tc

	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Token cache should have been deleted because revoke_tokens_before is in the future.
	if _, err := tc.ModTime("alice"); err == nil {
		t.Errorf("expected cache to be invalidated by revoke_tokens_before")
	}
	_ = buf
}

func TestAuthenticate_BreakglassClientConfigOverrides(t *testing.T) {
	// Verify that client_config overrides from the server are applied during
	// auto-approval, but that breakglass_enabled is preserved for rotation.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("5", 32)
	approvalToken := computeVerifyToken(secret, challengeID, "alice", "approved", "", "")

	f := &fakeServerOpts{
		challengeID: challengeID,
		createHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id":     challengeID,
				"user_code":        "XXXX-1234",
				"verification_url": "https://example/approve",
				"expires_in":       120,
				"status":           "approved",
				"approval_token":   approvalToken,
				"grace_remaining":  600,
				"client_config": map[string]any{
					"breakglass_password_type": "passphrase",
					"breakglass_rotation_days": 14,
				},
			})
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, buf := newTestClient(t, srv, secret)
	p.cfg.BreakglassEnabled = true
	p.cfg.BreakglassPasswordType = "random"
	p.cfg.BreakglassRotationDays = 30

	if err := p.Authenticate("alice"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Verify client_config was applied.
	if p.cfg.BreakglassPasswordType != "passphrase" {
		t.Errorf("BreakglassPasswordType = %q; want passphrase", p.cfg.BreakglassPasswordType)
	}
	if p.cfg.BreakglassRotationDays != 14 {
		t.Errorf("BreakglassRotationDays = %d; want 14", p.cfg.BreakglassRotationDays)
	}
	// Grace remaining should be shown.
	if !strings.Contains(buf.String(), "10m") {
		t.Errorf("expected grace duration in output: %q", buf.String())
	}
}

func TestAuthenticate_BreakglassNotTriggeredFor403(t *testing.T) {
	// A 403 from the server indicates the server is reachable but rejecting
	// the request. Breakglass must NOT be triggered.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/challenge" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	hashDir := t.TempDir()
	hashFile := filepath.Join(hashDir, "breakglass.hash")
	seedBreakglassHashFile(t, hashFile, "bg-pw")
	overrideFileOwnerUIDPam(t)
	withFakeTTYPam(t, "bg-pw")

	cfg := &config.ClientConfig{
		ServerURL:         srv.URL,
		SharedSecret:      "test-secret-32-bytes-long-xxxxxxxxx",
		PollInterval:      10 * time.Millisecond,
		Timeout:           time.Second,
		BreakglassEnabled: true,
		BreakglassFile:    hashFile,
	}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srv.Client()

	buf := &bytes.Buffer{}
	prev := MessageWriter
	MessageWriter = buf
	t.Cleanup(func() { MessageWriter = prev })

	err = p.Authenticate("alice")
	if err == nil {
		t.Fatal("expected error for 403")
	}
	// Should be "authentication failed", not "break-glass".
	if strings.Contains(err.Error(), "break-glass") {
		t.Errorf("breakglass should not trigger for reachable server (403): %v", err)
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected 'authentication failed' error, got: %v", err)
	}
}

func TestAuthenticate_BreakglassNotTriggeredFor502WhenDisabled(t *testing.T) {
	// A 502 is treated as "server unreachable" by IsServerUnreachable, but if
	// breakglass is disabled, the fallback must NOT be attempted.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/challenge" {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &config.ClientConfig{
		ServerURL:         srv.URL,
		SharedSecret:      "test-secret-32-bytes-long-xxxxxxxxx",
		PollInterval:      10 * time.Millisecond,
		Timeout:           time.Second,
		BreakglassEnabled: false,
	}
	p, err := NewPAMClient(cfg, nil, "testhost")
	if err != nil {
		t.Fatalf("NewPAMClient: %v", err)
	}
	p.client = srv.Client()

	buf := &bytes.Buffer{}
	prev := MessageWriter
	MessageWriter = buf
	t.Cleanup(func() { MessageWriter = prev })

	err = p.Authenticate("alice")
	if err == nil {
		t.Fatal("expected error for 502 with breakglass disabled")
	}
	if strings.Contains(err.Error(), "break-glass") {
		t.Errorf("breakglass should not trigger when disabled: %v", err)
	}
}

func TestAuthenticate_ServerError_Timeout(t *testing.T) {
	// When polling times out (no approval within cfg.Timeout), the function
	// should return a timeout error.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("6", 32)

	f := &fakeServerOpts{
		challengeID: challengeID,
		pollSequence: []func(http.ResponseWriter, *http.Request){
			// Always pending.
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending", "expires_in": 60})
			},
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, _ := newTestClient(t, srv, secret)
	p.cfg.Timeout = 200 * time.Millisecond
	p.cfg.PollInterval = 20 * time.Millisecond
	p.cfg.BreakglassEnabled = false

	err := p.Authenticate("alice")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestAuthenticate_ServerExpiry_IgnoredWithHMAC(t *testing.T) {
	// When the server reports expired (404/410) but HMAC is configured, the
	// client should ignore the unverified expiry and keep polling until its
	// own timeout. This prevents a MITM from injecting fake expiry responses.
	const secret = "test-secret-32-bytes-long-xxxxxxxxx"
	challengeID := strings.Repeat("7", 32)

	f := &fakeServerOpts{
		challengeID: challengeID,
		pollSequence: []func(http.ResponseWriter, *http.Request){
			// Return 404 (server expired) on every poll.
			func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			},
		},
	}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	p, _ := newTestClient(t, srv, secret)
	p.cfg.Timeout = 300 * time.Millisecond
	p.cfg.PollInterval = 20 * time.Millisecond
	p.cfg.BreakglassEnabled = false

	err := p.Authenticate("alice")
	// Should timeout, NOT report "expired".
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout (ignoring unverified expiry), got: %v", err)
	}
}
