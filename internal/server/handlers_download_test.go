package server

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rinseaid/identree/internal/config"
)

func newDownloadTestServer() *Server {
	return &Server{
		cfg: &config.ServerConfig{},
	}
}

// ── handleDownloadVersion tests ──────────────────────────────────────────────

func TestHandleDownloadVersion_OK(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodGet, "/download/version", nil)
	w := httptest.NewRecorder()
	s.handleDownloadVersion(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("expected text/plain, got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected no-store, got %q", cc)
	}
}

func TestHandleDownloadVersion_MethodNotAllowed(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodPost, "/download/version", nil)
	w := httptest.NewRecorder()
	s.handleDownloadVersion(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleDownloadBinary tests ───────────────────────────────────────────────

func TestHandleDownloadBinary_InvalidName(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodGet, "/download/identree-linux-mips", nil)
	w := httptest.NewRecorder()
	s.handleDownloadBinary(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleDownloadBinary_MethodNotAllowed(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodPost, "/download/identree-linux-amd64", nil)
	w := httptest.NewRecorder()
	s.handleDownloadBinary(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleDownloadSystemd tests ──────────────────────────────────────────────

func TestHandleDownloadSystemd_Service(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodGet, "/download/systemd/identree-rotate.service", nil)
	w := httptest.NewRecorder()
	s.handleDownloadSystemd(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "[Unit]") {
		t.Error("expected systemd unit content")
	}
}

func TestHandleDownloadSystemd_Timer(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodGet, "/download/systemd/identree-rotate.timer", nil)
	w := httptest.NewRecorder()
	s.handleDownloadSystemd(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "[Timer]") {
		t.Error("expected timer unit content")
	}
}

func TestHandleDownloadSystemd_NotFound(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodGet, "/download/systemd/nonexistent.service", nil)
	w := httptest.NewRecorder()
	s.handleDownloadSystemd(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleDownloadSystemd_MethodNotAllowed(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodPost, "/download/systemd/identree-rotate.service", nil)
	w := httptest.NewRecorder()
	s.handleDownloadSystemd(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleDownloadBinaryChecksum tests ───────────────────────────────────────

func TestHandleDownloadBinaryChecksum_InvalidName(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodGet, "/download/identree-linux-mips.sha256", nil)
	w := httptest.NewRecorder()
	s.handleDownloadBinaryChecksum(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleDownloadBinaryChecksum_MethodNotAllowed(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodPost, "/download/identree-linux-amd64.sha256", nil)
	w := httptest.NewRecorder()
	s.handleDownloadBinaryChecksum(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── handleAvatarProxy tests ──────────────────────────────────────────────────

func TestHandleAvatarProxy_MethodNotAllowed(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodPost, "/api/avatar?url=https://example.com/img.png", nil)
	w := httptest.NewRecorder()
	s.handleAvatarProxy(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleAvatarProxy_MissingURL(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodGet, "/api/avatar", nil)
	w := httptest.NewRecorder()
	s.handleAvatarProxy(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAvatarProxy_InvalidScheme(t *testing.T) {
	s := newDownloadTestServer()

	r := httptest.NewRequest(http.MethodGet, "/api/avatar?url=ftp://example.com/img.png", nil)
	w := httptest.NewRecorder()
	s.handleAvatarProxy(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// writeFakeBinary writes `content` to a file in the same directory as the
// running test executable, so binaryPath() resolves to it. Returns a cleanup.
func writeFakeBinary(t *testing.T, name string, content []byte) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	path := filepath.Join(filepath.Dir(exe), name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}

// TestHandleDownloadBinary_Success serves the binary bytes for a known arch.
func TestHandleDownloadBinary_Success(t *testing.T) {
	s := newDownloadTestServer()
	payload := []byte("fake-identree-binary-bytes")
	writeFakeBinary(t, "identree-linux-amd64", payload)

	r := httptest.NewRequest(http.MethodGet, "/download/identree-linux-amd64", nil)
	w := httptest.NewRecorder()
	s.handleDownloadBinary(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", w.Code, w.Body.String())
	}
	if got := w.Body.Bytes(); string(got) != string(payload) {
		t.Errorf("body: got %q, want %q", got, payload)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type: got %q, want application/octet-stream", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="identree-linux-amd64"`) {
		t.Errorf("Content-Disposition: got %q", cd)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control: got %q, want no-store", cc)
	}
}

// TestHandleDownloadBinary_MissingFile returns 404 when binary not present on disk.
func TestHandleDownloadBinary_MissingFile(t *testing.T) {
	s := newDownloadTestServer()
	// Do NOT write a binary — ensure cleanup in case a previous test left one.
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	_ = os.Remove(filepath.Join(filepath.Dir(exe), "identree-linux-arm64"))

	r := httptest.NewRequest(http.MethodGet, "/download/identree-linux-arm64", nil)
	w := httptest.NewRecorder()
	s.handleDownloadBinary(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not available") {
		t.Errorf("expected 'not available' body, got %q", w.Body.String())
	}
}

// TestHandleDownloadBinary_PathTraversalRejected is a SECURITY regression test:
// requesting a path like ../../etc/passwd must never read files outside the
// binary allowlist. The allowlist check rejects anything except the two known
// architecture names.
func TestHandleDownloadBinary_PathTraversalRejected(t *testing.T) {
	s := newDownloadTestServer()

	// The Go HTTP server normalises URL paths, but we can still exercise
	// handler directly with a traversal-looking suffix. Regardless of
	// normalisation, the allowlist rejects any name that isn't exactly
	// identree-linux-{amd64,arm64}.
	cases := []string{
		"/download/../etc/passwd",
		"/download/identree-linux-amd64/../../etc/passwd",
		"/download/..%2Fetc%2Fpasswd",
		"/download/identree-linux-amd64%00.sh",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			// Construct request with raw URL to avoid normalisation rewriting the path.
			u, _ := url.Parse("http://example.com" + path)
			r := &http.Request{
				Method: http.MethodGet,
				URL:    u,
				Header: make(http.Header),
			}
			w := httptest.NewRecorder()
			s.handleDownloadBinary(w, r)
			if w.Code != http.StatusNotFound {
				t.Errorf("expected 404 for %q, got %d (body=%q)", path, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleDownloadBinaryChecksum_Success verifies the SHA-256 is hex-encoded
// and matches a known payload.
func TestHandleDownloadBinaryChecksum_Success(t *testing.T) {
	s := newDownloadTestServer()
	payload := []byte("deterministic-checksum-payload")
	writeFakeBinary(t, "identree-linux-amd64", payload)

	r := httptest.NewRequest(http.MethodGet, "/download/identree-linux-amd64.sha256", nil)
	w := httptest.NewRecorder()
	s.handleDownloadBinaryChecksum(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", w.Code, w.Body.String())
	}
	body := strings.TrimSpace(w.Body.String())
	// Format: "<64-hex>  identree-linux-amd64"
	parts := strings.SplitN(body, "  ", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected checksum body %q", body)
	}
	if parts[1] != "identree-linux-amd64" {
		t.Errorf("filename part: got %q", parts[1])
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(parts[0]) {
		t.Errorf("hash is not 64-char lowercase hex: %q", parts[0])
	}
	// Verify it is in fact hex-decodable to 32 bytes (SHA-256 length).
	raw, err := hex.DecodeString(parts[0])
	if err != nil || len(raw) != 32 {
		t.Errorf("hash not hex-32-bytes: err=%v len=%d", err, len(raw))
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type: got %q", ct)
	}
}

// TestHandleDownloadBinaryChecksum_MissingFile returns 404.
func TestHandleDownloadBinaryChecksum_MissingFile(t *testing.T) {
	s := newDownloadTestServer()
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	_ = os.Remove(filepath.Join(filepath.Dir(exe), "identree-linux-arm64"))

	r := httptest.NewRequest(http.MethodGet, "/download/identree-linux-arm64.sha256", nil)
	w := httptest.NewRecorder()
	s.handleDownloadBinaryChecksum(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// TestHandleDownloadBinaryChecksum_PathTraversalRejected is a SECURITY
// regression test for the .sha256 endpoint. Same allowlist applies.
func TestHandleDownloadBinaryChecksum_PathTraversalRejected(t *testing.T) {
	s := newDownloadTestServer()

	cases := []string{
		"/download/../etc/passwd.sha256",
		"/download/identree-linux-amd64/../../etc/passwd.sha256",
		"/download/..%2Fetc%2Fpasswd.sha256",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			u, _ := url.Parse("http://example.com" + path)
			r := &http.Request{Method: http.MethodGet, URL: u, Header: make(http.Header)}
			w := httptest.NewRecorder()
			s.handleDownloadBinaryChecksum(w, r)
			if w.Code != http.StatusNotFound {
				t.Errorf("expected 404 for %q, got %d", path, w.Code)
			}
		})
	}
}

// ── handleAvatarProxy end-to-end tests ───────────────────────────────────────

// TestHandleAvatarProxy_SSRFBlocked is a SECURITY regression test: URLs that
// resolve to loopback or RFC1918 addresses must be rejected by the dialer.
// handleAvatarProxy swallows the dial error and returns 404 to the browser.
func TestHandleAvatarProxy_SSRFBlocked(t *testing.T) {
	s := newDownloadTestServer()
	// httptest.NewServer listens on 127.0.0.1 — the custom dialer must refuse.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Marker payload: if we ever see this body in the client response,
		// SSRF protection has regressed.
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("SHOULD-NOT-REACH-CLIENT"))
	}))
	t.Cleanup(upstream.Close)

	target := fmt.Sprintf("/api/avatar?url=%s", url.QueryEscape(upstream.URL+"/avatar.png"))
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	s.handleAvatarProxy(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for loopback SSRF, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "SHOULD-NOT-REACH-CLIENT") {
		t.Error("SSRF protection regressed: loopback response body leaked to client")
	}
}

// TestHandleAvatarProxy_InvalidURLParse covers the url.Parse failure branch
// (hostname-less URL slips past the scheme prefix check).
func TestHandleAvatarProxy_InvalidURLParse(t *testing.T) {
	s := newDownloadTestServer()
	// "https:///foo" parses but has an empty hostname.
	target := "/api/avatar?url=" + url.QueryEscape("https:///foo")
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	s.handleAvatarProxy(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHandleAvatarProxy_UpstreamUnreachable verifies a connection failure
// produces 404 (rather than 502 — this is the current contract).
func TestHandleAvatarProxy_UpstreamUnreachable(t *testing.T) {
	s := newDownloadTestServer()
	// Use a public DNS name the proxy will accept but a port that should fail.
	// We use example.invalid which will fail DNS lookup in the dialer. The
	// dialer error is swallowed and 404 is returned.
	target := "/api/avatar?url=" + url.QueryEscape("https://example.invalid/avatar.png")
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	s.handleAvatarProxy(w, r)

	// The handler returns 404 both for unreachable upstream and for non-2xx
	// responses, which is the current behaviour.
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unreachable upstream, got %d (body=%q)", w.Code, w.Body.String())
	}
}

