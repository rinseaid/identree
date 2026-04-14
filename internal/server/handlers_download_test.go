package server

import (
	"net/http"
	"net/http/httptest"
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
