package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rinseaid/identree/internal/config"
)

func newInstallTestServer() *Server {
	return &Server{
		cfg: &config.ServerConfig{
			ExternalURL: "https://auth.example.com",
		},
		baseURL: "https://auth.example.com",
	}
}

func TestInstallServerURL_Default(t *testing.T) {
	s := newInstallTestServer()
	got := s.installServerURL()
	if got != "https://auth.example.com" {
		t.Errorf("expected baseURL, got %q", got)
	}
}

func TestInstallServerURL_WithInstallURL(t *testing.T) {
	s := newInstallTestServer()
	s.cfg.InstallURL = "https://install.example.com/"
	got := s.installServerURL()
	if got != "https://install.example.com" {
		t.Errorf("expected InstallURL (stripped trailing slash), got %q", got)
	}
}

func TestHandleInstallScript_OK(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	w := httptest.NewRecorder()
	s.handleInstallScript(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "shellscript") {
		t.Errorf("expected shellscript content type, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "#!/") {
		t.Error("expected shell script shebang in response")
	}
}

func TestHandleInstallScript_MethodNotAllowed(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodPost, "/install.sh", nil)
	w := httptest.NewRecorder()
	s.handleInstallScript(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleUninstallScript_OK(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/api/deploy/uninstall-script", nil)
	w := httptest.NewRecorder()
	s.handleUninstallScript(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "#!/") {
		t.Error("expected shell script content")
	}
}

func TestHandleUninstallScript_MethodNotAllowed(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodPost, "/api/deploy/uninstall-script", nil)
	w := httptest.NewRecorder()
	s.handleUninstallScript(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestRenderInstallScript(t *testing.T) {
	s := newInstallTestServer()

	script, err := s.renderInstallScript()
	if err != nil {
		t.Fatalf("renderInstallScript: %v", err)
	}
	if len(script) == 0 {
		t.Error("expected non-empty install script")
	}
	if !strings.Contains(string(script), s.installServerURL()) {
		t.Error("expected install script to contain the server URL")
	}
}
