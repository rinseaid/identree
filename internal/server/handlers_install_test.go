package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/signing"
)

func newInstallTestServer() *Server {
	pub, priv, _ := signing.GenerateSigningKey()
	return &Server{
		cfg: &config.ServerConfig{
			ExternalURL: "https://auth.example.com",
		},
		baseURL:           "https://auth.example.com",
		installSigningKey: priv,
		installVerifyKey:  pub,
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

func TestHandleInstallScriptSig_OK(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/install.sh.sig", nil)
	w := httptest.NewRecorder()
	s.handleInstallScriptSig(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}

	sig := w.Body.String()
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	// Verify the signature matches the rendered script.
	script, err := s.renderInstallScript()
	if err != nil {
		t.Fatalf("renderInstallScript: %v", err)
	}
	if !signing.VerifyScript(s.installVerifyKey, script, sig) {
		t.Error("signature does not verify against rendered script")
	}
}

func TestHandleInstallScriptSig_MethodNotAllowed(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodPost, "/install.sh.sig", nil)
	w := httptest.NewRecorder()
	s.handleInstallScriptSig(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleInstallPubKey_OK(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/install.pub", nil)
	w := httptest.NewRecorder()
	s.handleInstallPubKey(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "pem") {
		t.Errorf("expected PEM content type, got %q", ct)
	}

	// Should be parseable as a public key.
	parsed, err := signing.ParsePublicKeyPEM(w.Body.Bytes())
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if !s.installVerifyKey.Equal(parsed) {
		t.Error("served public key does not match server's key")
	}
}

func TestHandleInstallPubKey_MethodNotAllowed(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodPost, "/install.pub", nil)
	w := httptest.NewRecorder()
	s.handleInstallPubKey(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleInstallScriptSig_NoKey(t *testing.T) {
	s := newInstallTestServer()
	s.installSigningKey = nil

	r := httptest.NewRequest(http.MethodGet, "/install.sh.sig", nil)
	w := httptest.NewRecorder()
	s.handleInstallScriptSig(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when signing key is nil, got %d", w.Code)
	}
}

func TestHandleInstallPubKey_NoKey(t *testing.T) {
	s := newInstallTestServer()
	s.installVerifyKey = nil

	r := httptest.NewRequest(http.MethodGet, "/install.pub", nil)
	w := httptest.NewRecorder()
	s.handleInstallPubKey(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when verify key is nil, got %d", w.Code)
	}
}

// TestInstallScriptSignatureIntegrity verifies the full flow: render script,
// sign it, serve the signature, and verify with the served public key.
func TestInstallScriptSignatureIntegrity(t *testing.T) {
	s := newInstallTestServer()

	// Get the script.
	scriptReq := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	scriptW := httptest.NewRecorder()
	s.handleInstallScript(scriptW, scriptReq)
	if scriptW.Code != http.StatusOK {
		t.Fatalf("install.sh: expected 200, got %d", scriptW.Code)
	}
	script := scriptW.Body.Bytes()

	// Get the signature.
	sigReq := httptest.NewRequest(http.MethodGet, "/install.sh.sig", nil)
	sigW := httptest.NewRecorder()
	s.handleInstallScriptSig(sigW, sigReq)
	if sigW.Code != http.StatusOK {
		t.Fatalf("install.sh.sig: expected 200, got %d", sigW.Code)
	}
	sig := sigW.Body.String()

	// Get the public key.
	pubReq := httptest.NewRequest(http.MethodGet, "/install.pub", nil)
	pubW := httptest.NewRecorder()
	s.handleInstallPubKey(pubW, pubReq)
	if pubW.Code != http.StatusOK {
		t.Fatalf("install.pub: expected 200, got %d", pubW.Code)
	}

	pub, err := signing.ParsePublicKeyPEM(pubW.Body.Bytes())
	if err != nil {
		t.Fatalf("parse served public key: %v", err)
	}

	// Verify: signature of served script with served public key.
	if !signing.VerifyScript(pub, script, sig) {
		t.Error("end-to-end verification failed: signature does not match script")
	}

	// Tamper with the script and verify failure.
	tampered := append([]byte("# injected malicious code\n"), script...)
	if signing.VerifyScript(pub, tampered, sig) {
		t.Error("verification should fail for tampered script")
	}
}
