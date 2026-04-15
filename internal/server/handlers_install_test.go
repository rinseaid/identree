package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/signing"
)

func newInstallTestServer() *Server {
	pub, priv, _ := signing.GenerateSigningKey()
	return &Server{
		cfg: &config.ServerConfig{
			ExternalURL:  "https://auth.example.com",
			SharedSecret: "test-secret-that-is-long-enough-for-validation",
			LDAPBaseDN:   "dc=example,dc=com",
		},
		baseURL:           "https://auth.example.com",
		installSigningKey: priv,
		installVerifyKey:  pub,
	}
}

// buildInstallAdminReq creates a request with valid admin session + CSRF headers.
func buildInstallAdminReq(s *Server, method, path string, body *bytes.Buffer) *http.Request {
	secret := s.hmacBase()
	ts := time.Now().Unix()
	csrfTs := fmt.Sprintf("%d", ts)
	csrfToken := computeCSRFToken(secret, "testadmin", csrfTs)
	sessionCookie := makeCookie(secret, "testadmin", "admin", ts)

	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, body)
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.Header.Set("X-CSRF-Ts", csrfTs)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	r.RemoteAddr = "10.0.0.1:12345"
	return r
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

func TestHandleInstallScript_Static(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	w := httptest.NewRecorder()
	s.handleInstallScript(w, r)

	body := w.Body.String()
	// The static script should NOT contain deployment-specific values.
	if strings.Contains(body, "auth.example.com") {
		t.Error("static install script should not contain deployment-specific URLs")
	}
	// It should reference install-config.json for runtime config.
	if !strings.Contains(body, "install-config.json") {
		t.Error("static install script should reference install-config.json")
	}
	// It should take a URL as $1.
	if !strings.Contains(body, "CONFIG_URL") {
		t.Error("static install script should accept CONFIG_URL as argument")
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
	// Static script should not contain deployment-specific URLs.
	if strings.Contains(string(script), s.installServerURL()) {
		t.Error("static install script should not embed the server URL")
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

	// Verify the signature matches the served script.
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

// ── Install config JSON endpoint tests ──────────────────────────────────────

func TestHandleInstallConfig_OK(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/install-config.json", nil)
	r.Header.Set("X-Shared-Secret", s.cfg.SharedSecret)
	w := httptest.NewRecorder()
	s.handleInstallConfig(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}

	var cfg installConfigJSON
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if cfg.ServerURL != "https://auth.example.com" {
		t.Errorf("expected server_url=https://auth.example.com, got %q", cfg.ServerURL)
	}
	if cfg.LDAPBaseDN != "dc=example,dc=com" {
		t.Errorf("expected ldap_base_dn=dc=example,dc=com, got %q", cfg.LDAPBaseDN)
	}
}

func TestHandleInstallConfig_Unauthorized(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/install-config.json", nil)
	w := httptest.NewRecorder()
	s.handleInstallConfig(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without secret, got %d", w.Code)
	}
}

func TestHandleInstallConfig_WrongSecret(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/install-config.json", nil)
	r.Header.Set("X-Shared-Secret", "wrong-secret")
	w := httptest.NewRecorder()
	s.handleInstallConfig(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong secret, got %d", w.Code)
	}
}

func TestHandleInstallConfig_MethodNotAllowed(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodPost, "/install-config.json", nil)
	w := httptest.NewRecorder()
	s.handleInstallConfig(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleInstallConfig_InstallURLOmittedWhenSame(t *testing.T) {
	s := newInstallTestServer()
	// When InstallURL == ExternalURL, install_url should be omitted.
	s.cfg.InstallURL = s.cfg.ExternalURL

	r := httptest.NewRequest(http.MethodGet, "/install-config.json", nil)
	r.Header.Set("X-Shared-Secret", s.cfg.SharedSecret)
	w := httptest.NewRecorder()
	s.handleInstallConfig(w, r)

	var cfg installConfigJSON
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if cfg.InstallURL != "" {
		t.Errorf("expected install_url to be omitted when same as external URL, got %q", cfg.InstallURL)
	}
}

func TestHandleInstallConfig_InstallURLIncludedWhenDifferent(t *testing.T) {
	s := newInstallTestServer()
	s.cfg.InstallURL = "https://install.example.com"

	r := httptest.NewRequest(http.MethodGet, "/install-config.json", nil)
	r.Header.Set("X-Shared-Secret", s.cfg.SharedSecret)
	w := httptest.NewRecorder()
	s.handleInstallConfig(w, r)

	var cfg installConfigJSON
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if cfg.InstallURL != "https://install.example.com" {
		t.Errorf("expected install_url=https://install.example.com, got %q", cfg.InstallURL)
	}
}

// ── Custom install script admin API tests ───────────────────────────────────

func TestHandleAdminInstallScript_GetNoCustom(t *testing.T) {
	s := newInstallTestServer()
	s.cfg.SessionSecret = s.cfg.SharedSecret

	r := buildInstallAdminReq(s, http.MethodGet, "/api/admin/install-script", nil)
	w := httptest.NewRecorder()
	s.handleAdminInstallScript(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no custom script, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleAdminInstallScript_UploadInvalidSignature(t *testing.T) {
	s := newInstallTestServer()
	s.cfg.SessionSecret = s.cfg.SharedSecret

	customScript := []byte("#!/bin/bash\necho custom installer\n")

	// Create multipart form with bad signature.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("script", "custom-install.sh")
	fw.Write(customScript)
	mw.WriteField("signature", "invalid-signature-data")
	mw.Close()

	r := buildInstallAdminReq(s, http.MethodPost, "/api/admin/install-script", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	s.handleAdminInstallScript(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid signature, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid signature" {
		t.Errorf("expected 'invalid signature' error, got %q", resp["error"])
	}
}

func TestHandleAdminInstallScript_UploadMissingSignature(t *testing.T) {
	s := newInstallTestServer()
	s.cfg.SessionSecret = s.cfg.SharedSecret

	customScript := []byte("#!/bin/bash\necho custom installer\n")

	// Create multipart form with no signature.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("script", "custom-install.sh")
	fw.Write(customScript)
	mw.Close()

	r := buildInstallAdminReq(s, http.MethodPost, "/api/admin/install-script", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	s.handleAdminInstallScript(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing signature, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "missing signature" {
		t.Errorf("expected 'missing signature' error, got %q", resp["error"])
	}
}

func TestHandleAdminInstallScript_Unauthorized(t *testing.T) {
	s := newInstallTestServer()

	r := httptest.NewRequest(http.MethodGet, "/api/admin/install-script", nil)
	w := httptest.NewRecorder()
	s.handleAdminInstallScript(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without session, got %d", w.Code)
	}
}

// TestInstallScript_DefaultIsStatic verifies the default install script is
// the static one with no deployment-specific values.
func TestInstallScript_DefaultIsStatic(t *testing.T) {
	s := newInstallTestServer()

	script := s.installScript()
	if !strings.Contains(string(script), "identree static installer") {
		t.Error("expected default static installer")
	}
	if !strings.Contains(string(script), "install-config.json") {
		t.Error("expected reference to install-config.json")
	}
}

// TestSignScriptRoundTrip verifies the sign-script CLI integration through the
// signing package functions (since we can't easily invoke the main binary).
func TestSignScriptRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Generate a keypair.
	pubPath := dir + "/test.pub"
	privPath := dir + "/test.key"
	pub, _, err := signing.LoadOrGenerateSigningKey(pubPath, privPath)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Create a test script.
	scriptContent := []byte("#!/bin/bash\necho hello\n")

	// Sign using the same functions the CLI uses.
	loadedPriv, err := signing.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	sig := signing.SignScript(loadedPriv, scriptContent)
	if sig == "" {
		t.Fatal("SignScript returned empty signature")
	}

	// Write sig file.
	sigPath := dir + "/test.sh.sig"
	os.WriteFile(sigPath, []byte(sig+"\n"), 0644)

	// Verify using public key.
	if !signing.VerifyScript(pub, scriptContent, sig) {
		t.Error("signature verification failed for script signed with LoadPrivateKey")
	}

	// Verify the signature file can be loaded back.
	sigData, _ := os.ReadFile(sigPath)
	sigStr := strings.TrimSpace(string(sigData))
	if !signing.VerifyScript(pub, scriptContent, sigStr) {
		t.Error("signature from file did not verify")
	}
}

// TestHandleAdminInstallScript_DeleteNoOp verifies that deleting when no
// custom script exists returns success.
func TestHandleAdminInstallScript_DeleteNoOp(t *testing.T) {
	s := newInstallTestServer()
	s.cfg.SessionSecret = s.cfg.SharedSecret

	r := buildInstallAdminReq(s, http.MethodDelete, "/api/admin/install-script", nil)
	w := httptest.NewRecorder()
	s.handleAdminInstallScript(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for delete (even no-op), got %d: %s", w.Code, w.Body.String())
	}
}
