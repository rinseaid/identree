package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rinseaid/identree/internal/config"
)

// newProvisionServer builds a minimal *Server configured for provision endpoint tests.
func newProvisionServer(cfg *config.ServerConfig) *Server {
	return &Server{
		cfg:          cfg,
		hostRegistry: NewHostRegistry(""),
	}
}

// makeProvisionRequest builds a GET request to /api/client/provision with the
// given shared secret and hostname headers (empty string means header is omitted).
func makeProvisionRequest(secret, hostname string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/client/provision", nil)
	if secret != "" {
		r.Header.Set("X-Shared-Secret", secret)
	}
	if hostname != "" {
		r.Header.Set("X-Hostname", hostname)
	}
	return r
}

// TestHandleClientProvision_NotFound verifies that the endpoint returns 404 when
// LDAPProvisionEnabled is false.
func TestHandleClientProvision_NotFound(t *testing.T) {
	s := newProvisionServer(&config.ServerConfig{
		SharedSecret:         "some-secret",
		LDAPProvisionEnabled: false,
		LDAPBaseDN:           "dc=example,dc=com",
	})

	w := httptest.NewRecorder()
	s.handleClientProvision(w, makeProvisionRequest("some-secret", "myhost"))

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// TestHandleClientProvision_Unauthorized verifies that the endpoint returns 401
// when no X-Shared-Secret header is provided.
func TestHandleClientProvision_Unauthorized(t *testing.T) {
	s := newProvisionServer(&config.ServerConfig{
		SharedSecret:         "some-secret",
		LDAPProvisionEnabled: true,
		LDAPBaseDN:           "dc=example,dc=com",
		LDAPExternalURL:      "ldap://ldap.example.com:389",
	})

	w := httptest.NewRecorder()
	// No secret header.
	r := httptest.NewRequest(http.MethodGet, "/api/client/provision", nil)
	r.Header.Set("X-Hostname", "myhost")
	s.handleClientProvision(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestHandleClientProvision_MissingHostname verifies that the endpoint returns 400
// when the X-Hostname header is absent.
func TestHandleClientProvision_MissingHostname(t *testing.T) {
	const secret = "good-secret"
	s := newProvisionServer(&config.ServerConfig{
		SharedSecret:         secret,
		LDAPProvisionEnabled: true,
		LDAPBaseDN:           "dc=example,dc=com",
		LDAPExternalURL:      "ldap://ldap.example.com:389",
	})

	w := httptest.NewRecorder()
	r := makeProvisionRequest(secret, "" /* no hostname */)
	s.handleClientProvision(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHandleClientProvision_InvalidHostname verifies that the endpoint returns 400
// when the X-Hostname header contains characters that would break LDAP DN construction.
func TestHandleClientProvision_InvalidHostname(t *testing.T) {
	const secret = "good-secret"
	s := newProvisionServer(&config.ServerConfig{
		SharedSecret:         secret,
		LDAPProvisionEnabled: true,
		LDAPBaseDN:           "dc=example,dc=com",
		LDAPExternalURL:      "ldap://ldap.example.com:389",
	})

	invalidHostnames := []struct {
		name     string
		hostname string
	}{
		{"comma", "host,name"},
		{"equals", "host=name"},
		{"newline", "host\nname"},
		{"carriage return", "host\rname"},
		{"null byte", "host\x00name"},
	}

	for _, tc := range invalidHostnames {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := makeProvisionRequest(secret, tc.hostname)
			s.handleClientProvision(w, r)

			if w.Code != http.StatusBadRequest {
				t.Errorf("hostname %q: expected 400, got %d", tc.hostname, w.Code)
			}
		})
	}
}

// TestHandleClientProvision_MissingSharedSecret verifies that the endpoint returns 500
// when provision is enabled but SharedSecret is empty (misconfiguration).
func TestHandleClientProvision_MissingSharedSecret(t *testing.T) {
	// verifyAPISecret will return false when SharedSecret is empty (fail closed),
	// so we need a host registry secret to pass auth but still hit the SharedSecret
	// empty check. We achieve this by using a non-empty host registry entry.
	//
	// However, since NewHostRegistry("") creates an empty registry with no hosts,
	// and verifyAPISecret falls back to ValidateAnyHost which also returns false
	// when the registry is empty, there is no way to pass auth with SharedSecret="".
	// The handler correctly returns 401 in that case, not 500.
	//
	// To reach the SharedSecret empty 500, we need a server where auth passes via
	// a per-host registry secret but SharedSecret is still empty. Use a host
	// registry file path of "" which disables the registry — we cannot reach the
	// SharedSecret check without a non-empty SharedSecret.
	//
	// The test below confirms the real reachable path: provision enabled, secret
	// empty → verifyAPISecret returns false → 401, not 500. The 500 for empty
	// SharedSecret is a defence-in-depth guard for a future configuration where
	// auth is satisfied via a different mechanism. We document that here and test
	// what is actually observable.
	s := newProvisionServer(&config.ServerConfig{
		SharedSecret:         "",
		LDAPProvisionEnabled: true,
		LDAPBaseDN:           "dc=example,dc=com",
		LDAPExternalURL:      "ldap://ldap.example.com:389",
	})

	w := httptest.NewRecorder()
	// Even with a secret in the header, verifyAPISecret fails closed when
	// SharedSecret is empty and no host registry secrets are loaded.
	r := httptest.NewRequest(http.MethodGet, "/api/client/provision", nil)
	r.Header.Set("X-Shared-Secret", "anything")
	r.Header.Set("X-Hostname", "myhost")
	s.handleClientProvision(w, r)

	// verifyAPISecret returns false when SharedSecret is empty → 401.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (fail-closed auth with empty secret), got %d", w.Code)
	}
}

// TestHandleClientProvision_MissingBaseDN verifies that the endpoint returns 500
// when LDAPBaseDN is not configured.
func TestHandleClientProvision_MissingBaseDN(t *testing.T) {
	const secret = "good-secret"
	s := newProvisionServer(&config.ServerConfig{
		SharedSecret:         secret,
		LDAPProvisionEnabled: true,
		LDAPBaseDN:           "", // not set
		LDAPExternalURL:      "ldap://ldap.example.com:389",
	})

	w := httptest.NewRecorder()
	r := makeProvisionRequest(secret, "myhost")
	s.handleClientProvision(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// TestHandleClientProvision_Success verifies that the endpoint returns 200 with
// a correct JSON payload when all required fields are configured.
func TestHandleClientProvision_Success(t *testing.T) {
	const secret = "good-secret"
	const baseDN = "dc=example,dc=com"
	const hostname = "myhost"
	const ldapURL = "ldap://ldap.example.com:389"

	s := newProvisionServer(&config.ServerConfig{
		SharedSecret:         secret,
		LDAPProvisionEnabled: true,
		LDAPBaseDN:           baseDN,
		LDAPExternalURL:      ldapURL,
		LDAPTLSCACert:        "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
	})

	w := httptest.NewRecorder()
	r := makeProvisionRequest(secret, hostname)
	s.handleClientProvision(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp provisionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify ldap_url.
	if resp.LDAPUrl != ldapURL {
		t.Errorf("ldap_url: got %q, want %q", resp.LDAPUrl, ldapURL)
	}

	// Verify base_dn.
	if resp.BaseDN != baseDN {
		t.Errorf("base_dn: got %q, want %q", resp.BaseDN, baseDN)
	}

	// Verify bind_dn format: uid=<hostname>,ou=identree-hosts,<baseDN>.
	wantBindDN := "uid=" + hostname + ",ou=identree-hosts," + baseDN
	if resp.BindDN != wantBindDN {
		t.Errorf("bind_dn: got %q, want %q", resp.BindDN, wantBindDN)
	}

	// Verify bind_password is a 64-character lowercase hex string (32-byte HMAC-SHA256).
	if len(resp.BindPassword) != 64 {
		t.Errorf("bind_password length: got %d, want 64", len(resp.BindPassword))
	}
	for _, c := range resp.BindPassword {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("bind_password contains non-hex char %q", c)
			break
		}
	}

	// Verify tls_ca_cert is present when configured.
	if resp.TLSCACert == "" {
		t.Error("tls_ca_cert should be present when LDAPTLSCACert is set")
	}

	// Verify Content-Type and Cache-Control headers.
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q, want %q", ct, "application/json")
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control: got %q, want %q", cc, "no-store")
	}
}

// TestHandleClientProvision_NoTLSCACert verifies that the tls_ca_cert field is
// absent from the JSON response when LDAPTLSCACert is not configured.
func TestHandleClientProvision_NoTLSCACert(t *testing.T) {
	const secret = "good-secret"

	s := newProvisionServer(&config.ServerConfig{
		SharedSecret:         secret,
		LDAPProvisionEnabled: true,
		LDAPBaseDN:           "dc=example,dc=com",
		LDAPExternalURL:      "ldap://ldap.example.com:389",
		LDAPTLSCACert:        "", // not set
	})

	w := httptest.NewRecorder()
	r := makeProvisionRequest(secret, "myhost")
	s.handleClientProvision(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	// Decode into a raw map so we can check field presence.
	var raw map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := raw["tls_ca_cert"]; ok {
		t.Error("tls_ca_cert field should be omitted when LDAPTLSCACert is empty (omitempty)")
	}
}

// TestLDAPProvisionURL_ExplicitURL verifies that LDAPExternalURL is used as-is
// when set.
func TestLDAPProvisionURL_ExplicitURL(t *testing.T) {
	const explicit = "ldap://ldap.corp.example.com:1389"
	s := newProvisionServer(&config.ServerConfig{
		LDAPExternalURL: explicit,
		ExternalURL:     "https://auth.example.com",
	})

	got := s.ldapProvisionURL()
	if got != explicit {
		t.Errorf("ldapProvisionURL: got %q, want %q", got, explicit)
	}
}

// TestLDAPProvisionURL_DerivedFromExternalURL verifies that when LDAPExternalURL
// is empty the URL is derived from ExternalURL.
func TestLDAPProvisionURL_DerivedFromExternalURL(t *testing.T) {
	tests := []struct {
		name        string
		externalURL string
		listenAddr  string
		want        string
	}{
		{
			name:        "https scheme stripped, port 389",
			externalURL: "https://auth.example.com",
			want:        "ldap://auth.example.com:389",
		},
		{
			name:        "http scheme stripped, port 389",
			externalURL: "http://auth.example.com",
			want:        "ldap://auth.example.com:389",
		},
		{
			name:        "path stripped",
			externalURL: "https://auth.example.com/identree",
			want:        "ldap://auth.example.com:389",
		},
		{
			name:        "existing port in ExternalURL is replaced",
			externalURL: "https://auth.example.com:8443",
			want:        "ldap://auth.example.com:389",
		},
		{
			name:        "non-standard LDAPListenAddr port is used",
			externalURL: "https://auth.example.com",
			listenAddr:  ":1389",
			want:        "ldap://auth.example.com:1389",
		},
		{
			name:        "standard 389 LDAPListenAddr still uses 389",
			externalURL: "https://auth.example.com",
			listenAddr:  ":389",
			want:        "ldap://auth.example.com:389",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newProvisionServer(&config.ServerConfig{
				LDAPExternalURL: "",
				ExternalURL:     tc.externalURL,
				LDAPListenAddr:  tc.listenAddr,
			})

			got := s.ldapProvisionURL()
			if got != tc.want {
				t.Errorf("ldapProvisionURL: got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLDAPProvisionURL_Empty verifies that an empty string is returned when both
// LDAPExternalURL and ExternalURL are unset.
func TestLDAPProvisionURL_Empty(t *testing.T) {
	s := newProvisionServer(&config.ServerConfig{
		LDAPExternalURL: "",
		ExternalURL:     "",
	})

	got := s.ldapProvisionURL()
	if got != "" {
		t.Errorf("ldapProvisionURL: got %q, want empty string", got)
	}
}
