package server

import (
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/randutil"
)

// samlMetadataTimeout limits how long we wait for IdP metadata fetches.
const samlMetadataTimeout = 30 * time.Second

// initSAML initializes the SAML Service Provider. Called from NewServer when
// AuthProtocol == "saml". Returns an error on failure.
func (s *Server) initSAML() error {
	cfg := s.cfg

	// Load or generate SP certificate and key.
	certPEM, keyPEM, err := loadOrGenerateSAMLCert(cfg.SAMLCertFile, cfg.SAMLKeyFile)
	if err != nil {
		return fmt.Errorf("SAML SP certificate: %w", err)
	}

	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("SAML SP key pair: %w", err)
	}

	// Parse the leaf certificate for the SP metadata.
	leafCert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("SAML SP certificate parse: %w", err)
	}

	rootURL, err := url.Parse(strings.TrimRight(cfg.ExternalURL, "/"))
	if err != nil {
		return fmt.Errorf("SAML ExternalURL parse: %w", err)
	}

	// Fetch IdP metadata.
	var idpMetadata *saml.EntityDescriptor
	if cfg.SAMLIdPMetadataURL != "" {
		metaURL, err := url.Parse(cfg.SAMLIdPMetadataURL)
		if err != nil {
			return fmt.Errorf("SAML IdP metadata URL parse: %w", err)
		}
		httpClient := &http.Client{Timeout: samlMetadataTimeout}
		if cfg.OIDCInsecureSkipVerify {
			httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), samlMetadataTimeout)
		defer cancel()
		idpMetadata, err = samlsp.FetchMetadata(ctx, httpClient, *metaURL)
		if err != nil {
			return fmt.Errorf("SAML IdP metadata fetch from %s: %w", cfg.SAMLIdPMetadataURL, err)
		}
	} else {
		idpMetadata = &saml.EntityDescriptor{}
		if err := xml.Unmarshal([]byte(cfg.SAMLIdPMetadata), idpMetadata); err != nil {
			return fmt.Errorf("SAML IdP metadata XML parse: %w", err)
		}
	}

	acsURL := *rootURL
	acsURL.Path = "/saml/acs"
	metadataURL := *rootURL
	metadataURL.Path = "/saml/metadata"

	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("SAML SP private key does not implement crypto.Signer")
	}

	sp := saml.ServiceProvider{
		EntityID:          cfg.SAMLEntityID,
		Key:               signer,
		Certificate:       leafCert,
		IDPMetadata:       idpMetadata,
		AcsURL:            acsURL,
		MetadataURL:       metadataURL,
		AllowIDPInitiated: false,
	}

	s.samlSP = &sp
	slog.Info("SAML SP initialized", "entity_id", cfg.SAMLEntityID, "acs_url", sp.AcsURL.String())
	return nil
}

// handleSAMLMetadata serves the SP metadata XML document.
// GET /saml/metadata
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	buf, err := xml.MarshalIndent(s.samlSP.Metadata(), "", "  ")
	if err != nil {
		slog.Error("SAML metadata marshal error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write([]byte(xml.Header)) //nolint:errcheck
	w.Write(buf)                //nolint:errcheck
}

// handleSAMLLogin initiates an SP-initiated SSO flow by creating an AuthnRequest
// and redirecting the user to the IdP.
// GET /saml/login
func (s *Server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Per-IP rate limit: reuse the login rate limiter.
	if !s.loginRL.allow(remoteAddr(r)) {
		http.Error(w, "too many requests -- try again later", http.StatusTooManyRequests)
		return
	}

	// Generate a relay state nonce for CSRF protection.
	nonce, err := randutil.Hex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Create the AuthnRequest so we can capture the request ID.
	authnRequest, err := s.samlSP.MakeAuthenticationRequest(
		s.samlSP.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		slog.Error("SAML AuthnRequest creation failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Store the relay state with the request ID and client IP.
	s.samlRelayMu.Lock()
	s.samlRelayStates[nonce] = samlRelayState{
		issuedAt:  time.Now(),
		clientIP:  remoteAddr(r),
		requestID: authnRequest.ID,
	}
	s.samlRelayMu.Unlock()

	redirectURL, err := authnRequest.Redirect(nonce, s.samlSP)
	if err != nil {
		slog.Error("SAML redirect URL creation failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// handleSAMLACS processes the SAML assertion from the IdP.
// POST /saml/acs
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.callbackRL.allow(remoteAddr(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	// Parse the form to access SAMLResponse and RelayState.
	if err := r.ParseForm(); err != nil {
		slog.Warn("SAML ACS: form parse error", "err", err)
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "invalid_form")
		return
	}

	// Validate and consume relay state.
	relayState := r.FormValue("RelayState")
	if relayState == "" || len(relayState) != 32 || !isHex(relayState) {
		slog.Warn("SECURITY SAML ACS: malformed relay state", "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_request", "auth_state_malformed")
		return
	}

	s.samlRelayMu.Lock()
	state, stateExists := s.samlRelayStates[relayState]
	if stateExists {
		delete(s.samlRelayStates, relayState)
	}
	s.samlRelayMu.Unlock()

	if !stateExists {
		slog.Warn("SECURITY SAML ACS: unknown or expired relay state", "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusBadRequest, "session_expired", "login_session_expired")
		return
	}

	// Reject stale relay states.
	if time.Since(state.issuedAt) > 15*time.Minute {
		slog.Warn("SECURITY SAML ACS: expired relay state", "remote_addr", remoteAddr(r))
		revokeErrorPage(w, r, http.StatusBadRequest, "auth_failed", "nonce_expired")
		return
	}

	// IP binding check.
	if state.clientIP != "" && state.clientIP != remoteAddr(r) {
		if s.cfg.EnforceOIDCIPBinding {
			slog.Warn("SECURITY SAML ACS: IP mismatch -- rejecting", "login_ip", state.clientIP, "callback_ip", remoteAddr(r))
			revokeErrorPage(w, r, http.StatusForbidden, "auth_failed", "ip_binding_mismatch")
			return
		}
		slog.Warn("SECURITY SAML ACS: IP mismatch (possible CSRF)", "login_ip", state.clientIP, "callback_ip", remoteAddr(r))
	}

	// Parse and validate the SAML assertion.
	// The request ID from the AuthnRequest is passed as the only valid InResponseTo value.
	assertion, err := s.samlSP.ParseResponse(r, []string{state.requestID})
	if err != nil {
		slog.Error("SAML ACS: assertion validation failed", "remote_addr", remoteAddr(r), "err", err)
		loginURL := s.baseURL + "/saml/login"
		revokeErrorPageWithLink(w, r, http.StatusForbidden, "auth_failed", "token_verify_failed", loginURL, "try_again")
		return
	}

	// Extract NameID.
	nameID := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
	}

	// Extract user attributes from the assertion.
	username := s.extractSAMLUsername(assertion, nameID)
	if username == "" || !validUsername.MatchString(username) {
		slog.Warn("SECURITY SAML ACS: invalid username", "remote_addr", remoteAddr(r), "nameID", nameID)
		challengesDenied.WithLabelValues("identity_mismatch").Inc()
		revokeErrorPage(w, r, http.StatusBadRequest, "invalid_identity", "invalid_idp_username")
		return
	}

	groups := s.extractSAMLGroups(assertion)

	// Determine role based on group membership.
	s.cfgMu.RLock()
	adminGroups := s.cfg.AdminGroups
	s.cfgMu.RUnlock()

	role := "user"
	if len(adminGroups) > 0 {
		if len(groups) == 0 {
			slog.Warn("SAML groups attribute is empty -- user will be assigned role=user; check IdP attribute mapping",
				"user", username, "groups_attr", s.cfg.SAMLGroupsAttr)
		}
		for _, userGroup := range groups {
			for _, adminGroup := range adminGroups {
				if userGroup == adminGroup {
					role = "admin"
					break
				}
			}
			if role == "admin" {
				break
			}
		}
	}

	slog.Info("SESSIONS (SAML)", "user", username, "role", role, "remote_addr", remoteAddr(r))

	s.dispatchNotification(notify.WebhookData{
		Event:      "user_logged_in",
		Username:   username,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		RemoteAddr: remoteAddr(r),
	})

	// Record authentication time for one-tap freshness checks (shared key with OIDC).
	s.store.RecordOIDCAuth(username)

	// Set session cookie and redirect to dashboard.
	s.setSessionCookie(w, username, role)

	// Check for pending one-tap approval after SAML login (same logic as OIDC callback).
	httpsOrigin := strings.HasPrefix(s.cfg.ExternalURL, "https://")
	if onetapCookie, err := r.Cookie("pam_onetap"); err == nil && onetapCookie.Value != "" {
		http.SetCookie(w, &http.Cookie{Name: "pam_onetap", Value: "", Path: "/", MaxAge: -1, Secure: httpsOrigin, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		parts := strings.SplitN(onetapCookie.Value, ".", 3)
		if len(parts) == 3 && isDecimal(parts[1]) && isHex(parts[2]) && len(parts[2]) == 64 {
			if challenge, ok := s.store.Get(parts[0]); ok && challenge.Username == username {
				expected := s.computeOneTapToken(challenge.ID, challenge.Username, challenge.Hostname, challenge.ExpiresAt)
				if expected != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(onetapCookie.Value)) == 1 {
					onetapURL := s.baseURL + "/api/onetap/" + onetapCookie.Value
					http.Redirect(w, r, onetapURL, http.StatusSeeOther)
					return
				}
			}
		}
	}

	http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
}

// extractSAMLUsername extracts the username from the SAML assertion.
// If SAMLUsernameAttr is set, it looks for that attribute; otherwise uses NameID.
func (s *Server) extractSAMLUsername(assertion *saml.Assertion, nameID string) string {
	if s.cfg.SAMLUsernameAttr != "" {
		if vals := samlAttrValues(assertion, s.cfg.SAMLUsernameAttr); len(vals) > 0 {
			return vals[0]
		}
	}
	return nameID
}

// extractSAMLGroups extracts group membership from the SAML assertion.
func (s *Server) extractSAMLGroups(assertion *saml.Assertion) []string {
	return samlAttrValues(assertion, s.cfg.SAMLGroupsAttr)
}

// extractSAMLDisplayName extracts the display name from the SAML assertion.
func (s *Server) extractSAMLDisplayName(assertion *saml.Assertion) string {
	if vals := samlAttrValues(assertion, s.cfg.SAMLDisplayNameAttr); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// samlAttrValues returns all values for a named SAML attribute from the assertion.
func samlAttrValues(assertion *saml.Assertion, name string) []string {
	if assertion == nil || name == "" {
		return nil
	}
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if attr.Name == name || attr.FriendlyName == name {
				var vals []string
				for _, v := range attr.Values {
					if v.Value != "" {
						vals = append(vals, v.Value)
					}
				}
				return vals
			}
		}
	}
	return nil
}

// samlRelayState holds state for an in-flight SAML login.
type samlRelayState struct {
	issuedAt  time.Time
	clientIP  string
	requestID string // SAML AuthnRequest ID for InResponseTo validation
}

// pruneSAMLRelayStates removes relay states older than 15 minutes.
// Called periodically from the nonce pruning goroutine.
func (s *Server) pruneSAMLRelayStates() {
	s.samlRelayMu.Lock()
	defer s.samlRelayMu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	for k, v := range s.samlRelayStates {
		if v.issuedAt.Before(cutoff) {
			delete(s.samlRelayStates, k)
		}
	}
}
