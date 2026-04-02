package pam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/rinseaid/identree/internal/config"
)

// TokenCache manages cached OIDC id_tokens on the PAM client machine.
// Tokens are stored at <CacheDir>/<username> with root-only permissions.
// On cache hit, the token is verified locally via JWKS (one network call
// to the issuer on first use; go-oidc caches JWKS internally after that).
// On miss or failure, the caller falls through to the full device flow.
type TokenCache struct {
	CacheDir string
	Issuer   string
	ClientID string

	// providerOnce guards lazy initialization of verifier.
	// go-oidc caches JWKS keys internally on the *oidc.Provider; caching the
	// verifier here means we pay the two HTTP round-trips (OIDC discovery +
	// JWKS fetch) at most once per process lifetime instead of on every Check.
	providerOnce sync.Once
	verifier     *oidc.IDTokenVerifier
	verifierErr  error
}

// cachedToken is the on-disk format for a cached OIDC token.
type cachedToken struct {
	IDToken   string    `json:"id_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewTokenCache creates a new token cache.
func NewTokenCache(cacheDir, issuer, clientID string) *TokenCache {
	return &TokenCache{
		CacheDir: cacheDir,
		Issuer:   issuer,
		ClientID: clientID,
	}
}

// Check validates a cached token for the given username.
// Returns the remaining validity duration, the file modification time (from the
// open fd's Stat to avoid a TOCTOU race with a separate Lstat call), and nil on
// success. Returns zero, zero time, and an error on any failure.
func (tc *TokenCache) Check(username string) (time.Duration, time.Time, error) {
	path := filepath.Join(tc.CacheDir, username)

	// Read with O_NOFOLLOW to reject symlinks (same pattern as readBreakglassHash)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("opening cache file: %w", err)
	}
	defer f.Close()

	// Validate file security; capture mtime from the open fd to avoid a
	// separate Lstat call that could race with a file replacement.
	info, err := f.Stat()
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("stating cache file: %w", err)
	}
	mtime := info.ModTime()
	if !info.Mode().IsRegular() {
		return 0, time.Time{}, fmt.Errorf("cache file is not a regular file")
	}
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return 0, time.Time{}, fmt.Errorf("cache file has group/other permissions (mode %04o)", mode)
	}
	if uid, ok := config.FileOwnerUID(info); !ok {
		return 0, time.Time{}, fmt.Errorf("cannot determine cache file owner")
	} else if uid != 0 {
		return 0, time.Time{}, fmt.Errorf("cache file not owned by root (uid=%d)", uid)
	}

	// Parse cached token (limit read size to prevent abuse).
	// Use io.ReadAll with a limit so a file read that returns (n, io.EOF) in
	// one call (common for small files) is not mistakenly treated as an error.
	data, err := io.ReadAll(io.LimitReader(f, 16*1024))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("reading cache file: %w", err)
	}

	var cached cachedToken
	if err := json.Unmarshal(data, &cached); err != nil {
		return 0, time.Time{}, fmt.Errorf("parsing cache file: %w", err)
	}

	if cached.IDToken == "" {
		return 0, time.Time{}, fmt.Errorf("cache file has no id_token")
	}

	// Quick expiry check before doing any crypto (30s clock-skew buffer)
	remaining := time.Until(cached.ExpiresAt) - 30*time.Second
	if remaining <= 0 {
		return 0, time.Time{}, fmt.Errorf("cached token expired")
	}

	// Verify JWT signature, audience, and expiry via OIDC provider JWKS.
	// This makes one network call to the issuer's JWKS endpoint. If the
	// issuer is unreachable, we fall through to the device flow (safe degradation).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	verifier, err := tc.getVerifier(ctx)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("creating OIDC verifier: %w", err)
	}

	idToken, err := verifier.Verify(ctx, cached.IDToken)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("token verification failed: %w", err)
	}

	// Extract preferred_username and verify it matches the expected user
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return 0, time.Time{}, fmt.Errorf("parsing token claims: %w", err)
	}
	if claims.PreferredUsername != username {
		return 0, time.Time{}, fmt.Errorf("token username %q does not match expected %q", claims.PreferredUsername, username)
	}

	return remaining, mtime, nil
}

// Write caches an id_token for the given username after a successful device flow.
// Uses atomic temp-file + rename to prevent partial reads.
func (tc *TokenCache) Write(username, rawIDToken string) error {
	// Parse the JWT to extract the exp claim (without verification — the server
	// already verified it, we just need the expiry for quick cache-hit checks).
	parts := strings.SplitN(rawIDToken, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("malformed JWT")
	}

	// Decode payload to get exp claim
	payload, err := decodeJWTSegment(parts[1])
	if err != nil {
		return fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("parsing JWT claims: %w", err)
	}
	if claims.Exp == 0 {
		return fmt.Errorf("JWT has no exp claim")
	}

	expiresAt := time.Unix(claims.Exp, 0)

	// Ensure cache directory exists with tight permissions.
	// MkdirAll does not fix permissions on existing directories, so
	// Chmod afterwards to enforce 0700 even if pre-created with looser perms.
	if err := os.MkdirAll(tc.CacheDir, 0700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}
	if err := os.Chmod(tc.CacheDir, 0700); err != nil {
		return fmt.Errorf("enforcing cache directory permissions: %w", err)
	}

	cached := cachedToken{
		IDToken:   rawIDToken,
		ExpiresAt: expiresAt,
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("marshaling cache data: %w", err)
	}

	// Atomic write: temp file + rename (same pattern as writeBreakglassFile)
	tmp, err := os.CreateTemp(tc.CacheDir, ".token-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("syncing token cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Set permissions before rename (root-owned, 0600)
	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("setting permissions: %w", err)
	}

	// Atomic rename
	path := filepath.Join(tc.CacheDir, username)
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming to target: %w", err)
	}
	// Sync the parent directory so the rename is durable on power loss.
	if d, err := os.Open(tc.CacheDir); err == nil {
		_ = d.Sync()
		d.Close()
	}

	return nil
}

// Delete removes the cached token file for a given username.
func (tc *TokenCache) Delete(username string) error {
	path := filepath.Join(tc.CacheDir, username)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing cache file: %w", err)
	}
	return nil
}

// ModTime returns the modification time of the cached token file.
func (tc *TokenCache) ModTime(username string) (time.Time, error) {
	path := filepath.Join(tc.CacheDir, username)
	info, err := os.Lstat(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("stating cache file: %w", err)
	}
	return info.ModTime(), nil
}

// oidcDiscoveryClient is the hardened HTTP client used for OIDC provider
// discovery. It disables proxy env vars and redirect following to prevent SSRF.
// It is intentionally package-level so it is shared across all TokenCache
// instances and allocated exactly once.
var oidcDiscoveryClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		Proxy: nil, // never use proxy env vars
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// getVerifier returns the cached OIDC verifier, initializing it on first call.
// The verifier (and the *oidc.Provider it wraps) is created once per TokenCache
// lifetime; go-oidc caches JWKS keys on the provider, so subsequent calls only
// pay for key-set refresh when keys actually rotate, not a full discovery round-trip.
func (tc *TokenCache) getVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	tc.providerOnce.Do(func() {
		// Inject the hardened client so oidc.NewProvider uses it for the
		// discovery and initial JWKS fetch.
		initCtx := context.WithValue(context.Background(), oauth2.HTTPClient, oidcDiscoveryClient)

		provider, err := oidc.NewProvider(initCtx, tc.Issuer)
		if err != nil {
			tc.verifierErr = fmt.Errorf("discovering OIDC provider: %w", err)
			return
		}
		tc.verifier = provider.Verifier(&oidc.Config{ClientID: tc.ClientID})
	})

	if tc.verifierErr != nil {
		return nil, tc.verifierErr
	}
	return tc.verifier, nil
}

// decodeJWTSegment decodes a base64url-encoded JWT segment.
func decodeJWTSegment(seg string) ([]byte, error) {
	// JWT uses base64url without padding — add padding if needed
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}
	return base64.URLEncoding.DecodeString(seg)
}
