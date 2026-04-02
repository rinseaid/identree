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
// Tokens are stored at <CacheDir>/<hostname>/<username> with root-only
// permissions. The hostname subdirectory prevents a token cached on one
// host from being used on another host sharing the same cache directory.
// On cache hit, the token is verified locally via JWKS (one network call
// to the issuer on first use; go-oidc caches JWKS internally after that).
// On miss or failure, the caller falls through to the full device flow.
type TokenCache struct {
	CacheDir string
	Issuer   string
	ClientID string
	hostname string // resolved once at construction; consistent across all operations

	// verifierMu guards lazy initialization of the OIDC verifier.
	// Unlike sync.Once, the TTL-based pattern here retries after failures so
	// that a temporary OIDC provider outage does not permanently block the
	// cache for the process lifetime.
	verifierMu     sync.Mutex
	verifier       *oidc.IDTokenVerifier
	verifierErr    error
	verifierExpiry time.Time
}

// cachedToken is the on-disk format for a cached OIDC token.
type cachedToken struct {
	IDToken   string    `json:"id_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewTokenCache creates a new token cache.
// Returns an error if issuer or clientID are empty, as both are required for
// OIDC token verification and an empty value would only be caught at first use.
// hostname is resolved once by the caller and stored so that all cache
// operations (Check, Write, Delete, ModTime) use a consistent path even if
// the system hostname were to change during the process lifetime.
func NewTokenCache(cacheDir, issuer, clientID, hostname string) (*TokenCache, error) {
	if issuer == "" {
		return nil, fmt.Errorf("token cache: issuer must not be empty")
	}
	if clientID == "" {
		return nil, fmt.Errorf("token cache: clientID must not be empty")
	}
	return &TokenCache{
		CacheDir: cacheDir,
		Issuer:   issuer,
		ClientID: clientID,
		hostname: hostname,
	}, nil
}

// Check validates a cached token for the given username.
// Returns the remaining validity duration, the file modification time (from the
// open fd's Stat to avoid a TOCTOU race with a separate Lstat call), and nil on
// success. Returns zero, zero time, and an error on any failure.
func (tc *TokenCache) Check(username string) (time.Duration, time.Time, error) {
	path := filepath.Join(tc.CacheDir, tc.hostname, username)

	// Read with O_NOFOLLOW to reject symlinks (same pattern as readBreakglassHash)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("opening cache file: %w", err)
	}
	defer f.Close()

	// Acquire a shared advisory lock so concurrent PAM sessions do not race
	// with a Write on the same token file.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return 0, time.Time{}, fmt.Errorf("locking cache file: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck

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
	// M8: Reject oversized tokens before touching the filesystem.
	// A legitimate OIDC id_token is well under 64KB; anything larger is
	// either malformed or a resource-exhaustion attempt.
	if len(rawIDToken) > 65536 {
		return fmt.Errorf("token too large")
	}

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

	// Resolve the hostname-specific cache directory using the stored hostname.
	hostCacheDir := filepath.Join(tc.CacheDir, tc.hostname)

	// Ensure per-hostname cache directory exists with tight permissions.
	// MkdirAll does not fix permissions on existing directories, so
	// Chmod afterwards to enforce 0700 even if pre-created with looser perms.
	if err := os.MkdirAll(hostCacheDir, 0700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}
	if err := os.Chmod(hostCacheDir, 0700); err != nil {
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

	// Atomic write: temp file + rename (same pattern as writeBreakglassFile).
	// Permissions are set immediately after CreateTemp, before any data is written,
	// so the id_token is never world-readable even transiently.
	tmp, err := os.CreateTemp(hostCacheDir, ".token-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	// Tighten permissions before writing any sensitive data.
	if err := os.Chmod(tmpName, 0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("setting permissions: %w", err)
	}
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

	// Acquire an exclusive advisory lock on the destination path before the
	// rename so that concurrent PAM sessions (a Check still in progress)
	// cannot observe a partial or replaced file. Open with O_CREATE so the
	// lock target always exists even on first write.
	path := filepath.Join(hostCacheDir, username)
	lockFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("opening lock target: %w", err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("locking cache file: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck

	// Atomic rename — replaces the locked file; the new inode is visible to
	// readers only after the lock is released.
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming to target: %w", err)
	}
	// Sync the parent directory so the rename is durable on power loss.
	if d, err := os.Open(hostCacheDir); err == nil {
		_ = d.Sync()
		d.Close()
	}

	return nil
}

// Delete removes the cached token file for a given username.
func (tc *TokenCache) Delete(username string) error {
	path := filepath.Join(tc.CacheDir, tc.hostname, username)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing cache file: %w", err)
	}
	return nil
}

// ModTime returns the modification time of the cached token file.
func (tc *TokenCache) ModTime(username string) (time.Time, error) {
	path := filepath.Join(tc.CacheDir, tc.hostname, username)
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

// getVerifier returns the cached OIDC verifier, re-initializing it if the
// previous attempt failed and the retry TTL has expired.
//
// On success the verifier is cached for 24 hours (JWKS key rotation is rare).
// On failure the error is cached for 5 minutes so that a transient OIDC
// provider outage does not permanently block the cache for the process lifetime
// the way sync.Once would.
func (tc *TokenCache) getVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	tc.verifierMu.Lock()
	defer tc.verifierMu.Unlock()

	// Re-initialize whenever the TTL has expired (first call, after a failure's
	// 5-minute retry window, or after a success's 24-hour refresh window).
	// The nil-guard was intentionally removed: without it the 24-hour TTL
	// actually fires and re-fetches JWKS / re-creates the verifier as intended.
	if tc.verifierExpiry.IsZero() || time.Now().After(tc.verifierExpiry) {
		// Inject the hardened client so oidc.NewProvider uses it for the
		// discovery and initial JWKS fetch.
		initCtx := context.WithValue(context.Background(), oauth2.HTTPClient, oidcDiscoveryClient)

		provider, err := oidc.NewProvider(initCtx, tc.Issuer)
		if err != nil {
			tc.verifierErr = fmt.Errorf("discovering OIDC provider: %w", err)
			tc.verifier = nil
			// Short TTL on failure so we retry after a temporary outage.
			tc.verifierExpiry = time.Now().Add(5 * time.Minute)
		} else {
			tc.verifier = provider.Verifier(&oidc.Config{ClientID: tc.ClientID})
			tc.verifierErr = nil
			// Long TTL on success; JWKS refresh is handled internally by go-oidc.
			tc.verifierExpiry = time.Now().Add(24 * time.Hour)
		}
	}

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
