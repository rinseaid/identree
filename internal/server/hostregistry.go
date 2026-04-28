package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RegisteredHost represents a host authorized to use identree.
type RegisteredHost struct {
	Secret        string    `json:"secret"`
	Users         []string  `json:"users"`                        // authorized usernames, "*" = all users
	Group         string    `json:"group,omitempty"`              // e.g., "production", "staging", "dev"
	RegisteredAt  time.Time `json:"registered_at"`
	CertExpiresAt time.Time `json:"cert_expires_at,omitempty"`   // mTLS cert NotAfter, set at provision time
}

// HostRegistry manages registered hosts with per-host secrets.
type HostRegistry struct {
	mu       sync.RWMutex
	hosts    map[string]*RegisteredHost // hostname -> config
	filePath string
}

// NewHostRegistry creates a new host registry, loading any existing data from filePath.
func NewHostRegistry(filePath string) *HostRegistry {
	r := &HostRegistry{
		hosts:    make(map[string]*RegisteredHost),
		filePath: filePath,
	}
	if filePath != "" {
		r.load()
	}
	return r
}

// IsEnabled returns true if any hosts are registered.
// When no hosts are registered, the server falls back to global shared secret.
func (r *HostRegistry) IsEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.hosts) > 0
}

// normalizeHostname lowercases a hostname and strips any trailing dot so that
// registry lookups and admin-approval patterns are case-insensitive and FQDN-safe.
func normalizeHostname(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// HasHost returns true if the hostname is present in the registry.
// When the registry is empty (no hosts registered), returns true for backward compatibility.
func (r *HostRegistry) HasHost(hostname string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hosts) == 0 {
		return true
	}
	_, ok := r.hosts[normalizeHostname(hostname)]
	return ok
}

// ValidateHost checks if a hostname is registered and the secret matches.
// Returns true if validation passes. When the registry is empty (no hosts
// registered), returns true for backward compatibility.
func (r *HostRegistry) ValidateHost(hostname, secret string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hosts) == 0 {
		return true // no hosts registered = backward compat
	}
	host, ok := r.hosts[normalizeHostname(hostname)]
	if !ok {
		return false
	}
	// Constant-time comparison to prevent timing attacks
	return subtleCompare(host.Secret, secret)
}

// ValidateAnyHost checks if the provided secret matches any registered host.
// Used for API endpoints where the hostname isn't known at auth time (e.g., poll, grace-status).
func (r *HostRegistry) ValidateAnyHost(secret string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hosts) == 0 {
		return true
	}
	// Iterate all hosts before returning to avoid a timing side-channel that
	// would reveal the position of a matching host in the registry.
	found := false
	for _, host := range r.hosts {
		if subtleCompare(host.Secret, secret) {
			found = true
		}
	}
	return found
}

// IsUserAuthorized checks if a username is allowed on a host.
// When the registry is empty, returns true for backward compatibility.
func (r *HostRegistry) IsUserAuthorized(hostname, username string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.hosts) == 0 {
		return true
	}
	host, ok := r.hosts[normalizeHostname(hostname)]
	if !ok {
		return false
	}
	for _, u := range host.Users {
		if u == "*" || u == username {
			return true
		}
	}
	return false
}

// RegisteredHosts returns all registered hostnames, sorted alphabetically.
func (r *HostRegistry) RegisteredHosts() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var hosts []string
	for h := range r.hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// GetHost returns info about a registered host (without exposing the secret).
func (r *HostRegistry) GetHost(hostname string) (users []string, group string, registeredAt time.Time, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	host, exists := r.hosts[normalizeHostname(hostname)]
	if !exists {
		return nil, "", time.Time{}, false
	}
	usersCopy := make([]string, len(host.Users))
	copy(usersCopy, host.Users)
	return usersCopy, host.Group, host.RegisteredAt, true
}

// SetCertExpiry records the mTLS certificate expiry time for a host.
func (r *HostRegistry) SetCertExpiry(hostname string, expiresAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	host, exists := r.hosts[normalizeHostname(hostname)]
	if !exists {
		return
	}
	host.CertExpiresAt = expiresAt
	r.saveLocked()
}

// HostCertExpiries returns a map of hostname to CertExpiresAt for all hosts
// that have a non-zero cert expiry recorded.
func (r *HostRegistry) HostCertExpiries() map[string]time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]time.Time)
	for hostname, host := range r.hosts {
		if !host.CertExpiresAt.IsZero() {
			result[hostname] = host.CertExpiresAt
		}
	}
	return result
}

// HostsForUser returns hostnames the user is authorized for, sorted alphabetically.
func (r *HostRegistry) HostsForUser(username string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []string
	for hostname, host := range r.hosts {
		for _, u := range host.Users {
			if u == "*" || u == username {
				result = append(result, hostname)
				break
			}
		}
	}
	sort.Strings(result)
	return result
}

// validGroupName is the allowed character set for host group labels.
var validGroupName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// reservedHostnames lists labels that must not be used as registered hostnames.
var reservedHostnames = map[string]bool{
	"localhost": true,
	"admin":     true,
	"root":      true,
	"identree":  true,
	"api":       true,
	"www":       true,
	"mail":      true,
	"ftp":       true,
	"ssh":       true,
	"vpn":       true,
	"gateway":   true,
	"firewall":  true,
	"router":    true,
}

// numericHostname matches hostnames that consist entirely of digits (e.g. "123").
var numericHostname = regexp.MustCompile(`^[0-9]+$`)

// AddHost registers a new host with a generated secret.
// Returns the secret so the admin can configure the host.
func (r *HostRegistry) AddHost(hostname string, users []string, group string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	hostname = normalizeHostname(hostname)
	if _, exists := r.hosts[hostname]; exists {
		return "", fmt.Errorf("host %q is already registered", hostname)
	}
	if !validHostname.MatchString(hostname) {
		return "", fmt.Errorf("invalid hostname format")
	}
	if reservedHostnames[hostname] || numericHostname.MatchString(hostname) {
		return "", fmt.Errorf("hostname is reserved")
	}
	for _, u := range users {
		if u != "*" && !validUsername.MatchString(u) {
			return "", fmt.Errorf("invalid username %q in users list", u)
		}
	}
	if group != "" && !validGroupName.MatchString(group) {
		return "", fmt.Errorf("invalid group name %q (must match ^[a-zA-Z0-9._-]{1,64}$)", group)
	}
	secret, err := generateHostSecret()
	if err != nil {
		return "", fmt.Errorf("generating secret: %w", err)
	}
	r.hosts[hostname] = &RegisteredHost{
		Secret:       secret,
		Users:        users,
		Group:        group,
		RegisteredAt: time.Now(),
	}
	registeredHosts.Set(float64(len(r.hosts)))
	r.saveLocked()
	return secret, nil
}

// RemoveHost unregisters a host.
func (r *HostRegistry) RemoveHost(hostname string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	hostname = normalizeHostname(hostname)
	if _, exists := r.hosts[hostname]; !exists {
		return fmt.Errorf("host %q is not registered", hostname)
	}
	delete(r.hosts, hostname)
	registeredHosts.Set(float64(len(r.hosts)))
	r.saveLocked()
	return nil
}

// RotateSecret generates a new secret for a host.
// Returns the new secret.
func (r *HostRegistry) RotateSecret(hostname string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	host, exists := r.hosts[normalizeHostname(hostname)]
	if !exists {
		return "", fmt.Errorf("host %q is not registered", hostname)
	}
	secret, err := generateHostSecret()
	if err != nil {
		return "", fmt.Errorf("generating secret: %w", err)
	}
	host.Secret = secret
	r.saveLocked()
	slog.Info("HOST_SECRET_ROTATED", "host", hostname)
	return secret, nil
}

// generateHostSecret generates a cryptographically random 64-character hex secret.
func generateHostSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (r *HostRegistry) load() {
	f, err := os.OpenFile(r.filePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("cannot read host registry", "path", r.filePath, "err", err)
		}
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		slog.Warn("cannot stat host registry", "path", r.filePath, "err", err)
		return
	}
	if !info.Mode().IsRegular() {
		slog.Warn("host registry is not a regular file, skipping", "path", r.filePath)
		return
	}
	if mode := info.Mode().Perm(); mode&0022 != 0 {
		slog.Warn("host registry is group/world writable, skipping", "path", r.filePath, "mode", fmt.Sprintf("%04o", mode))
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, 16<<20)) // 16 MiB limit
	if err != nil {
		slog.Warn("cannot read host registry", "path", r.filePath, "err", err)
		return
	}
	var hosts map[string]*RegisteredHost
	if err := json.Unmarshal(data, &hosts); err != nil {
		slog.Warn("corrupt host registry, starting fresh", "path", r.filePath, "err", err)
		return
	}
	// Filter out nil entries and entries with invalid hostname keys.
	// An attacker who can write the registry file could inject an empty-string
	// key or special-character key; the empty-string key would cause IsEnabled()
	// to return true and ValidateAnyHost to accept an attacker-controlled secret.
	for hostname, host := range hosts {
		normalized := normalizeHostname(hostname)
		if host == nil {
			slog.Warn("host registry contains nil entry, skipping", "hostname", hostname)
			delete(hosts, hostname)
		} else if !validHostname.MatchString(normalized) {
			slog.Warn("host registry contains invalid hostname key, skipping", "hostname", hostname)
			delete(hosts, hostname)
		} else if normalized != hostname {
			// Migrate legacy mixed-case or trailing-dot hostnames to canonical form.
			hosts[normalized] = host
			delete(hosts, hostname)
		}
	}
	if hosts != nil {
		r.hosts = hosts
	}
	slog.Info("loaded registered hosts", "count", len(hosts), "path", r.filePath)
	registeredHosts.Set(float64(len(r.hosts)))
}

func (r *HostRegistry) saveLocked() {
	if r.filePath == "" {
		return
	}
	// Acquire an advisory exclusive lock to prevent a concurrent CLI invocation
	// (add-host, remove-host, rotate-host-secret) from racing with the server's
	// in-memory writes. The lock is held for the duration of the write+rename.
	lockPath := r.filePath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		if flockErr := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); flockErr != nil {
			slog.Warn("host registry: flock failed, proceeding without advisory lock", "err", flockErr)
		}
		defer func() {
			syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			lockFile.Close()
		}()
	}
	data, err := json.MarshalIndent(r.hosts, "", "  ")
	if err != nil {
		slog.Error("marshaling host registry", "err", err)
		return
	}
	// Atomic write: temp file + fsync + rename
	dir := filepath.Dir(r.filePath) + "/"
	tmp, err := os.CreateTemp(dir, ".hosts-tmp-*")
	if err != nil {
		slog.Error("creating temp host registry file", "err", err)
		return
	}
	if err := syscall.Fchmod(int(tmp.Fd()), 0600); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		slog.Error("setting host registry permissions", "err", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		slog.Error("writing host registry", "err", err)
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		slog.Error("syncing host registry", "err", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		slog.Error("closing host registry temp file", "err", err)
		return
	}
	if err := os.Rename(tmpName, r.filePath); err != nil {
		os.Remove(tmpName)
		slog.Error("renaming host registry", "err", err)
		return
	}
	// Sync the parent directory so the rename is durable on power loss.
	if d, err := os.Open(filepath.Dir(r.filePath)); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// RemoveUserFromAllHosts removes a username from all host user lists.
func (r *HostRegistry) RemoveUserFromAllHosts(username string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for _, host := range r.hosts {
		var kept []string
		for _, u := range host.Users {
			if u != username {
				kept = append(kept, u)
			}
		}
		if len(kept) != len(host.Users) {
			host.Users = kept
			changed = true
		}
	}
	if changed {
		r.saveLocked()
	}
}

// subtleCompare does constant-time string comparison, preventing timing attacks.
// Always hashes both values so the comparison is constant-time regardless of
// whether lengths match, preventing byte-by-byte timing side-channels.
func subtleCompare(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
