package challenge

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/rinseaid/identree/internal/randutil"
)

const (
	ActionApproved = "approved"
	// ActionDenied is a historical alias for the "denied" challenge status value.
	// The action log uses ActionRejected ("rejected") for all user-denial events.
	ActionDenied   = "denied"
	ActionRejected = "rejected"
	ActionAutoApproved       = "auto_approved"
	ActionRevoked            = "revoked"
	ActionExtended           = "extended"
	ActionElevated           = "elevated"
	ActionRotatedBreakglass  = "rotated_breakglass"
	ActionRevealedBreakglass = "revealed_breakglass"
	ActionRemovedHost        = "removed_host"
	ActionRemovedUser        = "user_removed"
	ActionRotationRequested  = "rotation_requested"
	ActionDeployed           = "deployed"
	ActionConfigChanged          = "config_changed"
	ActionSudoRuleModified       = "sudo_rule_modified"
	ActionClaimsUpdated          = "claims_updated"
	ActionServerRestarted        = "server_restarted"
	ActionBreakglassOverride     = "breakglass_override"
)

var (
	challengesExpired = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "challenges_expired_total",
		Help:      "Total number of sudo challenges that expired without resolution.",
	})

	// ActiveChallenges is exported so the server package can increment/decrement it.
	ActiveChallenges = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Name:      "active_challenges",
		Help:      "Number of currently active (pending) challenges.",
	})

	graceSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Name:      "grace_sessions_active",
		Help:      "Current number of active grace period sessions.",
	})
)

// Sentinel errors for rate limiting. Checked via errors.Is in server.go
// instead of fragile string matching.
var (
	ErrTooManyChallenges           = errors.New("too many active challenges")
	ErrTooManyPerUser              = errors.New("too many pending challenges for user")
	ErrSessionSufficientlyExtended = errors.New("session already has sufficient remaining time")
	// ErrDiskWriteFailed is returned when Approve or ConsumeAndApprove cannot
	// durably persist the approval to disk. Callers should propagate this as a
	// 503 so the PAM client retries rather than caching a potentially lost approval.
	ErrDiskWriteFailed = errors.New("challenge: disk write failed, please retry")
	// ErrDuplicateApprover is returned when the same approver tries to approve twice.
	ErrDuplicateApprover = errors.New("approver has already approved this challenge")
)

// ChallengeStatus represents the state of a sudo challenge.
type ChallengeStatus string

const (
	StatusPending  ChallengeStatus = "pending"
	StatusApproved ChallengeStatus = "approved"
	StatusDenied   ChallengeStatus = "denied"
	StatusExpired  ChallengeStatus = "expired"
)

const (
	// maxChallengesPerUser limits how many pending challenges a single username can have.
	// Prevents memory exhaustion DoS via unlimited challenge creation.
	maxChallengesPerUser = 10

	// maxTotalChallenges is an absolute cap on total challenges in the store.
	maxTotalChallenges = 10000
)

// ApprovalRecord tracks a single approver's decision in multi-approval flows.
type ApprovalRecord struct {
	Approver   string    `json:"approver"`
	ApprovedAt time.Time `json:"approved_at"`
}

// GraceSession represents an active grace period session for a specific host.
type GraceSession struct {
	Username  string
	Hostname  string
	ExpiresAt time.Time
}

// Challenge represents a sudo elevation request awaiting user approval.
type Challenge struct {
	ID        string          `json:"id"`
	UserCode  string          `json:"user_code"`
	Username  string          `json:"username"`
	Status    ChallengeStatus `json:"status"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`

	// Nonce ties the OIDC state to this challenge, preventing CSRF/replay.
	// The nonce is generated when the user clicks "login" and verified on callback.
	Nonce string `json:"-"`

	// Hostname of the machine requesting sudo (sent by PAM client, optional)
	Hostname string `json:"hostname,omitempty"`

	// Reason is a human-readable description of why sudo is being requested.
	// Populated from the API request body; optional.
	Reason string `json:"reason,omitempty"`

	// BreakglassRotateBefore is the server's rotation signal at challenge creation time.
	// Stored per-challenge so the HMAC is consistent even if the server config changes
	// between challenge creation and poll-time approval.
	BreakglassRotateBefore string `json:"-"`

	// RequestedGrace is the per-challenge grace duration selected by the user
	// on the approval page. Zero means use the server's default grace period.
	RequestedGrace time.Duration `json:"-"`

	// RevokeTokensBefore is the server's revocation signal at challenge creation time.
	// Stored per-challenge so the HMAC is consistent even if revocations happen
	// between challenge creation and poll-time approval.
	RevokeTokensBefore string `json:"-"`

	// Policy fields — set at challenge creation from the policy engine evaluation.
	PolicyName        string `json:"policy_name,omitempty"`
	RequiredApprovals int    `json:"required_approvals,omitempty"`
	RequireAdmin      bool   `json:"require_admin,omitempty"`
	GraceEligible     bool   `json:"-"` // evaluated at creation, not persisted

	// BreakglassOverride indicates this challenge was force-approved via break-glass policy override.
	BreakglassOverride bool `json:"breakglass_override,omitempty"`

	// BreakglassBypassAllowed is set at challenge creation from the matching policy.
	// When true, an admin may use the break-glass override button.
	BreakglassBypassAllowed bool `json:"-"`

	// DenyReason is an optional explanation provided by the admin when rejecting.
	DenyReason string `json:"deny_reason,omitempty"`

	// Set after OIDC callback confirms identity
	ApprovedBy string    `json:"-"`
	ApprovedAt time.Time `json:"-"`

	// Approvals tracks all approvers for multi-approval challenges.
	// For single-approval (RequiredApprovals <= 1), this has at most one entry.
	Approvals []ApprovalRecord `json:"approvals,omitempty"`

	// RawIDToken stores the OIDC id_token after approval, for forwarding to
	// the PAM client's token cache. Not serialized to JSON.
	RawIDToken string `json:"-"`
}

// ActionLogEntry records an action taken on the dashboard (approval, revocation, etc.).
type ActionLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`          // "approved", "revoked", "auto_approved"
	Hostname  string    `json:"hostname"`
	Code      string    `json:"code,omitempty"`
	Actor     string    `json:"actor,omitempty"`  // who performed the action (empty = self)
	Reason    string    `json:"reason,omitempty"` // reason for the sudo request (set at challenge creation)
}

// maxActionLogPrune is the per-user entry limit applied when the state file
// exceeds 1 MB and gets rotated.  Between rotations the log grows unbounded.
const maxActionLogPrune = 1000

// archivedUserEntries is the JSON Lines record written to sessions.archive.jsonl
// when action log entries are dropped during state-file rotation.
type archivedUserEntries struct {
	Username   string           `json:"username"`
	Entries    []ActionLogEntry `json:"entries"`
	ArchivedAt string           `json:"archived_at"`
}

// EscrowRecord stores metadata about a host's escrowed break-glass password.
type EscrowRecord struct {
	Timestamp time.Time `json:"timestamp"`
	ItemID    string    `json:"item_id,omitempty"`   // external secrets manager item ID
	VaultID   string    `json:"vault_id,omitempty"`  // resolved vault/container UUID (1password-connect)
}

// ChallengeStore manages in-memory sudo challenges with TTL expiration.
type ChallengeStore struct {
	mu                 sync.RWMutex
	diskMu             sync.Mutex            // serialises writeStateToDisk calls
	dirty              atomic.Bool           // true when actionLog has unflushed changes
	challenges         map[string]*Challenge // keyed by ID
	byCode             map[string]string     // user_code -> ID
	pendingByUser      map[string]int        // username -> count of pending non-expired challenges
	totalPending       int                   // total across all users; used for the global cap
	lastApproval       map[string]time.Time  // graceKey -> expiry time (for grace period)
	revokeTokensBefore     map[string]time.Time  // username -> revocation timestamp
	rotateBreakglassBefore map[string]time.Time  // hostname -> per-host rotate-before timestamp
	actionLog              map[string][]ActionLogEntry // username -> last N action log entries
	escrowedHosts          map[string]EscrowRecord // hostname -> escrow metadata
	escrowedCiphertexts    map[string]string       // hostname -> base64(nonce||ciphertext) for local backend
	oneTapUsed         map[string]bool       // challenge ID -> whether one-tap was consumed
	lastOIDCAuth       map[string]time.Time  // username -> last OIDC authentication time
	ttl                time.Duration
	gracePeriod        time.Duration
	persistPath        string        // file path for persisted state (empty = no persistence)
	stopCh             chan struct{} // signals reapLoop to stop
	stopOnce           sync.Once    // ensures Stop is safe to call concurrently
	stopWg             sync.WaitGroup // waits for reapLoop goroutine to exit

	// revokedNoncesStore and revokedAdminSessionsStore persist server-side session
	// revocations across restarts. They are separate from the in-memory maps in
	// server.go because ChallengeStore owns the persistence layer.
	revokedNoncesMu          sync.Mutex
	revokedNoncesStore       map[string]int64 // nonce -> Unix revocation timestamp

	revokedAdminSessionsMu   sync.Mutex
	revokedAdminSessionsStore map[string]int64 // username -> Unix revocation timestamp

	usedEscrowTokens   map[string]time.Time // escrow token key -> first-seen time (replay prevention)
	usedEscrowTokensMu sync.Mutex

	sessionNoncesMap map[string]SessionNonceData // nonce -> OIDC login state
	sessionNoncesMu  sync.Mutex

	// OnExpire is an optional callback invoked when a pending challenge is
	// reaped (expired). The server wires this up to emit audit events.
	OnExpire func(username, hostname, code string)
}

// persistedState is the JSON-serializable snapshot of grace sessions, revocation timestamps,
// action log entries, and escrowed host records.
type persistedState struct {
	// Version is the schema version for this state file.
	// Version 0 (absent) is the legacy format and is loaded as-is for backward compatibility.
	// Version 1 is the current format.
	Version                int                         `json:"version"`
	GraceSessions          map[string]time.Time        `json:"grace_sessions"`
	RevokeTokensBefore     map[string]time.Time        `json:"revoke_tokens_before"`
	RotateBreakglassBefore map[string]time.Time        `json:"rotate_breakglass_before_hosts,omitempty"`
	ActionLog              map[string][]ActionLogEntry  `json:"action_log,omitempty"`
	EscrowedHosts          map[string]EscrowRecord      `json:"escrowed_hosts,omitempty"`
	EscrowedCiphertexts    map[string]string            `json:"escrowed_ciphertexts,omitempty"`
	LastOIDCAuth           map[string]time.Time         `json:"last_oidc_auth,omitempty"`
	// RevokedNonces holds session cookie nonces that were explicitly revoked (sign-out).
	// Stored as Unix timestamps (int64) so the JSON remains compact.
	RevokedNonces          map[string]int64             `json:"revokedNonces,omitempty"`
	// RevokedAdminSessions holds the most recent admin-role revocation time per username.
	// Stored as Unix timestamps (int64) so the JSON remains compact.
	RevokedAdminSessions   map[string]int64             `json:"revokedAdminSessions,omitempty"`
	// UsedEscrowTokens holds HMAC escrow tokens that have already been redeemed,
	// keyed by "hostname:timestamp". Stored as Unix timestamps (int64) so the JSON remains compact.
	UsedEscrowTokens       map[string]int64             `json:"used_escrow_tokens,omitempty"`
	// OneTapUsed is intentionally ephemeral: it is in-memory only and is reset on restart.
	// Challenges do not survive restarts, so persisting consumed nonces would only accumulate
	// orphaned entries with no corresponding challenge to protect.
	OneTapUsed             map[string]bool              `json:"-"`
}

// NewChallengeStore creates a new store with the given challenge TTL, grace period,
// and optional persistence file path. If persistPath is empty, no state is persisted.
func NewChallengeStore(ttl, gracePeriod time.Duration, persistPath string) *ChallengeStore {
	s := &ChallengeStore{
		challenges:         make(map[string]*Challenge),
		byCode:             make(map[string]string),
		pendingByUser:      make(map[string]int),
		lastApproval:       make(map[string]time.Time),
		revokeTokensBefore:     make(map[string]time.Time),
		rotateBreakglassBefore: make(map[string]time.Time),
		actionLog:              make(map[string][]ActionLogEntry),
		escrowedHosts:       make(map[string]EscrowRecord),
		escrowedCiphertexts: make(map[string]string),
		oneTapUsed:         make(map[string]bool),
		lastOIDCAuth:       make(map[string]time.Time),
		usedEscrowTokens:   make(map[string]time.Time),
		sessionNoncesMap:   make(map[string]SessionNonceData),
		ttl:                ttl,
		gracePeriod:        gracePeriod,
		persistPath:        persistPath,
		stopCh:             make(chan struct{}),
	}
	if persistPath != "" {
		s.loadState()
	}
	s.stopWg.Add(1)
	go func() {
		defer s.stopWg.Done()
		s.reapLoop()
	}()
	return s
}

// Stop cleanly shuts down the reap goroutine and waits for it to exit.
// Safe to call concurrently; blocks until the goroutine has finished its
// final flush so callers can safely access the persist file afterwards.
func (s *ChallengeStore) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.stopWg.Wait()
}

// graceKey returns the key used for per-host grace period tracking.
// Format: "username\x00hostname" or just "username" if hostname is empty.
// The null byte separator is used because it cannot appear in POSIX usernames
// or hostnames, avoiding collisions with email-style usernames (e.g. user@host).
func graceKey(username, hostname string) string {
	if hostname == "" {
		return username
	}
	return username + "\x00" + hostname
}

// Create generates a new challenge for the given username, optional hostname,
// optional BreakglassRotateBefore snapshot (set before insertion to avoid data races),
// and optional reason string describing why sudo is being requested.
func (s *ChallengeStore) Create(username, hostname, breakglassRotateBefore, reason string) (*Challenge, error) {
	id, err := randutil.Hex(16)
	if err != nil {
		return nil, fmt.Errorf("generating challenge ID: %w", err)
	}

	code, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}

	now := time.Now()

	// Snapshot revokeTokensBefore and per-host rotate-before for this challenge
	s.mu.RLock()
	var revokeTokensBefore string
	if t, ok := s.revokeTokensBefore[username]; ok {
		revokeTokensBefore = t.Format(time.RFC3339)
	}
	// Check per-host rotate-before; use it if it's newer than the global one
	if hostname != "" {
		if perHostT, ok := s.rotateBreakglassBefore[hostname]; ok {
			var globalT time.Time
			if breakglassRotateBefore != "" {
				var parseErr error
				globalT, parseErr = time.Parse(time.RFC3339, breakglassRotateBefore)
				if parseErr != nil {
					slog.Warn("challenge: invalid breakglassRotateBefore, treating as zero", "value", breakglassRotateBefore, "err", parseErr)
				}
			}
			if perHostT.After(globalT) {
				breakglassRotateBefore = perHostT.Format(time.RFC3339)
			}
		}
	}
	s.mu.RUnlock()

	c := &Challenge{
		ID:                     id,
		UserCode:               code,
		Username:               username,
		Hostname:               hostname,
		Reason:                 reason,
		BreakglassRotateBefore: breakglassRotateBefore,
		RevokeTokensBefore:     revokeTokensBefore,
		Status:                 StatusPending,
		CreatedAt:              now,
		ExpiresAt:              now.Add(s.ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Rate limit: cap pending challenges to prevent memory exhaustion DoS.
	// Counting only pending (not yet resolved) challenges ensures that a burst
	// of approvals doesn't prevent new challenges while the reaper catches up.
	if s.totalPending >= maxTotalChallenges {
		return nil, fmt.Errorf("try again later: %w", ErrTooManyChallenges)
	}

	// Rate limit: cap per-user pending challenges (O(1) via counter map)
	if s.pendingByUser[username] >= maxChallengesPerUser {
		return nil, fmt.Errorf("user %q, wait for existing ones to expire: %w", username, ErrTooManyPerUser)
	}

	// Ensure no user code collision (astronomically unlikely, but defense in depth)
	if _, exists := s.byCode[code]; exists {
		return nil, fmt.Errorf("user code collision, try again")
	}

	s.challenges[id] = c
	s.byCode[code] = id
	s.pendingByUser[username]++
	s.totalPending++
	return c, nil
}

// Get retrieves a challenge by ID. Returns a snapshot copy to avoid data races
// when callers read fields after the lock is released.
func (s *ChallengeStore) Get(id string) (Challenge, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.challenges[id]
	if !ok {
		return Challenge{}, false
	}
	if time.Now().After(c.ExpiresAt) {
		return Challenge{}, false
	}
	return *c, true
}

// GetByCode retrieves a challenge by user code.
// Both lookups are performed under a single lock to avoid a TOCTOU race
// where reap() or RemoveUser() could delete the challenge between the two steps.
func (s *ChallengeStore) GetByCode(code string) (Challenge, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byCode[code]
	if !ok {
		return Challenge{}, false
	}
	c, ok := s.challenges[id]
	if !ok || time.Now().After(c.ExpiresAt) {
		return Challenge{}, false
	}
	return *c, true
}

// SetNonce stores the OIDC nonce on a challenge when the login flow begins.
// This binds the OIDC authentication to this specific challenge, preventing CSRF.
// Also re-checks status and expiry under the write lock to close the TOCTOU gap
// between GetByCode (which returns a snapshot) and this mutation.
func (s *ChallengeStore) SetNonce(id string, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return fmt.Errorf("challenge expired")
	}
	if c.Status != StatusPending {
		return fmt.Errorf("challenge already resolved")
	}
	if c.Nonce != "" {
		return fmt.Errorf("nonce already set (login already initiated)")
	}
	c.Nonce = nonce
	return nil
}

// SetBreakglassOverride marks the challenge as having been force-approved via break-glass override.
func (s *ChallengeStore) SetBreakglassOverride(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.challenges[id]; ok {
		c.BreakglassOverride = true
	}
}

// SetRequestedGrace sets the per-challenge grace duration selected on the approval page.
func (s *ChallengeStore) SetRequestedGrace(id string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.challenges[id]; ok {
		c.RequestedGrace = d
	}
}

// Approve marks a challenge as approved by the given identity.
func (s *ChallengeStore) Approve(id string, approvedBy string) error {
	now := time.Now() // snapshot once to avoid expiry/approval time skew
	s.mu.Lock()
	c, ok := s.challenges[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("challenge not found")
	}
	if now.After(c.ExpiresAt) {
		s.mu.Unlock()
		return fmt.Errorf("challenge expired")
	}
	if c.Status != StatusPending {
		s.mu.Unlock()
		return fmt.Errorf("challenge already resolved")
	}
	// If the user's session was revoked after this challenge was created,
	// treat the challenge as expired to prevent approval of a stale challenge.
	if revokeTs, ok := s.revokeTokensBefore[c.Username]; ok && revokeTs.After(c.CreatedAt) {
		s.mu.Unlock()
		return fmt.Errorf("challenge superseded by session revocation")
	}
	c.Status = StatusApproved
	c.ApprovedBy = approvedBy
	c.ApprovedAt = now
	if s.gracePeriod > 0 {
		key := graceKey(c.Username, c.Hostname)
		graceDur := c.RequestedGrace
		if graceDur == 0 {
			graceDur = s.gracePeriod
		}
		s.lastApproval[key] = now.Add(graceDur)
	}
	graceSessions.Set(float64(len(s.lastApproval)))
	s.decPending(c.Username)
	data, rotate := s.marshalStateLocked()
	s.mu.Unlock()
	if !s.writeStateToDisk(data, rotate) {
		s.dirty.Store(true)
		return ErrDiskWriteFailed
	}
	return nil
}

// AddApproval records a partial approval for multi-approval challenges.
// Returns true if this approval met the threshold (challenge is now fully approved).
func (s *ChallengeStore) AddApproval(id string, approver string, requiredApprovals int) (bool, error) {
	now := time.Now()
	s.mu.Lock()
	c, ok := s.challenges[id]
	if !ok {
		s.mu.Unlock()
		return false, fmt.Errorf("challenge not found")
	}
	if now.After(c.ExpiresAt) {
		s.mu.Unlock()
		return false, fmt.Errorf("challenge expired")
	}
	if c.Status != StatusPending {
		s.mu.Unlock()
		return false, fmt.Errorf("challenge already resolved")
	}
	// If the user's session was revoked after this challenge was created,
	// treat the challenge as expired.
	if revokeTs, ok := s.revokeTokensBefore[c.Username]; ok && revokeTs.After(c.CreatedAt) {
		s.mu.Unlock()
		return false, fmt.Errorf("challenge superseded by session revocation")
	}
	// Check for duplicate approver.
	for _, a := range c.Approvals {
		if a.Approver == approver {
			s.mu.Unlock()
			return false, ErrDuplicateApprover
		}
	}
	c.Approvals = append(c.Approvals, ApprovalRecord{
		Approver:   approver,
		ApprovedAt: now,
	})
	fullyApproved := len(c.Approvals) >= requiredApprovals
	if fullyApproved {
		c.Status = StatusApproved
		c.ApprovedBy = approver
		c.ApprovedAt = now
		if s.gracePeriod > 0 {
			key := graceKey(c.Username, c.Hostname)
			graceDur := c.RequestedGrace
			if graceDur == 0 {
				graceDur = s.gracePeriod
			}
			s.lastApproval[key] = now.Add(graceDur)
		}
		graceSessions.Set(float64(len(s.lastApproval)))
		s.decPending(c.Username)
	}
	data, rotate := s.marshalStateLocked()
	s.mu.Unlock()
	if !s.writeStateToDisk(data, rotate) {
		s.dirty.Store(true)
		return false, ErrDiskWriteFailed
	}
	return fullyApproved, nil
}

// Deny marks a challenge as denied, with an optional reason.
func (s *ChallengeStore) Deny(id, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return fmt.Errorf("challenge expired")
	}
	if c.Status != StatusPending {
		return fmt.Errorf("challenge already resolved")
	}
	c.Status = StatusDenied
	c.DenyReason = reason
	s.decPending(c.Username)
	s.dirty.Store(true)
	return nil
}

// WithinGracePeriod returns true if the user has a recent approval within the grace period
// for the given hostname.
func (s *ChallengeStore) WithinGracePeriod(username, hostname string) bool {
	if s.gracePeriod <= 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := graceKey(username, hostname)
	expiry, ok := s.lastApproval[key]
	if !ok {
		return false
	}
	return time.Now().Before(expiry)
}

// GraceRemaining returns how much of the grace period remains for a user on a host.
func (s *ChallengeStore) GraceRemaining(username, hostname string) time.Duration {
	if s.gracePeriod <= 0 {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := graceKey(username, hostname)
	expiry, ok := s.lastApproval[key]
	if !ok {
		return 0
	}
	remaining := time.Until(expiry)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// PendingChallenges returns all pending, non-expired challenges for a username.
func (s *ChallengeStore) PendingChallenges(username string) []Challenge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var result []Challenge
	for _, c := range s.challenges {
		if c.Username == username && c.Status == StatusPending && now.Before(c.ExpiresAt) {
			result = append(result, *c)
		}
	}
	return result
}

// AutoApprove immediately approves a challenge (used for grace period bypass).
// Does NOT update lastApproval — the existing grace session continues unchanged.
func (s *ChallengeStore) AutoApprove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	if time.Now().After(c.ExpiresAt) {
		return fmt.Errorf("challenge expired")
	}
	if c.Status != StatusPending {
		return fmt.Errorf("challenge already resolved")
	}
	c.Status = StatusApproved
	c.ApprovedBy = c.Username
	c.ApprovedAt = time.Now()
	// AutoApprove does NOT update lastApproval — the existing grace session
	// continues with its original expiry.
	s.decPending(c.Username)
	return nil
}

// AutoApproveIfWithinGracePeriod atomically checks the grace period and approves
// the challenge in a single write-lock acquisition, eliminating the TOCTOU window
// between a separate WithinGracePeriod check and AutoApprove call.
// Returns true if the challenge was auto-approved; false if the grace period
// had expired (or never existed) by the time the lock was acquired.
func (s *ChallengeStore) AutoApproveIfWithinGracePeriod(username, hostname, id string) bool {
	if s.gracePeriod <= 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := graceKey(username, hostname)
	expiry, ok := s.lastApproval[key]
	if !ok || !time.Now().Before(expiry) {
		return false
	}

	c, ok := s.challenges[id]
	if !ok || c.Status != StatusPending {
		return false
	}
	// Fix 6: do not auto-approve an expired challenge.
	if time.Now().After(c.ExpiresAt) {
		return false
	}
	c.Status = StatusApproved
	c.ApprovedBy = c.Username
	c.ApprovedAt = time.Now()
	s.decPending(c.Username)
	return true
}

// ActiveSessions returns all active grace sessions for a given username.
func (s *ChallengeStore) ActiveSessions(username string) []GraceSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prefix := username + "\x00"
	var sessions []GraceSession
	now := time.Now()
	for key, expiry := range s.lastApproval {
		if !now.Before(expiry) {
			continue // expired
		}
		if key == username {
			// Entry without hostname
			sessions = append(sessions, GraceSession{Username: username, Hostname: "(unknown)", ExpiresAt: expiry})
		} else if strings.HasPrefix(key, prefix) {
			hostname := key[len(prefix):]
			sessions = append(sessions, GraceSession{Username: username, Hostname: hostname, ExpiresAt: expiry})
		}
	}
	return sessions
}

// AllPendingChallenges returns all pending, non-expired challenges across all users.
func (s *ChallengeStore) AllPendingChallenges() []Challenge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var result []Challenge
	for _, c := range s.challenges {
		if c.Status == StatusPending && now.Before(c.ExpiresAt) {
			result = append(result, *c)
		}
	}
	return result
}

// AllActiveSessions returns all active grace sessions across all users.
func (s *ChallengeStore) AllActiveSessions() []GraceSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var sessions []GraceSession
	for key, expiry := range s.lastApproval {
		if !now.Before(expiry) {
			continue
		}
		parts := strings.SplitN(key, "\x00", 2)
		hostname := "(unknown)"
		username := key
		if len(parts) == 2 {
			username = parts[0]
			hostname = parts[1]
		}
		sessions = append(sessions, GraceSession{
			Username:  username,
			Hostname:  hostname,
			ExpiresAt: expiry,
		})
	}
	return sessions
}

// AllActionHistory returns merged action log across all users, most recent first.
func (s *ChallengeStore) AllActionHistory() []ActionLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all []ActionLogEntry
	for _, entries := range s.actionLog {
		all = append(all, entries...)
	}
	// Sort by timestamp descending
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.After(all[j].Timestamp)
	})
	return all
}

// ActionLogEntryWithUser extends ActionLogEntry with the owning username,
// used for cross-user exports (e.g. API key access).
type ActionLogEntryWithUser struct {
	Username  string    `json:"username"`
	Actor     string    `json:"actor,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Hostname  string    `json:"hostname"`
	Code      string    `json:"code,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// AllActionHistoryWithUsers returns merged action log across all users (with
// username included per entry), sorted most recent first.
func (s *ChallengeStore) AllActionHistoryWithUsers() []ActionLogEntryWithUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all []ActionLogEntryWithUser
	for user, entries := range s.actionLog {
		for _, e := range entries {
			all = append(all, ActionLogEntryWithUser{
				Username:  user,
				Actor:     e.Actor,
				Timestamp: e.Timestamp,
				Action:    e.Action,
				Hostname:  e.Hostname,
				Code:      e.Code,
				Reason:    e.Reason,
			})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Timestamp.After(all[j].Timestamp) })
	return all
}

// LogAction records an action in the per-user action log.
// The log grows unbounded; pruning happens during file rotation in marshalStateLocked
// when the serialized state exceeds 1 MB.
// actor is who performed the action; if empty or equal to username (self-action), Actor is not stored.
func (s *ChallengeStore) LogAction(username, action, hostname, code, actor string) {
	s.LogActionAt(username, action, hostname, code, actor, time.Now())
}

// LogActionWithReason records an action in the per-user action log, including an optional
// reason string from the originating challenge.
func (s *ChallengeStore) LogActionWithReason(username, action, hostname, code, actor, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := ActionLogEntry{
		Timestamp: time.Now(),
		Action:    action,
		Hostname:  hostname,
		Code:      code,
		Reason:    reason,
	}
	if actor != "" && actor != username {
		entry.Actor = actor
	}
	s.actionLog[username] = append(s.actionLog[username], entry)
	if len(s.actionLog[username]) > maxActionLogPrune*2 {
		entries := s.actionLog[username]
		s.actionLog[username] = entries[len(entries)-maxActionLogPrune:]
	}
	s.dirty.Store(true)
}

// LogActionAt records an action with an explicit timestamp (for seeding test data).
// Disk writes are deferred to the 2-second flush timer rather than happening inline.
func (s *ChallengeStore) LogActionAt(username, action, hostname, code, actor string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := ActionLogEntry{
		Timestamp: at,
		Action:    action,
		Hostname:  hostname,
		Code:      code,
	}
	if actor != "" && actor != username {
		entry.Actor = actor
	}
	s.actionLog[username] = append(s.actionLog[username], entry)
	// Cap in-memory growth; the disk-rotation prune (maxActionLogPrune) is a
	// secondary backstop but only fires when the serialized state exceeds 1 MB.
	if len(s.actionLog[username]) > maxActionLogPrune*2 {
		entries := s.actionLog[username]
		s.actionLog[username] = entries[len(entries)-maxActionLogPrune:]
	}
	s.dirty.Store(true)
}

// ActionHistory returns the action log entries for a user, most recent first.
// limit <= 0 means return all entries.
func (s *ChallengeStore) ActionHistory(username string, limit int) []ActionLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	log := s.actionLog[username]
	if len(log) == 0 {
		return nil
	}
	n := len(log)
	if limit > 0 && limit < n {
		n = limit
	}
	// Return a copy in reverse order (most recent first), bounded by limit.
	result := make([]ActionLogEntry, n)
	for i := 0; i < n; i++ {
		result[i] = log[len(log)-1-i]
	}
	return result
}

// UsersWithHostActivity returns usernames that have action log entries for the given hostname.
func (s *ChallengeStore) UsersWithHostActivity(hostname string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var users []string
	for user, entries := range s.actionLog {
		for _, e := range entries {
			if e.Hostname == hostname {
				users = append(users, user)
				break
			}
		}
	}
	return users
}

// RemoveHost removes all state for a hostname: action log entries, escrow record,
// and grace sessions.
func (s *ChallengeStore) RemoveHost(hostname string) {
	s.mu.Lock()
	for user, entries := range s.actionLog {
		var kept []ActionLogEntry
		for _, e := range entries {
			if e.Hostname != hostname {
				kept = append(kept, e)
			}
		}
		s.actionLog[user] = kept
	}
	delete(s.escrowedHosts, hostname)
	delete(s.escrowedCiphertexts, hostname)
	suffix := "\x00" + hostname
	for key := range s.lastApproval {
		if strings.HasSuffix(key, suffix) {
			delete(s.lastApproval, key)
		}
	}
	s.dirty.Store(true)
	s.mu.Unlock()
}

// ActiveSessionsForHost returns all users with active grace sessions on a host.
func (s *ChallengeStore) ActiveSessionsForHost(hostname string) []GraceSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var sessions []GraceSession
	suffix := "\x00" + hostname
	for key, expiry := range s.lastApproval {
		if !now.Before(expiry) {
			continue
		}
		if strings.HasSuffix(key, suffix) {
			username := strings.TrimSuffix(key, suffix)
			sessions = append(sessions, GraceSession{Username: username, Hostname: hostname, ExpiresAt: expiry})
		} else if hostname == "" && !strings.Contains(key, "\x00") {
			sessions = append(sessions, GraceSession{Username: key, Hostname: "", ExpiresAt: expiry})
		}
	}
	return sessions
}

// KnownHosts returns unique hostnames from the action log for a given user, sorted alphabetically.
// Entries with action ActionRemovedHost are excluded so removed hosts do not reappear.
func (s *ChallengeStore) KnownHosts(username string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]bool)
	for _, entry := range s.actionLog[username] {
		if entry.Hostname != "" && entry.Hostname != "(unknown)" && entry.Action != ActionRemovedHost {
			seen[entry.Hostname] = true
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// AllKnownHosts returns unique hostnames from the action log across all users, sorted alphabetically.
// Entries with action ActionRemovedHost are excluded so removed hosts do not reappear.
func (s *ChallengeStore) AllKnownHosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]bool)
	for _, entries := range s.actionLog {
		for _, entry := range entries {
			if entry.Hostname != "" && entry.Hostname != "(unknown)" && entry.Action != ActionRemovedHost {
				seen[entry.Hostname] = true
			}
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// CreateGraceSession creates a grace session for a user on a specific hostname with the given duration.
// Used for manual elevation from the hosts page.
func (s *ChallengeStore) CreateGraceSession(username, hostname string, duration time.Duration) {
	s.mu.Lock()
	key := graceKey(username, hostname)
	s.lastApproval[key] = time.Now().Add(duration)
	graceSessions.Set(float64(len(s.lastApproval)))
	s.dirty.Store(true)
	s.mu.Unlock()
}

// RecordEscrow records that a host has escrowed a break-glass password.
func (s *ChallengeStore) RecordEscrow(hostname, itemID, vaultID string) {
	s.mu.Lock()
	s.escrowedHosts[hostname] = EscrowRecord{Timestamp: time.Now(), ItemID: itemID, VaultID: vaultID}
	s.dirty.Store(true)
	s.mu.Unlock()
}

// StoreEscrowCiphertext stores an encrypted break-glass password for the local escrow backend.
// Implements escrow.EscrowStorer. Must NOT be called while holding the write lock.
func (s *ChallengeStore) StoreEscrowCiphertext(hostname, ciphertext string) {
	s.mu.Lock()
	s.escrowedCiphertexts[hostname] = ciphertext
	s.dirty.Store(true)
	s.mu.Unlock()
}

// GetEscrowCiphertext returns the encrypted ciphertext for a host, if any.
// Implements escrow.EscrowStorer.
func (s *ChallengeStore) GetEscrowCiphertext(hostname string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.escrowedCiphertexts[hostname]
	return v, ok
}

// EscrowedHosts returns all hosts with escrowed passwords and their escrow records.
func (s *ChallengeStore) EscrowedHosts() map[string]EscrowRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]EscrowRecord, len(s.escrowedHosts))
	for h, r := range s.escrowedHosts {
		result[h] = r
	}
	return result
}

// SetHostRotateBefore sets the per-host rotate-before timestamp to now and saves state.
func (s *ChallengeStore) SetHostRotateBefore(hostname string) {
	s.mu.Lock()
	s.rotateBreakglassBefore[hostname] = time.Now()
	s.dirty.Store(true)
	s.mu.Unlock()
}

// HostRotateBefore returns the per-host rotate-before time, or zero if not set.
func (s *ChallengeStore) HostRotateBefore(hostname string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rotateBreakglassBefore[hostname]
}

// SetAllHostsRotateBefore sets the rotate-before timestamp to now for all given hostnames.
func (s *ChallengeStore) SetAllHostsRotateBefore(hostnames []string) {
	s.mu.Lock()
	now := time.Now()
	for _, h := range hostnames {
		s.rotateBreakglassBefore[h] = now
	}
	s.dirty.Store(true)
	s.mu.Unlock()
}

// ExtendGraceSession extends a grace session to the maximum allowed duration.
// Returns the new remaining duration, or 0 if no session exists.
// Extension is skipped if more than 75% of the grace period remains, preventing
// repeated extension abuse (e.g. clicking extend every day to extend indefinitely).
// Returns ErrSessionSufficientlyExtended when the guard fires so callers can
// distinguish "already extended" from a real failure.
func (s *ChallengeStore) ExtendGraceSession(username, hostname string) (time.Duration, error) {
	s.mu.Lock()
	key := graceKey(username, hostname)
	expiry, ok := s.lastApproval[key]
	if !ok {
		s.mu.Unlock()
		return 0, nil
	}
	remaining := time.Until(expiry)
	// Don't extend if more than 75% of grace period remains
	if remaining > s.gracePeriod*3/4 {
		s.mu.Unlock()
		return remaining, ErrSessionSufficientlyExtended
	}
	newExpiry := time.Now().Add(s.gracePeriod)
	s.lastApproval[key] = newExpiry
	graceSessions.Set(float64(len(s.lastApproval)))
	s.dirty.Store(true)
	s.mu.Unlock()
	return s.gracePeriod, nil
}

// ForceExtendGraceSession extends a grace session to the full grace period
// unconditionally, bypassing the 75% guard. Used for admin-initiated extends.
func (s *ChallengeStore) ForceExtendGraceSession(username, hostname string) time.Duration {
	s.mu.Lock()
	if s.gracePeriod <= 0 {
		s.mu.Unlock()
		return 0 // grace period disabled; extending would set expiry to "now"
	}
	key := graceKey(username, hostname)
	if _, ok := s.lastApproval[key]; !ok {
		s.mu.Unlock()
		return 0
	}
	newExpiry := time.Now().Add(s.gracePeriod)
	s.lastApproval[key] = newExpiry
	graceSessions.Set(float64(len(s.lastApproval)))
	s.dirty.Store(true)
	s.mu.Unlock()
	return s.gracePeriod
}

// ExtendGraceSessionFor extends a grace session to the given duration from now,
// capped at the configured grace period. Returns the new remaining duration, or 0 if no session exists.
func (s *ChallengeStore) ExtendGraceSessionFor(username, hostname string, dur time.Duration) time.Duration {
	s.mu.Lock()
	if s.gracePeriod <= 0 {
		s.mu.Unlock()
		return 0
	}
	key := graceKey(username, hostname)
	if _, ok := s.lastApproval[key]; !ok {
		s.mu.Unlock()
		return 0
	}
	if dur > s.gracePeriod {
		dur = s.gracePeriod
	}
	newExpiry := time.Now().Add(dur)
	s.lastApproval[key] = newExpiry
	graceSessions.Set(float64(len(s.lastApproval)))
	s.dirty.Store(true)
	s.mu.Unlock()
	return dur
}

// RevokeSession removes a grace session for a user on a specific hostname
// and sets the revocation timestamp so that token caches are invalidated.
func (s *ChallengeStore) RevokeSession(username, hostname string) {
	s.mu.Lock()
	key := graceKey(username, hostname)
	delete(s.lastApproval, key)
	graceSessions.Set(float64(len(s.lastApproval)))
	s.revokeTokensBefore[username] = time.Now()
	s.dirty.Store(true)
	s.mu.Unlock()
}

// RevokeTokensBefore returns the revocation timestamp for a user, if any.
func (s *ChallengeStore) RevokeTokensBefore(username string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revokeTokensBefore[username]
}

// decPending decrements the pending counter for a username. Must be called under write lock.
func (s *ChallengeStore) decPending(username string) {
	if s.pendingByUser[username] > 0 {
		s.pendingByUser[username]--
		if s.totalPending > 0 {
			s.totalPending--
		}
	}
	if s.pendingByUser[username] == 0 {
		delete(s.pendingByUser, username)
	}
}

// ConsumeOneTap marks a challenge's one-tap token as used. Returns error if already consumed
// or if the challenge no longer exists (prevents orphaned oneTapUsed entries when the challenge
// is removed between Get and ConsumeOneTap by reap or RemoveUser).
func (s *ChallengeStore) ConsumeOneTap(challengeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[challengeID]
	if !ok || time.Now().After(c.ExpiresAt) {
		return fmt.Errorf("challenge not found or expired")
	}
	if s.oneTapUsed[challengeID] {
		return fmt.Errorf("one-tap already used")
	}
	s.oneTapUsed[challengeID] = true
	return nil
}

// ConsumeAndApprove atomically marks the one-tap token as used and approves the challenge
// under a single lock acquisition, eliminating the TOCTOU window between separate
// ConsumeOneTap and Approve calls where another goroutine could approve the same challenge.
func (s *ChallengeStore) ConsumeAndApprove(challengeID, approvedBy string) error {
	now := time.Now() // snapshot once to avoid expiry/approval time skew
	s.mu.Lock()
	c, ok := s.challenges[challengeID]
	if !ok || now.After(c.ExpiresAt) {
		s.mu.Unlock()
		return fmt.Errorf("challenge not found or expired")
	}
	if s.oneTapUsed[challengeID] {
		s.mu.Unlock()
		return fmt.Errorf("one-tap already used")
	}
	if c.Status != StatusPending {
		s.mu.Unlock()
		return fmt.Errorf("challenge already resolved")
	}
	// If the user's session was revoked after this challenge was created,
	// treat the challenge as expired to prevent approval of a stale challenge.
	if revokeTs, ok := s.revokeTokensBefore[c.Username]; ok && revokeTs.After(c.CreatedAt) {
		s.mu.Unlock()
		return fmt.Errorf("challenge superseded by session revocation")
	}
	s.oneTapUsed[challengeID] = true
	c.Status = StatusApproved
	c.ApprovedBy = approvedBy
	c.ApprovedAt = now
	if s.gracePeriod > 0 {
		key := graceKey(c.Username, c.Hostname)
		graceDur := c.RequestedGrace
		if graceDur == 0 {
			graceDur = s.gracePeriod
		}
		s.lastApproval[key] = now.Add(graceDur)
	}
	graceSessions.Set(float64(len(s.lastApproval)))
	s.decPending(c.Username)
	data, rotate := s.marshalStateLocked()
	s.mu.Unlock()
	if !s.writeStateToDisk(data, rotate) {
		s.dirty.Store(true)
		return ErrDiskWriteFailed
	}
	return nil
}

// RecordOIDCAuth records the current time as the last OIDC authentication time for the user.
func (s *ChallengeStore) RecordOIDCAuth(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastOIDCAuth[username] = time.Now()
	s.dirty.Store(true)
}

// LastOIDCAuth returns the last OIDC authentication time for the user, or zero if never recorded.
func (s *ChallengeStore) LastOIDCAuth(username string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastOIDCAuth[username]
}

// AllUsers returns all usernames that have any data in the store.
func (s *ChallengeStore) AllUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make(map[string]bool)
	for user := range s.actionLog {
		users[user] = true
	}
	for key := range s.lastApproval {
		parts := strings.SplitN(key, "\x00", 2)
		users[parts[0]] = true
	}
	result := make([]string, 0, len(users))
	for u := range users {
		result = append(result, u)
	}
	sort.Strings(result)
	return result
}

// RemoveUser removes all data for a user: grace sessions, action log, revocation timestamps,
// and any pending challenges (cancelling them to free pending counters and byCode entries).
func (s *ChallengeStore) RemoveUser(username string) {
	s.mu.Lock()
	// Cancel pending challenges and clean up all challenge data for this user
	for id, c := range s.challenges {
		if c.Username == username {
			if c.Status == StatusPending {
				s.decPending(username)
			}
			delete(s.byCode, c.UserCode)
			delete(s.challenges, id)
			delete(s.oneTapUsed, id)
		}
	}
	// pendingByUser[username] is already zero at this point because decPending
	// in the loop above decrements it to zero and deletes the key. The subtraction
	// is a no-op but is removed to avoid confusion and prevent a future regression
	// if decPending's behaviour changes.
	delete(s.pendingByUser, username)
	// Revoke all grace sessions for this user
	prefix := username + "\x00"
	for key := range s.lastApproval {
		if key == username || strings.HasPrefix(key, prefix) {
			delete(s.lastApproval, key)
		}
	}
	// Set revocation timestamp so token caches are invalidated
	s.revokeTokensBefore[username] = time.Now()
	graceSessions.Set(float64(len(s.lastApproval)))
	// Fix 7: marshal state before clearing the action log so that any
	// ActionRemovedUser log entry added by the caller is included on disk.
	data, rotate := s.marshalStateLocked()
	// Clear action log and OIDC auth record after capturing state for disk.
	delete(s.actionLog, username)
	delete(s.lastOIDCAuth, username)
	s.mu.Unlock()
	s.writeStateToDisk(data, rotate)
}

// PersistRevokedNonce records a revoked session cookie nonce to the persisted state.
// at is the revocation time; it is stored as a Unix timestamp (int64).
// This method is goroutine-safe.
func (s *ChallengeStore) PersistRevokedNonce(nonce string, at time.Time) {
	if s.persistPath == "" {
		return
	}
	s.revokedNoncesMu.Lock()
	if s.revokedNoncesStore == nil {
		s.revokedNoncesStore = make(map[string]int64)
	}
	s.revokedNoncesStore[nonce] = at.Unix()
	s.revokedNoncesMu.Unlock()
	s.dirty.Store(true)
}

// PersistRevokedAdminSession records an admin-session revocation to the persisted state.
// at is the revocation time; it is stored as a Unix timestamp (int64).
// This method is goroutine-safe.
func (s *ChallengeStore) PersistRevokedAdminSession(username string, at time.Time) {
	if s.persistPath == "" {
		return
	}
	s.revokedAdminSessionsMu.Lock()
	if s.revokedAdminSessionsStore == nil {
		s.revokedAdminSessionsStore = make(map[string]int64)
	}
	s.revokedAdminSessionsStore[username] = at.Unix()
	s.revokedAdminSessionsMu.Unlock()
	s.dirty.Store(true)
}

// CheckAndRecordEscrowToken checks whether tokenKey has already been redeemed
// and records it if not. Returns true if the token was already seen (replay detected).
// tokenKey is "hostname:timestamp_unix". Automatically prunes entries older than 10 minutes.
func (s *ChallengeStore) CheckAndRecordEscrowToken(tokenKey string) (alreadySeen bool) {
	s.usedEscrowTokensMu.Lock()
	defer s.usedEscrowTokensMu.Unlock()
	_, seen := s.usedEscrowTokens[tokenKey]
	if seen {
		return true
	}
	s.usedEscrowTokens[tokenKey] = time.Now()
	// Lazy prune: remove entries older than the escrow token validity window.
	cutoff := time.Now().Add(-10 * time.Minute)
	for k, t := range s.usedEscrowTokens {
		if t.Before(cutoff) {
			delete(s.usedEscrowTokens, k)
		}
	}
	s.dirty.Store(true)
	return false
}

// UsedEscrowTokenCount returns the current count of tracked escrow tokens.
// Used for rate limiting.
func (s *ChallengeStore) UsedEscrowTokenCount() int {
	s.usedEscrowTokensMu.Lock()
	defer s.usedEscrowTokensMu.Unlock()
	return len(s.usedEscrowTokens)
}

// LoadRevokedNonces returns the persisted revoked nonces as a map[nonce]time.Time.
// Returns an empty map when no nonces are persisted or persistence is disabled.
func (s *ChallengeStore) LoadRevokedNonces() map[string]time.Time {
	s.revokedNoncesMu.Lock()
	defer s.revokedNoncesMu.Unlock()
	out := make(map[string]time.Time, len(s.revokedNoncesStore))
	for nonce, ts := range s.revokedNoncesStore {
		out[nonce] = time.Unix(ts, 0)
	}
	return out
}

// LoadRevokedAdminSessions returns the persisted admin-session revocations as a map[username]time.Time.
// Returns an empty map when no entries are persisted or persistence is disabled.
func (s *ChallengeStore) LoadRevokedAdminSessions() map[string]time.Time {
	s.revokedAdminSessionsMu.Lock()
	defer s.revokedAdminSessionsMu.Unlock()
	out := make(map[string]time.Time, len(s.revokedAdminSessionsStore))
	for username, ts := range s.revokedAdminSessionsStore {
		out[username] = time.Unix(ts, 0)
	}
	return out
}

// flushDirty writes pending action-log changes to disk if the dirty flag is set.
// Safe to call from any goroutine; serialised internally by diskMu.
func (s *ChallengeStore) flushDirty() {
	if !s.dirty.Load() { // quick non-locking check to avoid unnecessary lock acquisition
		return
	}
	s.mu.Lock()
	if !s.dirty.Swap(false) { // re-check under lock
		s.mu.Unlock()
		return
	}
	data, rotate := s.marshalStateLocked()
	s.mu.Unlock()
	if !s.writeStateToDisk(data, rotate) {
		s.dirty.Store(true) // restore dirty flag on failure
	}
}

// reapLoop removes expired challenges periodically and flushes dirty action-log
// writes every 2 seconds.
func (s *ChallengeStore) reapLoop() {
	s.reapLoopWithBackoff(time.Second)
}

func (s *ChallengeStore) reapLoopWithBackoff(backoff time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			slog.Error("panic in challenge reaper (recovered)", "panic", r, "stack", string(buf[:n]))
			// Only restart if Stop() has not been called.
			select {
			case <-s.stopCh:
				return
			default:
			}
			time.Sleep(backoff)
			// Re-check stopCh after the sleep: Stop() may have been called while we slept.
			select {
			case <-s.stopCh:
				return
			default:
			}
			// Double backoff for next panic, capped at 30s.
			nextBackoff := backoff * 2
			if nextBackoff > 30*time.Second {
				nextBackoff = 30 * time.Second
			}
			go s.reapLoopWithBackoff(nextBackoff)
		}
	}()
	reapTicker := time.NewTicker(30 * time.Second)
	flushTicker := time.NewTicker(2 * time.Second)
	defer reapTicker.Stop()
	defer flushTicker.Stop()
	for {
		select {
		case <-reapTicker.C:
			s.reap()
			backoff = time.Second // reset on successful reap
		case <-flushTicker.C:
			s.flushDirty()
		case <-s.stopCh:
			s.flushDirty() // flush on shutdown
			return
		}
	}
}

func (s *ChallengeStore) reap() {
	now := time.Now()
	type expiredInfo struct {
		username, hostname, code string
	}
	var expired []expiredInfo
	s.mu.Lock()
	for id, c := range s.challenges {
		if now.After(c.ExpiresAt.Add(30 * time.Second)) {
			// If the challenge was still pending when reaped, decrement the counter
			if c.Status == StatusPending {
				s.decPending(c.Username)
				challengesExpired.Inc()
				ActiveChallenges.Dec()
				if s.OnExpire != nil {
					hostname := c.Hostname
					if hostname == "" {
						hostname = "(unknown)"
					}
					expired = append(expired, expiredInfo{c.Username, hostname, c.UserCode})
				}
			}
			delete(s.byCode, c.UserCode)
			delete(s.challenges, id)
			delete(s.oneTapUsed, id)
		}
	}
	// Prune stale grace period entries where expiry has passed.
	pruned := false
	for key, expiry := range s.lastApproval {
		if now.After(expiry) {
			delete(s.lastApproval, key)
			pruned = true
		}
	}
	// Prune stale revocation timestamps (older than 30 days)
	cutoff := now.Add(-30 * 24 * time.Hour)
	for user, ts := range s.revokeTokensBefore {
		if ts.Before(cutoff) {
			delete(s.revokeTokensBefore, user)
			pruned = true
		}
	}
	// Prune stale rotate-before timestamps (older than 30 days)
	for host, ts := range s.rotateBreakglassBefore {
		if ts.Before(cutoff) {
			delete(s.rotateBreakglassBefore, host)
			pruned = true
		}
	}
	// Prune stale escrow records (older than configured rotation period + 30 day buffer)
	escrowCutoff := now.Add(-120 * 24 * time.Hour) // 120 days (covers 90-day rotation + buffer)
	for host, record := range s.escrowedHosts {
		if record.Timestamp.Before(escrowCutoff) {
			delete(s.escrowedHosts, host)
			pruned = true
		}
	}
	// Prune stale OIDC auth timestamps (older than 30 days)
	for user, ts := range s.lastOIDCAuth {
		if ts.Before(cutoff) {
			delete(s.lastOIDCAuth, user)
			pruned = true
		}
	}
	var data []byte
	var rotate bool
	if pruned {
		data, rotate = s.marshalStateLocked()
	}
	// Prune revokedNoncesStore and revokedAdminSessionsStore entries older than 35 minutes.
	// These are short-lived (max session TTL is 30 min); we use 35 min to be safe.
	noncePruneCutoff := now.Add(-35 * time.Minute).Unix()
	var noncePruned bool
	s.revokedNoncesMu.Lock()
	for nonce, ts := range s.revokedNoncesStore {
		if ts < noncePruneCutoff {
			delete(s.revokedNoncesStore, nonce)
			noncePruned = true
		}
	}
	s.revokedNoncesMu.Unlock()
	s.revokedAdminSessionsMu.Lock()
	for username, ts := range s.revokedAdminSessionsStore {
		if ts < noncePruneCutoff {
			delete(s.revokedAdminSessionsStore, username)
			noncePruned = true
		}
	}
	s.revokedAdminSessionsMu.Unlock()
	if noncePruned {
		s.dirty.Store(true)
	}
	// Prune stale session nonces (OIDC login state older than 15 minutes).
	sessionNonceCutoff := now.Add(-15 * time.Minute)
	s.sessionNoncesMu.Lock()
	for nonce, data := range s.sessionNoncesMap {
		if data.IssuedAt.Before(sessionNonceCutoff) {
			delete(s.sessionNoncesMap, nonce)
		}
	}
	s.sessionNoncesMu.Unlock()
	graceSessions.Set(float64(len(s.lastApproval)))
	s.mu.Unlock()
	if data != nil {
		s.writeStateToDisk(data, rotate)
	}
	// Invoke OnExpire callback outside the lock to avoid deadlocks.
	for _, e := range expired {
		s.OnExpire(e.username, e.hostname, e.code)
	}
}

// loadState reads persisted grace sessions and revocation timestamps from the JSON file.
// Handles missing file (first run) and corrupt JSON gracefully — starts fresh.
func (s *ChallengeStore) loadState() {
	if s.persistPath == "" {
		return
	}
	f, err := os.OpenFile(s.persistPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("cannot open session state file — starting fresh", "path", s.persistPath, "err", err)
		}
		return
	}
	defer f.Close()

	// Non-blocking exclusive flock: if another process already holds the lock,
	// a second identree instance is running against the same state file.
	// Log an error and abort loading rather than risk split-brain corruption.
	if flockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); flockErr != nil {
		if flockErr == syscall.EWOULDBLOCK {
			slog.Error("challenge: another identree instance holds the state file lock — refusing to load to prevent data corruption", "path", s.persistPath)
		} else {
			slog.Error("challenge: failed to flock state file on load", "path", s.persistPath, "err", flockErr)
		}
		return
	}
	// Release the lock immediately — we only needed it to detect concurrent instances.
	// writeStateToDisk will reacquire it for each write.
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	info, err := f.Stat()
	if err != nil {
		slog.Warn("cannot stat session state file — starting fresh", "err", err)
		return
	}
	if !info.Mode().IsRegular() {
		slog.Warn("session state file is not a regular file — starting fresh", "path", s.persistPath)
		return
	}
	if info.Mode().Perm()&0077 != 0 {
		slog.Warn("session state file has insecure permissions — starting fresh", "path", s.persistPath, "perm", fmt.Sprintf("%o", info.Mode().Perm()))
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, 10<<20)) // 10MB limit
	if err != nil {
		slog.Warn("cannot read session state file — starting fresh", "path", s.persistPath, "err", err)
		return
	}
	// First pass: try to migrate old escrowed_hosts format (map[string]time.Time)
	// before the main unmarshal, which would fail on type mismatch.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		if eh, ok := raw["escrowed_hosts"]; ok {
			var oldFormat map[string]time.Time
			if json.Unmarshal(eh, &oldFormat) == nil && len(oldFormat) > 0 {
				// Old format detected — convert in-place to new format
				newFormat := make(map[string]EscrowRecord, len(oldFormat))
				for host, ts := range oldFormat {
					newFormat[host] = EscrowRecord{Timestamp: ts}
				}
				if converted, err := json.Marshal(newFormat); err == nil {
					raw["escrowed_hosts"] = converted
					if migrated, merr := json.Marshal(raw); merr == nil {
						data = migrated
						slog.Info("migrated escrowed_hosts entries to new format", "count", len(oldFormat))
					}
				}
			}
		}
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		slog.Warn("corrupt session state file — starting fresh", "path", s.persistPath, "err", err)
		return
	}
	// Version migration check (Fix 3 / C4).
	switch {
	case state.Version == 0:
		// Legacy file written before versioning was introduced — compatible as-is.
		slog.Info("challenge: loaded legacy v0 state, upgrading to v1")
	case state.Version > 1:
		// File was written by a newer identree binary. Load it anyway but warn.
		slog.Warn("challenge: state file is from a newer version", "version", state.Version)
	}
	// Normalise version so the next write upgrades the on-disk format.
	state.Version = 1

	const maxStateMapEntries = 100_000
	const maxGraceSessionTTL = 90 * 24 * time.Hour   // grace sessions > 90 days in future are suspect
	const maxRevokeTokensAge = 30 * 24 * time.Hour    // revoke timestamps > 30 days in future are suspect
	const maxActionLogPerUser = 1000                  // cap per-user action log entries on load

	now := time.Now()
	ceiling := now.Add(maxGraceSessionTTL)
	for key, expiry := range state.GraceSessions {
		if now.Before(expiry) && expiry.Before(ceiling) {
			s.lastApproval[key] = expiry
		}
		if len(s.lastApproval) >= maxStateMapEntries {
			slog.Warn("grace_sessions map in state file exceeds limit — truncating", "limit", maxStateMapEntries)
			break
		}
	}
	revokeCeiling := now.Add(maxRevokeTokensAge)
	for user, ts := range state.RevokeTokensBefore {
		if ts.Before(revokeCeiling) {
			s.revokeTokensBefore[user] = ts
		}
		if len(s.revokeTokensBefore) >= maxStateMapEntries {
			slog.Warn("revoke_tokens_before map in state file exceeds limit — truncating", "limit", maxStateMapEntries)
			break
		}
	}
	for user, entries := range state.ActionLog {
		if len(entries) > maxActionLogPerUser {
			entries = entries[len(entries)-maxActionLogPerUser:]
		}
		s.actionLog[user] = entries
		if len(s.actionLog) >= maxStateMapEntries {
			slog.Warn("action_log map in state file exceeds limit — truncating", "limit", maxStateMapEntries)
			break
		}
	}
	for host, rec := range state.EscrowedHosts {
		s.escrowedHosts[host] = rec
		if len(s.escrowedHosts) >= maxStateMapEntries {
			break
		}
	}
	for host, ct := range state.EscrowedCiphertexts {
		s.escrowedCiphertexts[host] = ct
		if len(s.escrowedCiphertexts) >= maxStateMapEntries {
			break
		}
	}
	rotateCeiling := now.Add(maxRevokeTokensAge)
	for host, ts := range state.RotateBreakglassBefore {
		// Skip timestamps implausibly far in the future (could force-expire all passwords).
		if ts.After(rotateCeiling) {
			continue
		}
		s.rotateBreakglassBefore[host] = ts
		if len(s.rotateBreakglassBefore) >= maxStateMapEntries {
			break
		}
	}
	for user, ts := range state.LastOIDCAuth {
		// Skip future timestamps — a future LastOIDCAuth could suppress re-auth checks.
		if ts.After(now.Add(time.Minute)) {
			continue
		}
		s.lastOIDCAuth[user] = ts
		if len(s.lastOIDCAuth) >= maxStateMapEntries {
			break
		}
	}
	// oneTapUsed is intentionally NOT loaded from persisted state.
	// Challenges are in-memory only and do not survive restarts, so any persisted
	// oneTapUsed IDs have no corresponding challenge and accumulate unboundedly.
	// Dropping them on restart is safe: a challenge that was pending before restart
	// will have expired, and the one-tap token is tied to the challenge ID.

	// Load persisted revoked nonces (prune those older than 35 minutes on load).
	const revokedNonceTTL = 35 * time.Minute
	nonceCutoff := now.Add(-revokedNonceTTL)
	if len(state.RevokedNonces) > 0 {
		s.revokedNoncesStore = make(map[string]int64, len(state.RevokedNonces))
		for nonce, ts := range state.RevokedNonces {
			if time.Unix(ts, 0).After(nonceCutoff) {
				s.revokedNoncesStore[nonce] = ts
			}
			if len(s.revokedNoncesStore) >= maxStateMapEntries {
				break
			}
		}
	}
	// Load persisted admin-session revocations (prune those older than 35 minutes on load).
	if len(state.RevokedAdminSessions) > 0 {
		s.revokedAdminSessionsStore = make(map[string]int64, len(state.RevokedAdminSessions))
		for username, ts := range state.RevokedAdminSessions {
			if time.Unix(ts, 0).After(nonceCutoff) {
				s.revokedAdminSessionsStore[username] = ts
			}
			if len(s.revokedAdminSessionsStore) >= maxStateMapEntries {
				break
			}
		}
	}

	// Load persisted escrow replay tokens (prune those older than 10 minutes on load).
	const escrowTokenTTL = 10 * time.Minute
	escrowTokenCutoff := now.Add(-escrowTokenTTL)
	if len(state.UsedEscrowTokens) > 0 {
		s.usedEscrowTokensMu.Lock()
		for k, ts := range state.UsedEscrowTokens {
			t := time.Unix(ts, 0)
			if t.After(escrowTokenCutoff) { // only restore non-expired entries
				s.usedEscrowTokens[k] = t
			}
			if len(s.usedEscrowTokens) >= maxStateMapEntries {
				break
			}
		}
		s.usedEscrowTokensMu.Unlock()
	}

	slog.Info("loaded session state", "grace_sessions", len(s.lastApproval), "revocations", len(s.revokeTokensBefore), "escrowed_hosts", len(s.escrowedHosts), "path", s.persistPath)
	graceSessions.Set(float64(len(s.lastApproval)))
}

// marshalStateLocked serialises the current in-memory state to JSON.
// Must be called while holding the write lock (s.mu).
// If the marshaled payload exceeds 1 MB the in-memory action logs are pruned
// in-place and the state is re-marshalled; the returned needsRotation flag
// tells writeStateToDisk to rotate archive files before writing the new file.
// Returns (nil, false) when persistPath is empty.
func (s *ChallengeStore) marshalStateLocked() (data []byte, needsRotation bool) {
	if s.persistPath == "" {
		return nil, false
	}
	now := time.Now()
	state := persistedState{
		Version:            1,
		GraceSessions:      make(map[string]time.Time),
		RevokeTokensBefore: make(map[string]time.Time),
		ActionLog:          make(map[string][]ActionLogEntry),
	}
	for key, expiry := range s.lastApproval {
		if now.Before(expiry) {
			state.GraceSessions[key] = expiry
		}
	}
	for user, ts := range s.revokeTokensBefore {
		state.RevokeTokensBefore[user] = ts
	}
	for user, entries := range s.actionLog {
		if len(entries) > 0 {
			state.ActionLog[user] = entries
		}
	}
	if len(s.escrowedHosts) > 0 {
		state.EscrowedHosts = make(map[string]EscrowRecord, len(s.escrowedHosts))
		for host, rec := range s.escrowedHosts {
			state.EscrowedHosts[host] = rec
		}
	}
	if len(s.escrowedCiphertexts) > 0 {
		state.EscrowedCiphertexts = make(map[string]string, len(s.escrowedCiphertexts))
		for host, ct := range s.escrowedCiphertexts {
			state.EscrowedCiphertexts[host] = ct
		}
	}
	if len(s.rotateBreakglassBefore) > 0 {
		state.RotateBreakglassBefore = make(map[string]time.Time, len(s.rotateBreakglassBefore))
		for host, ts := range s.rotateBreakglassBefore {
			state.RotateBreakglassBefore[host] = ts
		}
	}
	if len(s.lastOIDCAuth) > 0 {
		state.LastOIDCAuth = make(map[string]time.Time, len(s.lastOIDCAuth))
		for user, ts := range s.lastOIDCAuth {
			state.LastOIDCAuth[user] = ts
		}
	}
	// Include persisted revoked nonces and admin session revocations.
	// These are stored in side-maps (revokedNoncesStore, revokedAdminSessionsStore)
	// rather than the main state because they are written by the server package.
	s.revokedNoncesMu.Lock()
	if len(s.revokedNoncesStore) > 0 {
		state.RevokedNonces = make(map[string]int64, len(s.revokedNoncesStore))
		for nonce, ts := range s.revokedNoncesStore {
			state.RevokedNonces[nonce] = ts
		}
	}
	s.revokedNoncesMu.Unlock()
	s.revokedAdminSessionsMu.Lock()
	if len(s.revokedAdminSessionsStore) > 0 {
		state.RevokedAdminSessions = make(map[string]int64, len(s.revokedAdminSessionsStore))
		for username, ts := range s.revokedAdminSessionsStore {
			state.RevokedAdminSessions[username] = ts
		}
	}
	s.revokedAdminSessionsMu.Unlock()
	// Snapshot usedEscrowTokens for persistence.
	s.usedEscrowTokensMu.Lock()
	if len(s.usedEscrowTokens) > 0 {
		usedEscrowCopy := make(map[string]int64, len(s.usedEscrowTokens))
		escrowCutoff := time.Now().Add(-10 * time.Minute)
		for k, t := range s.usedEscrowTokens {
			if !t.Before(escrowCutoff) { // only persist non-expired entries
				usedEscrowCopy[k] = t.Unix()
			}
		}
		if len(usedEscrowCopy) > 0 {
			state.UsedEscrowTokens = usedEscrowCopy
		}
	}
	s.usedEscrowTokensMu.Unlock()
	// oneTapUsed is not persisted: challenges are in-memory only and
	// do not survive restarts, so persisting these IDs would accumulate orphans.
	d, err := json.Marshal(state)
	if err != nil {
		slog.Error("marshaling session state", "err", err)
		return nil, false
	}

	// If the serialised state exceeds 1 MB, prune in-memory action logs so
	// the fresh file starts small.  The caller (writeStateToDisk) will rotate
	// archive files before writing the new data.
	if len(d) > 1_000_000 {
		// Collect dropped entries for archiving BEFORE modifying the in-memory log.
		// We only prune in-memory state after a successful archive write so that
		// a failed write leaves entries intact (Fix C6).
		archivedAt := time.Now().UTC().Format(time.RFC3339)
		var toArchive []archivedUserEntries
		// prunedLog holds the post-prune slices for each user; applied only on success.
		prunedLog := make(map[string][]ActionLogEntry)
		for user, entries := range s.actionLog {
			if len(entries) > maxActionLogPrune {
				dropped := entries[:len(entries)-maxActionLogPrune]
				toArchive = append(toArchive, archivedUserEntries{
					Username:   user,
					Entries:    dropped,
					ArchivedAt: archivedAt,
				})
				prunedLog[user] = entries[len(entries)-maxActionLogPrune:]
			}
		}
		// Attempt archive write before touching the in-memory log.
		// If the write fails, skip rotation and keep all entries intact.
		if len(toArchive) > 0 && s.persistPath != "" {
			archivePath := filepath.Join(filepath.Dir(s.persistPath), "sessions.archive.jsonl")
			if !s.appendToArchive(archivePath, toArchive) {
				slog.Warn("challenge: archive write failed — skipping action log rotation to preserve entries")
				return d, false
			}
		}
		// Archive succeeded (or nothing needed archiving): apply in-memory prune.
		for user, kept := range prunedLog {
			s.actionLog[user] = kept
		}
		state.ActionLog = make(map[string][]ActionLogEntry)
		for user, entries := range s.actionLog {
			if len(entries) > 0 {
				state.ActionLog[user] = entries
			}
		}
		d, err = json.Marshal(state)
		if err != nil {
			slog.Error("re-marshaling session state after prune", "err", err)
			return nil, false
		}
		return d, true
	}
	return d, false
}

// appendToArchive appends the given archived user entries to the JSONL archive file,
// rotating it if it exceeds 10 MB. Keeps up to 5 numbered archive files (.1–.5).
// All entries are serialised to an in-memory buffer and written in a single call
// so that a partial write cannot corrupt the file (Fix C6/H10).
// Returns true on success, false if any error prevented the write.
func (s *ChallengeStore) appendToArchive(archivePath string, entries []archivedUserEntries) bool {
	const maxArchiveSize = 10 << 20 // 10 MB
	const maxArchiveFiles = 5

	// Rotate archive if it has grown too large.
	if info, err := os.Stat(archivePath); err == nil && info.Size() >= maxArchiveSize {
		// Shift existing numbered files: delete .5, rename .4→.5, .3→.4, … .1→.2.
		os.Remove(fmt.Sprintf("%s.%d", archivePath, maxArchiveFiles))
		for i := maxArchiveFiles - 1; i >= 1; i-- {
			src := fmt.Sprintf("%s.%d", archivePath, i)
			dst := fmt.Sprintf("%s.%d", archivePath, i+1)
			os.Rename(src, dst) // best-effort; file may not exist
		}
		if err := os.Rename(archivePath, archivePath+".1"); err != nil {
			slog.Warn("challenge: failed to rotate archive file", "path", archivePath, "err", err)
			// Continue — we'll still try to append/create a fresh file.
		}
	}

	// Serialise all entries into a buffer first so the file write is a single
	// syscall, preventing a partial-write from producing a truncated JSON line.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, item := range entries {
		if err := enc.Encode(item); err != nil {
			slog.Warn("challenge: failed to encode archive entry", "err", err)
			return false
		}
	}

	f, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		slog.Warn("challenge: failed to open archive file", "path", archivePath, "err", err)
		return false
	}
	defer f.Close()

	if _, err := f.Write(buf.Bytes()); err != nil {
		slog.Warn("challenge: failed to write archive entries", "path", archivePath, "err", err)
		return false
	}
	if err := f.Sync(); err != nil {
		slog.Warn("challenge: failed to sync archive file", "path", archivePath, "err", err)
		return false
	}
	return true
}

// flockWithTimeout acquires an exclusive advisory flock on f within the given
// timeout. Returns nil on success, an error if the lock cannot be acquired.
func flockWithTimeout(f *os.File, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("flock timeout after %s", timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// writeStateToDisk atomically writes data to the persist file.
// If needsRotation is true the current file is archived (sessions.json →
// sessions.json.1 etc.) before the new file is written.
// No-op when data is nil (persistPath was empty or marshal failed).
// Serialises concurrent writers via s.diskMu and an advisory flock.
func (s *ChallengeStore) writeStateToDisk(data []byte, needsRotation bool) bool {
	if data == nil {
		return true
	}
	s.diskMu.Lock()
	defer s.diskMu.Unlock()

	// Acquire an exclusive advisory flock on the destination file to prevent a
	// second identree instance from writing concurrently. Create the file if it
	// does not yet exist so we always have a file descriptor to lock.
	lockFile, err := os.OpenFile(s.persistPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		slog.Error("challenge: cannot open state file for locking", "err", err)
		return false
	}
	defer lockFile.Close()
	if err := flockWithTimeout(lockFile, 5*time.Second); err != nil {
		slog.Error("challenge: cannot acquire flock on state file", "err", err)
		return false
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck

	if needsRotation {
		s.rotateStateFiles()
	}

	// Atomic write: temp file + rename (same pattern as writeBreakglassFile).
	dir := filepath.Dir(s.persistPath) + "/"
	tmp, err := os.CreateTemp(dir, ".sessions-tmp-*")
	if err != nil {
		slog.Error("creating temp session state file", "err", err)
		return false
	}
	tmpName := tmp.Name()
	// Set permissions before writing so the file is never readable by others,
	// even briefly (avoids a world-readable window if umask is 0).
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		slog.Error("setting session state permissions", "err", err)
		return false
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		slog.Error("writing session state", "err", err)
		return false
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		slog.Error("syncing session state", "err", err)
		return false
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		slog.Error("closing session state temp file", "err", err)
		return false
	}
	if err := os.Rename(tmpName, s.persistPath); err != nil {
		os.Remove(tmpName)
		slog.Error("renaming session state file", "err", err)
		return false
	}
	// Sync the parent directory so the rename is durable on power loss.
	if d, err := os.Open(filepath.Dir(s.persistPath)); err == nil {
		if syncErr := d.Sync(); syncErr != nil {
			slog.Warn("challenge: failed to sync parent directory after state write", "err", syncErr)
		}
		d.Close()
	}
	return true
}

// rotateStateFiles shifts existing archive files to make room for a new backup.
// sessions.json.8 → sessions.json.9, sessions.json.7 → sessions.json.8, ...,
// sessions.json → sessions.json.1.  Maximum 9 numbered archives (.1 through .9).
func (s *ChallengeStore) rotateStateFiles() {
	for i := 8; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", s.persistPath, i)
		dst := fmt.Sprintf("%s.%d", s.persistPath, i+1)
		// Best-effort: ignore errors (file may not exist yet).
		os.Rename(src, dst)
	}
	// Copy current file to .1 (rename would leave us without the original during write).
	os.Rename(s.persistPath, s.persistPath+".1")
}

// SaveState persists the current grace sessions and revocation timestamps.
// Intended for graceful shutdown — acquires the lock before saving.
func (s *ChallengeStore) SaveState() {
	if s.persistPath == "" {
		return
	}
	s.mu.Lock()
	data, rotate := s.marshalStateLocked()
	s.mu.Unlock()
	s.writeStateToDisk(data, rotate)
}

// HealthCheck verifies the local store is operational. For the file-backed store
// this checks that the persist directory is writable (when persistence is enabled).
func (s *ChallengeStore) HealthCheck() error {
	if s.persistPath == "" {
		return nil
	}
	dir := filepath.Dir(s.persistPath)
	tmp, err := os.CreateTemp(dir, ".healthz-store-*")
	if err != nil {
		return fmt.Errorf("store health check: %w", err)
	}
	tmp.Close()
	os.Remove(tmp.Name())
	return nil
}

// StoreSessionNonce stores OIDC login state for an in-flight session.
// For the local store this is an in-memory map; ttl is ignored (pruning is
// handled by the server's periodic cleanup goroutine).
func (s *ChallengeStore) StoreSessionNonce(nonce string, data SessionNonceData, _ time.Duration) error {
	s.sessionNoncesMu.Lock()
	defer s.sessionNoncesMu.Unlock()
	s.sessionNoncesMap[nonce] = data
	return nil
}

// GetSessionNonce retrieves OIDC login state by nonce.
func (s *ChallengeStore) GetSessionNonce(nonce string) (SessionNonceData, bool) {
	s.sessionNoncesMu.Lock()
	defer s.sessionNoncesMu.Unlock()
	d, ok := s.sessionNoncesMap[nonce]
	return d, ok
}

// DeleteSessionNonce removes OIDC login state for the given nonce.
func (s *ChallengeStore) DeleteSessionNonce(nonce string) {
	s.sessionNoncesMu.Lock()
	defer s.sessionNoncesMu.Unlock()
	delete(s.sessionNoncesMap, nonce)
}

// generateUserCode creates a human-friendly code like "ABCDEF-123456".
// Uses 6 letters (24^6 = ~191M) + 6 digits (10^6 = 1M) = ~191 billion combinations.
// This makes brute-force enumeration of active codes infeasible within the TTL window.
func generateUserCode() (string, error) {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I, O (ambiguous)
	const digits = "0123456789"

	code := make([]byte, 13) // XXXXXX-YYYYYY
	for i := 0; i < 6; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		code[i] = letters[n.Int64()]
	}
	code[6] = '-'
	for i := 7; i < 13; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[n.Int64()]
	}
	return string(code), nil
}

