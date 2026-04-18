package challenge

import "time"

// Store is the interface that any challenge state backend must implement.
// The SQL-backed SQLStore is the only implementation.
type Store interface {
	// Lifecycle
	Stop()
	SaveState()

	// SetGraceHMACKey sets the HMAC key used to sign and verify grace session values.
	SetGraceHMACKey(key []byte)

	// Challenge CRUD
	Create(username, hostname, breakglassRotateBefore, reason string) (*Challenge, error)
	Get(id string) (Challenge, bool)
	GetByCode(code string) (Challenge, bool)
	SetNonce(id string, nonce string) error
	SetRequestedGrace(id string, d time.Duration)
	Approve(id string, approvedBy string) error
	// AddApproval records a partial approval for multi-approval challenges.
	// Returns true if this approval met the threshold (challenge is now fully approved).
	// Returns false if more approvals are still needed.
	// Returns error if the challenge doesn't exist, is not pending, the approver
	// already approved, or the challenge is expired.
	AddApproval(id string, approver string, requiredApprovals int) (fullyApproved bool, err error)
	SetBreakglassOverride(id string)
	// SetChallengePolicy persists the policy outcome on a freshly-created
	// challenge so subsequent Approve/AddApproval calls can read it.
	SetChallengePolicy(id, policyName string, requiredApprovals int, requireAdmin, breakglassBypassAllowed bool)
	Deny(id, reason string) error
	AutoApprove(id string) error
	AutoApproveIfWithinGracePeriod(username, hostname, id string) bool

	// One-tap
	ConsumeOneTap(challengeID string) error
	ConsumeAndApprove(challengeID, approvedBy string) error

	// Grace period / sessions
	WithinGracePeriod(username, hostname string) bool
	GraceRemaining(username, hostname string) time.Duration
	ActiveSessions(username string) []GraceSession
	AllActiveSessions() []GraceSession
	ActiveSessionsForHost(hostname string) []GraceSession
	CreateGraceSession(username, hostname string, duration time.Duration)
	ExtendGraceSession(username, hostname string) (time.Duration, error)
	ForceExtendGraceSession(username, hostname string) time.Duration
	ExtendGraceSessionFor(username, hostname string, dur time.Duration) time.Duration
	RevokeSession(username, hostname string)

	// Challenge queries
	PendingChallenges(username string) []Challenge
	AllPendingChallenges() []Challenge

	// Revocation
	RevokeTokensBefore(username string) time.Time

	// OIDC auth tracking
	RecordOIDCAuth(username string)
	LastOIDCAuth(username string) time.Time

	// Action log
	LogAction(username, action, hostname, code, actor string)
	LogActionWithReason(username, action, hostname, code, actor, reason string)
	LogActionAt(username, action, hostname, code, actor string, at time.Time)
	ActionHistory(username string, limit int) []ActionLogEntry
	AllActionHistory() []ActionLogEntry
	AllActionHistoryWithUsers() []ActionLogEntryWithUser

	// Host data
	KnownHosts(username string) []string
	AllKnownHosts() []string
	UsersWithHostActivity(hostname string) []string
	RemoveHost(hostname string)

	// Escrow
	RecordEscrow(hostname, itemID, vaultID string)
	StoreEscrowCiphertext(hostname, ciphertext string)
	GetEscrowCiphertext(hostname string) (string, bool)
	EscrowedHosts() map[string]EscrowRecord

	// Host rotation
	SetHostRotateBefore(hostname string)
	HostRotateBefore(hostname string) time.Time
	SetAllHostsRotateBefore(hostnames []string)

	// User management
	AllUsers() []string
	RemoveUser(username string)

	// Session persistence (revoked nonces / admin sessions)
	PersistRevokedNonce(nonce string, at time.Time)
	PersistRevokedAdminSession(username string, at time.Time)
	LoadRevokedNonces() map[string]time.Time
	LoadRevokedAdminSessions() map[string]time.Time

	// Escrow token replay prevention
	CheckAndRecordEscrowToken(tokenKey string) (alreadySeen bool)
	UsedEscrowTokenCount() int

	// Health check
	HealthCheck() error

	// Session nonces (OIDC login state)
	StoreSessionNonce(nonce string, data SessionNonceData, ttl time.Duration) error
	GetSessionNonce(nonce string) (SessionNonceData, bool)
	DeleteSessionNonce(nonce string)
}

// SessionNonceData holds state for an in-flight OIDC login.
type SessionNonceData struct {
	IssuedAt     time.Time
	CodeVerifier string // PKCE code verifier; empty for legacy sessions
	ClientIP     string // client IP at login initiation for state binding
}

