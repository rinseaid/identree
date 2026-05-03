package challenge

import (
	"context"
	"time"
)

// Store is the interface that any challenge state backend must implement.
// The SQL-backed SQLStore is the only implementation.
type Store interface {
	// Lifecycle
	Stop()
	SaveState()

	// SetGraceHMACKey sets the HMAC key used to sign and verify grace session values.
	SetGraceHMACKey(key []byte)

	// Challenge CRUD
	Create(ctx context.Context, username, hostname, breakglassRotateBefore, reason string) (*Challenge, error)
	Get(ctx context.Context, id string) (Challenge, bool)
	GetByCode(ctx context.Context, code string) (Challenge, bool)
	SetNonce(ctx context.Context, id string, nonce string) error
	SetRequestedGrace(ctx context.Context, id string, d time.Duration)
	Approve(ctx context.Context, id string, approvedBy string) error
	// AddApproval records a partial approval for multi-approval challenges.
	// Returns true if this approval met the threshold (challenge is now fully approved).
	// Returns false if more approvals are still needed.
	// Returns error if the challenge doesn't exist, is not pending, the approver
	// already approved, or the challenge is expired.
	AddApproval(ctx context.Context, id string, approver string, requiredApprovals int) (fullyApproved bool, err error)
	SetBreakglassOverride(ctx context.Context, id string)
	// SetChallengePolicy persists the policy outcome on a freshly-created
	// challenge so subsequent Approve/AddApproval calls can read it.
	SetChallengePolicy(ctx context.Context, id, policyName string, requiredApprovals int, requireAdmin, breakglassBypassAllowed bool)
	Deny(ctx context.Context, id, reason string) error
	AutoApprove(ctx context.Context, id string) error
	AutoApproveIfWithinGracePeriod(ctx context.Context, username, hostname, id string) bool

	// One-tap
	ConsumeOneTap(ctx context.Context, challengeID string) error
	ConsumeAndApprove(ctx context.Context, challengeID, approvedBy string) error

	// Grace period / sessions
	WithinGracePeriod(ctx context.Context, username, hostname string) bool
	GraceRemaining(ctx context.Context, username, hostname string) time.Duration
	ActiveSessions(ctx context.Context, username string) []GraceSession
	AllActiveSessions(ctx context.Context) []GraceSession
	ActiveSessionsForHost(ctx context.Context, hostname string) []GraceSession
	CreateGraceSession(ctx context.Context, username, hostname string, duration time.Duration)
	ExtendGraceSession(ctx context.Context, username, hostname string) (time.Duration, error)
	ForceExtendGraceSession(ctx context.Context, username, hostname string) time.Duration
	ExtendGraceSessionFor(ctx context.Context, username, hostname string, dur time.Duration) time.Duration
	RevokeSession(ctx context.Context, username, hostname string)

	// Challenge queries
	PendingChallenges(ctx context.Context, username string) []Challenge
	AllPendingChallenges(ctx context.Context) []Challenge

	// Revocation
	RevokeTokensBefore(ctx context.Context, username string) time.Time

	// OIDC auth tracking
	RecordOIDCAuth(ctx context.Context, username string)
	LastOIDCAuth(ctx context.Context, username string) time.Time

	// Action log
	LogAction(ctx context.Context, username, action, hostname, code, actor string)
	LogActionWithReason(ctx context.Context, username, action, hostname, code, actor, reason string)
	LogActionAt(ctx context.Context, username, action, hostname, code, actor string, at time.Time)
	ActionHistory(ctx context.Context, username string, limit int) []ActionLogEntry
	AllActionHistory(ctx context.Context, limit int) []ActionLogEntry
	AllActionHistoryWithUsers(ctx context.Context, limit, offset int) []ActionLogEntryWithUser

	// Host data
	KnownHosts(ctx context.Context, username string) []string
	AllKnownHosts(ctx context.Context) []string
	UsersWithHostActivity(ctx context.Context, hostname string) []string
	RemoveHost(ctx context.Context, hostname string)

	// Escrow
	RecordEscrow(ctx context.Context, hostname, itemID, vaultID string)
	StoreEscrowCiphertext(ctx context.Context, hostname, ciphertext string)
	GetEscrowCiphertext(ctx context.Context, hostname string) (string, bool)
	EscrowedHosts(ctx context.Context) map[string]EscrowRecord

	// Host rotation
	SetHostRotateBefore(ctx context.Context, hostname string)
	HostRotateBefore(ctx context.Context, hostname string) time.Time
	SetAllHostsRotateBefore(ctx context.Context, hostnames []string)

	// User management
	AllUsers(ctx context.Context) []string
	RemoveUser(ctx context.Context, username string)

	// Session persistence (revoked nonces / admin sessions)
	PersistRevokedNonce(ctx context.Context, nonce string, at time.Time)
	PersistRevokedAdminSession(ctx context.Context, username string, at time.Time)
	LoadRevokedNonces(ctx context.Context) map[string]time.Time
	LoadRevokedAdminSessions(ctx context.Context) map[string]time.Time

	// Escrow token replay prevention
	CheckAndRecordEscrowToken(ctx context.Context, tokenKey string) (alreadySeen bool)
	UsedEscrowTokenCount(ctx context.Context) int

	// Health check
	HealthCheck(ctx context.Context) error

	// Session nonces (OIDC login state)
	StoreSessionNonce(ctx context.Context, nonce string, data SessionNonceData, ttl time.Duration) error
	GetSessionNonce(ctx context.Context, nonce string) (SessionNonceData, bool)
	DeleteSessionNonce(ctx context.Context, nonce string)

	// Agent heartbeats
	RecordHeartbeat(ctx context.Context, h AgentHeartbeat)
	ListAgents(ctx context.Context) []AgentStatus

	// Schema version
	SchemaVersion(ctx context.Context) int
}

// AgentHeartbeat carries a single ping from a managed host.
type AgentHeartbeat struct {
	Hostname string
	Version  string
	OSInfo   string
	IP       string
}

// AgentStatus is the per-host record returned to dashboard handlers.
type AgentStatus struct {
	Hostname  string
	Version   string
	OSInfo    string
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
}

// SessionNonceData holds state for an in-flight OIDC login.
type SessionNonceData struct {
	IssuedAt     time.Time
	CodeVerifier string // PKCE code verifier; empty for legacy sessions
	ClientIP     string // client IP at login initiation for state binding
}

