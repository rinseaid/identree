// Package challenge holds the sudo-elevation challenge model and the
// SQL-backed store that persists challenges, grace sessions, action log,
// and other server state. This file contains only shared types and
// helpers; the storage implementation lives in sqlstore*.go.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ── Action log action constants ─────────────────────────────────────────────

const (
	ActionApproved = "approved"
	// ActionDenied is a historical alias for the "denied" challenge status value.
	// The action log uses ActionRejected ("rejected") for all user-denial events.
	ActionDenied             = "denied"
	ActionRejected           = "rejected"
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
	ActionConfigChanged      = "config_changed"
	ActionSudoRuleModified   = "sudo_rule_modified"
	ActionClaimsUpdated      = "claims_updated"
	ActionServerRestarted    = "server_restarted"
	ActionBreakglassOverride = "breakglass_override"
	ActionBreakglassUsed     = "breakglass_used"
)

// ── Sentinel errors ─────────────────────────────────────────────────────────

var (
	ErrTooManyChallenges           = errors.New("too many active challenges")
	ErrTooManyPerUser              = errors.New("too many pending challenges for user")
	ErrSessionSufficientlyExtended = errors.New("session already has sufficient remaining time")
	// ErrDiskWriteFailed is returned when an Approve/ConsumeAndApprove cannot
	// durably persist the approval. Callers should propagate as 503 so the
	// PAM client retries instead of caching a possibly-lost approval.
	ErrDiskWriteFailed = errors.New("challenge: disk write failed, please retry")
	// ErrDuplicateApprover is returned when the same approver tries to approve twice.
	ErrDuplicateApprover = errors.New("approver has already approved this challenge")
	// ErrAlreadyResolved is returned when an operation targets a challenge that
	// is no longer pending (already approved, denied, or expired).
	ErrAlreadyResolved = errors.New("challenge already resolved")
)

// ── Challenge model ─────────────────────────────────────────────────────────

type ChallengeStatus string

const (
	StatusPending  ChallengeStatus = "pending"
	StatusApproved ChallengeStatus = "approved"
	StatusDenied   ChallengeStatus = "denied"
	StatusExpired  ChallengeStatus = "expired"
)

const (
	maxChallengesPerUser = 10
	maxTotalChallenges   = 10000
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
	Nonce string `json:"-"`

	Hostname string `json:"hostname,omitempty"`
	Reason   string `json:"reason,omitempty"`

	// BreakglassRotateBefore is the server's rotation signal at challenge creation.
	BreakglassRotateBefore string `json:"-"`

	// RequestedGrace is the per-challenge grace duration selected by the user
	// on the approval page. Zero means use the server's default grace period.
	RequestedGrace time.Duration `json:"-"`

	// RevokeTokensBefore is the server's revocation signal at challenge creation.
	RevokeTokensBefore string `json:"-"`

	// Policy fields — set at challenge creation from the policy engine evaluation.
	PolicyName        string `json:"policy_name,omitempty"`
	RequiredApprovals int    `json:"required_approvals,omitempty"`
	RequireAdmin      bool   `json:"require_admin,omitempty"`
	GraceEligible     bool   `json:"-"` // evaluated at creation, not persisted

	// BreakglassOverride indicates this challenge was force-approved via break-glass policy override.
	BreakglassOverride bool `json:"breakglass_override,omitempty"`

	// BreakglassBypassAllowed is set at challenge creation from the matching policy.
	BreakglassBypassAllowed bool `json:"-"`

	DenyReason string `json:"deny_reason,omitempty"`

	ApprovedBy string    `json:"-"`
	ApprovedAt time.Time `json:"-"`

	// Approvals tracks all approvers for multi-approval challenges.
	Approvals []ApprovalRecord `json:"approvals,omitempty"`

	// RawIDToken stores the OIDC id_token after approval, for forwarding to
	// the PAM client's token cache. Not serialized to JSON.
	RawIDToken string `json:"-"`
}

// ActionLogEntry records an action taken on the dashboard.
type ActionLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Hostname  string    `json:"hostname"`
	Code      string    `json:"code,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// ActionLogEntryWithUser extends ActionLogEntry with the owning username,
// used for cross-user exports.
type ActionLogEntryWithUser struct {
	Username  string    `json:"username"`
	Actor     string    `json:"actor,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Hostname  string    `json:"hostname"`
	Code      string    `json:"code,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// EscrowRecord stores metadata about a host's escrowed break-glass password.
type EscrowRecord struct {
	Timestamp time.Time `json:"timestamp"`
	ItemID    string    `json:"item_id,omitempty"`
	VaultID   string    `json:"vault_id,omitempty"`
}

// ── Prometheus metrics ──────────────────────────────────────────────────────

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

// ── Helpers ─────────────────────────────────────────────────────────────────

// computeGraceHMAC returns the hex-encoded HMAC-SHA256 of username, hostname,
// and expiry. Used by SQLStore.signGrace / verifyGrace to detect tampering of
// grace_sessions rows in the database.
func computeGraceHMAC(key []byte, username, hostname string, expiryUnix int64) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(username + "\x00" + hostname + "\x00" + strconv.FormatInt(expiryUnix, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateUserCode returns a fresh "XXXXXX-YYYYYY" code for a new challenge.
// Letters: A-Z without I and O (visually ambiguous). Digits: 0-9.
func generateUserCode() (string, error) {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const digits = "0123456789"

	code := make([]byte, 13)
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
