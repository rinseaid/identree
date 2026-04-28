package challenge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rinseaid/identree/internal/randutil"
)

// challengeColumns lists every column read into a Challenge struct, in the
// order scanChallengeRow expects.
const challengeColumns = `id, user_code, username, status, hostname, reason, nonce,
	created_at, expires_at, approved_by, approved_at, deny_reason,
	breakglass_rotate_before, requested_grace_ns, revoke_tokens_before,
	policy_name, required_approvals, require_admin, breakglass_override,
	breakglass_bypass_allowed, one_tap_used, approvals_json, raw_id_token`

// rowScanner is satisfied by *sql.Row and the result of *sql.Rows.Scan.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanChallenge decodes one challenge row.
func scanChallenge(r rowScanner) (Challenge, error) {
	var (
		c                                                                              Challenge
		createdAt, expiresAt, approvedAt                                               int64
		requestedGraceNS                                                               int64
		requireAdmin, breakglassOverride, breakglassBypassAllowed, oneTapUsed          int
		approvalsJSON                                                                  string
	)
	err := r.Scan(
		&c.ID, &c.UserCode, &c.Username, &c.Status, &c.Hostname, &c.Reason, &c.Nonce,
		&createdAt, &expiresAt, &c.ApprovedBy, &approvedAt, &c.DenyReason,
		&c.BreakglassRotateBefore, &requestedGraceNS, &c.RevokeTokensBefore,
		&c.PolicyName, &c.RequiredApprovals, &requireAdmin, &breakglassOverride,
		&breakglassBypassAllowed, &oneTapUsed, &approvalsJSON, &c.RawIDToken,
	)
	if err != nil {
		return Challenge{}, err
	}
	c.CreatedAt = unixToTime(createdAt)
	c.ExpiresAt = unixToTime(expiresAt)
	c.ApprovedAt = unixToTime(approvedAt)
	c.RequestedGrace = time.Duration(requestedGraceNS)
	c.RequireAdmin = requireAdmin != 0
	c.BreakglassOverride = breakglassOverride != 0
	c.BreakglassBypassAllowed = breakglassBypassAllowed != 0
	if approvalsJSON != "" && approvalsJSON != "[]" {
		if err := json.Unmarshal([]byte(approvalsJSON), &c.Approvals); err != nil {
			// Don't fail the whole read on a corrupt approvals blob — just leave it empty.
			logErr("scanChallenge.Approvals", err)
			c.Approvals = nil
		}
	}
	// One-tap-used is a struct-internal column; we expose it via the
	// dedicated ConsumeOneTap path so it doesn't appear on Challenge directly.
	_ = oneTapUsed
	return c, nil
}

// ── Create ──────────────────────────────────────────────────────────────────

// Create generates a new challenge with a user code and persists it.
// Cap enforcement (per-user and total pending) happens in the same
// transaction as the insert. Under concurrent racing creates on Postgres
// the cap can overrun by 1–2 entries; this is acceptable since the cap
// exists for DoS protection and the legacy contract is preserved by
// SQLite via single-writer serialization.
func (s *SQLStore) Create(username, hostname, breakglassRotateBefore, reason string) (*Challenge, error) {
	id, err := randutil.Hex(16)
	if err != nil {
		return nil, fmt.Errorf("generating challenge ID: %w", err)
	}
	code, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}
	now := time.Now()
	expires := now.Add(s.ttl)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Per-host rotate-before may be newer than the global value passed in.
	revokeTokensBefore := ""
	if t := s.RevokeTokensBefore(username); !t.IsZero() {
		revokeTokensBefore = t.Format(time.RFC3339)
	}
	if hostname != "" {
		if perHostT := s.HostRotateBefore(hostname); !perHostT.IsZero() {
			var globalT time.Time
			if breakglassRotateBefore != "" {
				if t, perr := time.Parse(time.RFC3339, breakglassRotateBefore); perr == nil {
					globalT = t
				}
			}
			if perHostT.After(globalT) {
				breakglassRotateBefore = perHostT.Format(time.RFC3339)
			}
		}
	}

	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var totalPending int
	if err := tx.QueryRowContext(ctx, s.q(
		`SELECT COUNT(*) FROM challenges WHERE status = ? AND expires_at > ?`),
		string(StatusPending), now.Unix()).Scan(&totalPending); err != nil {
		return nil, err
	}
	if totalPending >= maxTotalChallenges {
		return nil, fmt.Errorf("try again later: %w", ErrTooManyChallenges)
	}

	var perUserPending int
	if err := tx.QueryRowContext(ctx, s.q(
		`SELECT COUNT(*) FROM challenges WHERE username = ? AND status = ? AND expires_at > ?`),
		username, string(StatusPending), now.Unix()).Scan(&perUserPending); err != nil {
		return nil, err
	}
	if perUserPending >= maxChallengesPerUser {
		return nil, fmt.Errorf("user %q, wait for existing ones to expire: %w", username, ErrTooManyPerUser)
	}

	if _, err := tx.ExecContext(ctx, s.q(
		`INSERT INTO challenges (id, user_code, username, status, hostname, reason, nonce,
			created_at, expires_at, breakglass_rotate_before, revoke_tokens_before)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?)`),
		id, code, username, string(StatusPending), hostname, reason,
		now.Unix(), expires.Unix(), breakglassRotateBefore, revokeTokensBefore,
	); err != nil {
		// UNIQUE violation on user_code is the realistic failure mode;
		// callers should retry with a fresh code.
		return nil, fmt.Errorf("user code collision, try again: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.dirty.Store(true)
	// ActiveChallenges is incremented by the API handler after Create returns,
	// matching the legacy contract.

	return &Challenge{
		ID:                     id,
		UserCode:               code,
		Username:               username,
		Hostname:               hostname,
		Reason:                 reason,
		BreakglassRotateBefore: breakglassRotateBefore,
		RevokeTokensBefore:     revokeTokensBefore,
		Status:                 StatusPending,
		CreatedAt:              now,
		ExpiresAt:              expires,
	}, nil
}

// ── Get / GetByCode ─────────────────────────────────────────────────────────

func (s *SQLStore) Get(id string) (Challenge, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	row := s.queryRow(ctx, `SELECT `+challengeColumns+` FROM challenges WHERE id = ?`, id)
	c, err := scanChallenge(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Challenge{}, false
	}
	if err != nil {
		logErr("Get", err)
		return Challenge{}, false
	}
	if time.Now().After(c.ExpiresAt) {
		return Challenge{}, false
	}
	return c, true
}

func (s *SQLStore) GetByCode(code string) (Challenge, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	row := s.queryRow(ctx, `SELECT `+challengeColumns+` FROM challenges WHERE user_code = ?`, code)
	c, err := scanChallenge(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Challenge{}, false
	}
	if err != nil {
		logErr("GetByCode", err)
		return Challenge{}, false
	}
	if time.Now().After(c.ExpiresAt) {
		return Challenge{}, false
	}
	return c, true
}

// ── Light setters ───────────────────────────────────────────────────────────

func (s *SQLStore) SetNonce(id string, nonce string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		status     string
		expiresAt  int64
		nonceCur   string
	)
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT status, expires_at, nonce FROM challenges WHERE id = ?`+s.forUpdate()),
		id).Scan(&status, &expiresAt, &nonceCur)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("challenge not found")
	}
	if err != nil {
		return err
	}
	if time.Now().After(unixToTime(expiresAt)) {
		return fmt.Errorf("challenge expired")
	}
	if ChallengeStatus(status) != StatusPending {
		return ErrAlreadyResolved
	}
	if nonceCur != "" {
		return fmt.Errorf("nonce already set (login already initiated)")
	}
	if _, err := tx.ExecContext(ctx, s.q(`UPDATE challenges SET nonce = ? WHERE id = ?`), nonce, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.dirty.Store(true)
	return nil
}

func (s *SQLStore) SetRequestedGrace(id string, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := s.exec(ctx, `UPDATE challenges SET requested_grace_ns = ? WHERE id = ?`, int64(d), id); err != nil {
		logErr("SetRequestedGrace", err)
	}
}

func (s *SQLStore) SetBreakglassOverride(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := s.exec(ctx, `UPDATE challenges SET breakglass_override = 1 WHERE id = ?`, id); err != nil {
		logErr("SetBreakglassOverride", err)
	}
}

func (s *SQLStore) SetChallengePolicy(id, policyName string, requiredApprovals int, requireAdmin, breakglassBypassAllowed bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := s.exec(ctx,
		`UPDATE challenges
		 SET policy_name = ?, required_approvals = ?, require_admin = ?, breakglass_bypass_allowed = ?
		 WHERE id = ?`,
		policyName, requiredApprovals, boolToInt(requireAdmin), boolToInt(breakglassBypassAllowed), id); err != nil {
		logErr("SetChallengePolicy", err)
	}
}

// ── Approve / Deny / AddApproval ────────────────────────────────────────────

// approveCommon shares the read-modify-write body for Approve and ConsumeAndApprove.
// Returns the loaded challenge (with grace info) on success.
type approveResult struct {
	username       string
	hostname       string
	requestedGrace time.Duration
}

// resolvePendingChallenge verifies the challenge is still pending and not
// expired, and not superseded by a session revocation, returning enough
// context for the caller to compute a new grace expiry.
func (s *SQLStore) resolvePendingChallenge(ctx context.Context, tx *sql.Tx, id string) (approveResult, error) {
	var (
		status                                string
		username, hostname                    string
		createdAt, expiresAt, requestedGrace int64
	)
	err := tx.QueryRowContext(ctx, s.q(
		`SELECT status, username, hostname, created_at, expires_at, requested_grace_ns
		 FROM challenges WHERE id = ?`+s.forUpdate()),
		id).Scan(&status, &username, &hostname, &createdAt, &expiresAt, &requestedGrace)
	if errors.Is(err, sql.ErrNoRows) {
		return approveResult{}, fmt.Errorf("challenge not found")
	}
	if err != nil {
		return approveResult{}, err
	}
	now := time.Now()
	if now.After(unixToTime(expiresAt)) {
		return approveResult{}, fmt.Errorf("challenge expired")
	}
	if ChallengeStatus(status) != StatusPending {
		return approveResult{}, ErrAlreadyResolved
	}
	// Session revocation check.
	var revokedAt int64
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT revoked_at FROM revoke_tokens_before WHERE username = ?`),
		username).Scan(&revokedAt)
	if err == nil && revokedAt > createdAt {
		return approveResult{}, fmt.Errorf("challenge superseded by session revocation")
	}
	return approveResult{
		username:       username,
		hostname:       hostname,
		requestedGrace: time.Duration(requestedGrace),
	}, nil
}

// finalizeApproval marks a challenge approved, optionally creates the grace
// session, and commits. Caller must already hold the row lock.
func (s *SQLStore) finalizeApproval(ctx context.Context, tx *sql.Tx, id, approvedBy string, info approveResult, createGrace bool) error {
	now := time.Now()
	if _, err := tx.ExecContext(ctx, s.q(
		`UPDATE challenges SET status = ?, approved_by = ?, approved_at = ? WHERE id = ?`),
		string(StatusApproved), approvedBy, now.Unix(), id); err != nil {
		return err
	}
	if createGrace && s.gracePeriod > 0 {
		dur := info.requestedGrace
		if dur == 0 {
			dur = s.gracePeriod
		}
		if err := s.upsertGrace(ctx, tx, info.username, info.hostname, now.Add(dur)); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) Approve(id string, approvedBy string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	info, err := s.resolvePendingChallenge(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := s.finalizeApproval(ctx, tx, id, approvedBy, info, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrDiskWriteFailed
	}
	s.dirty.Store(true)
	ActiveChallenges.Dec()
	s.refreshGraceMetric(ctx)
	return nil
}

func (s *SQLStore) AddApproval(id string, approver string, requiredApprovals int) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	info, err := s.resolvePendingChallenge(ctx, tx, id)
	if err != nil {
		return false, err
	}

	// Fetch current approvals JSON, append, check threshold.
	var approvalsJSON string
	if err := tx.QueryRowContext(ctx, s.q(
		`SELECT approvals_json FROM challenges WHERE id = ?`+s.forUpdate()),
		id).Scan(&approvalsJSON); err != nil {
		return false, err
	}
	var approvals []ApprovalRecord
	if approvalsJSON != "" && approvalsJSON != "[]" {
		if err := json.Unmarshal([]byte(approvalsJSON), &approvals); err != nil {
			return false, fmt.Errorf("decoding approvals: %w", err)
		}
	}
	for _, a := range approvals {
		if a.Approver == approver {
			return false, ErrDuplicateApprover
		}
	}
	now := time.Now()
	approvals = append(approvals, ApprovalRecord{Approver: approver, ApprovedAt: now})
	updated, err := json.Marshal(approvals)
	if err != nil {
		return false, fmt.Errorf("encoding approvals: %w", err)
	}
	fullyApproved := len(approvals) >= requiredApprovals

	if fullyApproved {
		if _, err := tx.ExecContext(ctx, s.q(
			`UPDATE challenges SET status = ?, approved_by = ?, approved_at = ?, approvals_json = ?
			 WHERE id = ?`),
			string(StatusApproved), approver, now.Unix(), string(updated), id); err != nil {
			return false, err
		}
		if s.gracePeriod > 0 {
			dur := info.requestedGrace
			if dur == 0 {
				dur = s.gracePeriod
			}
			if err := s.upsertGrace(ctx, tx, info.username, info.hostname, now.Add(dur)); err != nil {
				return false, err
			}
		}
	} else {
		if _, err := tx.ExecContext(ctx, s.q(
			`UPDATE challenges SET approvals_json = ? WHERE id = ?`),
			string(updated), id); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, ErrDiskWriteFailed
	}
	s.dirty.Store(true)
	if fullyApproved {
		ActiveChallenges.Dec()
		s.refreshGraceMetric(ctx)
	}
	return fullyApproved, nil
}

func (s *SQLStore) Deny(id, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		status    string
		expiresAt int64
	)
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT status, expires_at FROM challenges WHERE id = ?`+s.forUpdate()),
		id).Scan(&status, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("challenge not found")
	}
	if err != nil {
		return err
	}
	if time.Now().After(unixToTime(expiresAt)) {
		return fmt.Errorf("challenge expired")
	}
	if ChallengeStatus(status) != StatusPending {
		return ErrAlreadyResolved
	}
	if _, err := tx.ExecContext(ctx, s.q(
		`UPDATE challenges SET status = ?, deny_reason = ? WHERE id = ?`),
		string(StatusDenied), reason, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.dirty.Store(true)
	ActiveChallenges.Dec()
	return nil
}

func (s *SQLStore) AutoApprove(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		status    string
		username  string
		expiresAt int64
	)
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT status, username, expires_at FROM challenges WHERE id = ?`+s.forUpdate()),
		id).Scan(&status, &username, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("challenge not found")
	}
	if err != nil {
		return err
	}
	if time.Now().After(unixToTime(expiresAt)) {
		return fmt.Errorf("challenge expired")
	}
	if ChallengeStatus(status) != StatusPending {
		return ErrAlreadyResolved
	}
	// AutoApprove deliberately does NOT extend grace — the existing session continues.
	if _, err := tx.ExecContext(ctx, s.q(
		`UPDATE challenges SET status = ?, approved_by = ?, approved_at = ? WHERE id = ?`),
		string(StatusApproved), username, time.Now().Unix(), id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.dirty.Store(true)
	ActiveChallenges.Dec()
	return nil
}

func (s *SQLStore) AutoApproveIfWithinGracePeriod(username, hostname, id string) bool {
	if s.gracePeriod <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return false
	}
	defer func() { _ = tx.Rollback() }()

	// Read grace.
	var (
		expiryUnix int64
		mac        string
	)
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT expiry_unix, hmac_hex FROM grace_sessions
		 WHERE username = ? AND hostname = ?`+s.forUpdate()),
		username, hostname).Scan(&expiryUnix, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		logErr("AutoApproveIfWithinGracePeriod.grace", err)
		return false
	}
	if !s.verifyGrace(username, hostname, expiryUnix, mac) {
		return false
	}
	if !time.Now().Before(time.Unix(expiryUnix, 0)) {
		return false
	}

	// Read challenge.
	var (
		status    string
		expiresAt int64
	)
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT status, expires_at FROM challenges WHERE id = ?`+s.forUpdate()),
		id).Scan(&status, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		logErr("AutoApproveIfWithinGracePeriod.chal", err)
		return false
	}
	if ChallengeStatus(status) != StatusPending {
		return false
	}
	if time.Now().After(unixToTime(expiresAt)) {
		return false
	}
	if _, err := tx.ExecContext(ctx, s.q(
		`UPDATE challenges SET status = ?, approved_by = ?, approved_at = ? WHERE id = ?`),
		string(StatusApproved), username, time.Now().Unix(), id); err != nil {
		logErr("AutoApproveIfWithinGracePeriod.update", err)
		return false
	}
	if err := tx.Commit(); err != nil {
		logErr("AutoApproveIfWithinGracePeriod.commit", err)
		return false
	}
	s.dirty.Store(true)
	ActiveChallenges.Dec()
	return true
}

// ── One-tap ─────────────────────────────────────────────────────────────────

func (s *SQLStore) ConsumeOneTap(challengeID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		expiresAt   int64
		oneTapUsed  int
	)
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT expires_at, one_tap_used FROM challenges WHERE id = ?`+s.forUpdate()),
		challengeID).Scan(&expiresAt, &oneTapUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("challenge not found or expired")
	}
	if err != nil {
		return err
	}
	if time.Now().After(unixToTime(expiresAt)) {
		return fmt.Errorf("challenge not found or expired")
	}
	if oneTapUsed != 0 {
		return fmt.Errorf("one-tap already used")
	}
	if _, err := tx.ExecContext(ctx, s.q(
		`UPDATE challenges SET one_tap_used = 1 WHERE id = ?`),
		challengeID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.dirty.Store(true)
	return nil
}

func (s *SQLStore) ConsumeAndApprove(challengeID, approvedBy string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Read full state under lock.
	var (
		status      string
		username    string
		hostname    string
		createdAt   int64
		expiresAt   int64
		oneTapUsed  int
		requestedGr int64
	)
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT status, username, hostname, created_at, expires_at, one_tap_used, requested_grace_ns
		 FROM challenges WHERE id = ?`+s.forUpdate()),
		challengeID).Scan(&status, &username, &hostname, &createdAt, &expiresAt, &oneTapUsed, &requestedGr)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("challenge not found or expired")
	}
	if err != nil {
		return err
	}
	now := time.Now()
	if now.After(unixToTime(expiresAt)) {
		return fmt.Errorf("challenge not found or expired")
	}
	if oneTapUsed != 0 {
		return fmt.Errorf("one-tap already used")
	}
	if ChallengeStatus(status) != StatusPending {
		return ErrAlreadyResolved
	}
	// Session revocation check.
	var revokedAt int64
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT revoked_at FROM revoke_tokens_before WHERE username = ?`),
		username).Scan(&revokedAt)
	if err == nil && revokedAt > createdAt {
		return fmt.Errorf("challenge superseded by session revocation")
	}

	if _, err := tx.ExecContext(ctx, s.q(
		`UPDATE challenges SET one_tap_used = 1, status = ?, approved_by = ?, approved_at = ?
		 WHERE id = ?`),
		string(StatusApproved), approvedBy, now.Unix(), challengeID); err != nil {
		return err
	}
	if s.gracePeriod > 0 {
		dur := time.Duration(requestedGr)
		if dur == 0 {
			dur = s.gracePeriod
		}
		if err := s.upsertGrace(ctx, tx, username, hostname, now.Add(dur)); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return ErrDiskWriteFailed
	}
	s.dirty.Store(true)
	ActiveChallenges.Dec()
	s.refreshGraceMetric(ctx)
	return nil
}

// ── Pending queries ─────────────────────────────────────────────────────────

func (s *SQLStore) PendingChallenges(username string) []Challenge {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT `+challengeColumns+` FROM challenges
		 WHERE username = ? AND status = ? AND expires_at > ?
		 ORDER BY created_at`,
		username, string(StatusPending), nowUnix())
	if err != nil {
		logErr("PendingChallenges", err)
		return nil
	}
	defer rows.Close()
	var out []Challenge
	for rows.Next() {
		c, err := scanChallenge(rows)
		if err != nil {
			logErr("PendingChallenges.Scan", err)
			continue
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		logErr("PendingChallenges", err)
		return nil
	}
	return out
}

func (s *SQLStore) AllPendingChallenges() []Challenge {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT `+challengeColumns+` FROM challenges
		 WHERE status = ? AND expires_at > ?
		 ORDER BY created_at`,
		string(StatusPending), nowUnix())
	if err != nil {
		logErr("AllPendingChallenges", err)
		return nil
	}
	defer rows.Close()
	var out []Challenge
	for rows.Next() {
		c, err := scanChallenge(rows)
		if err != nil {
			logErr("AllPendingChallenges.Scan", err)
			continue
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		logErr("AllPendingChallenges", err)
		return nil
	}
	return out
}
