package challenge

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"sort"
	"time"
)

// ── Internal grace helpers ──────────────────────────────────────────────────

// signGrace returns the HMAC for a grace session, or "" when no key is set.
func (s *SQLStore) signGrace(username, hostname string, expiryUnix int64) string {
	key := s.currentGraceHMACKey()
	if len(key) == 0 {
		return ""
	}
	return computeGraceHMAC(key, username, hostname, expiryUnix)
}

// verifyGrace returns true when the stored MAC matches the expected one.
// When no HMAC key is configured, every row is treated as valid (legacy mode).
func (s *SQLStore) verifyGrace(username, hostname string, expiryUnix int64, storedMAC string) bool {
	key := s.currentGraceHMACKey()
	if len(key) == 0 {
		return true
	}
	if storedMAC == "" {
		return false
	}
	expected := computeGraceHMAC(key, username, hostname, expiryUnix)
	return hmac.Equal([]byte(expected), []byte(storedMAC))
}

// upsertGrace writes (or refreshes) a grace session row.
// Caller is responsible for emitting the gauge update if needed.
func (s *SQLStore) upsertGrace(ctx context.Context, runner sqlExec, username, hostname string, expiry time.Time) error {
	expiryUnix := expiry.Unix()
	mac := s.signGrace(username, hostname, expiryUnix)
	_, err := runner.ExecContext(ctx, s.q(
		`INSERT INTO grace_sessions (username, hostname, expiry_unix, hmac_hex)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (username, hostname) DO UPDATE SET
		   expiry_unix = excluded.expiry_unix,
		   hmac_hex    = excluded.hmac_hex`),
		username, hostname, expiryUnix, mac)
	return err
}

// readGrace returns the expiry of a single grace session, or zero if none / tampered / expired.
func (s *SQLStore) readGrace(ctx context.Context, username, hostname string) time.Time {
	var (
		expiryUnix int64
		mac        string
	)
	err := s.queryRow(ctx,
		`SELECT expiry_unix, hmac_hex FROM grace_sessions WHERE username = ? AND hostname = ?`,
		username, hostname).Scan(&expiryUnix, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}
	}
	if err != nil {
		logErr("readGrace", err)
		return time.Time{}
	}
	if !s.verifyGrace(username, hostname, expiryUnix, mac) {
		// Tampered row — drop it lazily.
		_, _ = s.exec(ctx, `DELETE FROM grace_sessions WHERE username = ? AND hostname = ?`, username, hostname)
		return time.Time{}
	}
	expiry := time.Unix(expiryUnix, 0)
	if !time.Now().Before(expiry) {
		// Expired — drop it lazily so the reap query stays small.
		_, _ = s.exec(ctx, `DELETE FROM grace_sessions WHERE username = ? AND hostname = ?`, username, hostname)
		return time.Time{}
	}
	return expiry
}

// ── Public grace methods ────────────────────────────────────────────────────

// CreateGraceSession upserts a grace session for (username, hostname) with the
// given duration measured from now. Used for manual elevation flows.
func (s *SQLStore) CreateGraceSession(ctx context.Context, username, hostname string, duration time.Duration) {
	if duration <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.upsertGrace(ctx, s.db, username, hostname, time.Now().Add(duration)); err != nil {
		logErr("CreateGraceSession", err)
		return
	}
	s.dirty.Store(true)
	s.refreshGraceMetric(ctx)
}

func (s *SQLStore) WithinGracePeriod(ctx context.Context, username, hostname string) bool {
	if s.gracePeriod <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return !s.readGrace(ctx, username, hostname).IsZero()
}

func (s *SQLStore) GraceRemaining(ctx context.Context, username, hostname string) time.Duration {
	if s.gracePeriod <= 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	expiry := s.readGrace(ctx, username, hostname)
	if expiry.IsZero() {
		return 0
	}
	remaining := time.Until(expiry)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (s *SQLStore) ActiveSessions(ctx context.Context, username string) []GraceSession {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.readGraceSessions(ctx, "WHERE username = ? AND expiry_unix > ?", username, nowUnix())
}

func (s *SQLStore) AllActiveSessions(ctx context.Context) []GraceSession {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.readGraceSessions(ctx, "WHERE expiry_unix > ?", nowUnix())
}

func (s *SQLStore) ActiveSessionsForHost(ctx context.Context, hostname string) []GraceSession {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.readGraceSessions(ctx, "WHERE hostname = ? AND expiry_unix > ?", hostname, nowUnix())
}

// readGraceSessions fetches and HMAC-verifies grace rows matching a SQL fragment.
// The fragment must include the WHERE clause; placeholders are dialect-rewritten.
func (s *SQLStore) readGraceSessions(ctx context.Context, where string, args ...any) []GraceSession {
	rows, err := s.query(ctx, `SELECT username, hostname, expiry_unix, hmac_hex FROM grace_sessions `+where, args...)
	if err != nil {
		logErr("readGraceSessions", err)
		return nil
	}
	defer rows.Close()
	var out []GraceSession
	for rows.Next() {
		var (
			user, host string
			expiryUnix int64
			mac        string
		)
		if err := rows.Scan(&user, &host, &expiryUnix, &mac); err != nil {
			logErr("readGraceSessions.Scan", err)
			continue
		}
		if !s.verifyGrace(user, host, expiryUnix, mac) {
			// Skip tampered rows; they will be dropped on next single-row read.
			continue
		}
		displayHost := host
		if displayHost == "" {
			// The legacy in-memory store rendered hostnameless rows as
			// "(unknown)" in the dashboards. Preserve that surface.
			displayHost = "(unknown)"
		}
		out = append(out, GraceSession{
			Username:  user,
			Hostname:  displayHost,
			ExpiresAt: time.Unix(expiryUnix, 0),
		})
	}
	if err := rows.Err(); err != nil {
		logErr("readGraceSessions", err)
		return nil
	}
	// Stable order helps tests and dashboard rendering.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Username != out[j].Username {
			return out[i].Username < out[j].Username
		}
		return out[i].Hostname < out[j].Hostname
	})
	return out
}

func (s *SQLStore) ExtendGraceSession(ctx context.Context, username, hostname string) (time.Duration, error) {
	if s.gracePeriod <= 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.beginTxRMW(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		expiryUnix int64
		mac        string
	)
	err = tx.QueryRowContext(ctx, s.q(
		`SELECT expiry_unix, hmac_hex FROM grace_sessions WHERE username = ? AND hostname = ?`+s.forUpdate()),
		username, hostname).Scan(&expiryUnix, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !s.verifyGrace(username, hostname, expiryUnix, mac) {
		return 0, nil
	}
	remaining := time.Until(time.Unix(expiryUnix, 0))
	if remaining > s.gracePeriod*3/4 {
		return remaining, ErrSessionSufficientlyExtended
	}
	newExpiry := time.Now().Add(s.gracePeriod)
	if err := s.upsertGrace(ctx, tx, username, hostname, newExpiry); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.dirty.Store(true)
	s.refreshGraceMetric(ctx)
	return s.gracePeriod, nil
}

func (s *SQLStore) ForceExtendGraceSession(ctx context.Context, username, hostname string) time.Duration {
	if s.gracePeriod <= 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res, err := s.exec(ctx, `UPDATE grace_sessions SET expiry_unix = ?, hmac_hex = ?
	    WHERE username = ? AND hostname = ?`,
		time.Now().Add(s.gracePeriod).Unix(),
		s.signGrace(username, hostname, time.Now().Add(s.gracePeriod).Unix()),
		username, hostname)
	if err != nil {
		logErr("ForceExtendGraceSession", err)
		return 0
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0
	}
	s.refreshGraceMetric(ctx)
	return s.gracePeriod
}

func (s *SQLStore) ExtendGraceSessionFor(ctx context.Context, username, hostname string, dur time.Duration) time.Duration {
	if s.gracePeriod <= 0 {
		return 0
	}
	if dur > s.gracePeriod {
		dur = s.gracePeriod
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	newExpiry := time.Now().Add(dur)
	res, err := s.exec(ctx, `UPDATE grace_sessions SET expiry_unix = ?, hmac_hex = ?
	    WHERE username = ? AND hostname = ?`,
		newExpiry.Unix(),
		s.signGrace(username, hostname, newExpiry.Unix()),
		username, hostname)
	if err != nil {
		logErr("ExtendGraceSessionFor", err)
		return 0
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0
	}
	s.refreshGraceMetric(ctx)
	return dur
}

// RevokeSession removes the (username, hostname) grace row and bumps
// revoke_tokens_before for the user so any cached token signed before now
// is rejected on the next poll.
func (s *SQLStore) RevokeSession(ctx context.Context, username, hostname string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		logErr("RevokeSession.Begin", err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, s.q(
		`DELETE FROM grace_sessions WHERE username = ? AND hostname = ?`),
		username, hostname); err != nil {
		logErr("RevokeSession.Delete", err)
		return
	}
	if _, err := tx.ExecContext(ctx, s.q(
		`INSERT INTO revoke_tokens_before (username, revoked_at) VALUES (?, ?)
		 ON CONFLICT (username) DO UPDATE SET revoked_at = excluded.revoked_at`),
		username, nowUnix()); err != nil {
		logErr("RevokeSession.UpsertRevoke", err)
		return
	}
	if err := tx.Commit(); err != nil {
		logErr("RevokeSession.Commit", err)
		return
	}
	s.dirty.Store(true)
	s.refreshGraceMetric(ctx)
}

// refreshGraceMetric updates the active grace sessions gauge by querying COUNT.
// Cheap with the idx_grace_expiry index; called after any grace mutation.
func (s *SQLStore) refreshGraceMetric(ctx context.Context) {
	var n int
	if err := s.queryRow(ctx, `SELECT COUNT(*) FROM grace_sessions WHERE expiry_unix > ?`, nowUnix()).Scan(&n); err != nil {
		// Silently swallow — metric is best-effort.
		return
	}
	graceSessions.Set(float64(n))
}

// sqlExec is the common interface satisfied by *sql.DB and *sql.Tx so the
// upsertGrace helper can be reused both inside and outside transactions.
type sqlExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}
