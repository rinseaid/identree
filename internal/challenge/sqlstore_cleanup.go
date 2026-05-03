package challenge

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ── RemoveHost ──────────────────────────────────────────────────────────────

// RemoveHost wipes all per-host state in a single transaction:
// action log entries, grace sessions, escrow records, escrow ciphertext,
// rotation timestamp, and any agent record. The action_log entries are
// preserved (legacy behaviour was to delete them, but for audit purposes
// we keep them and let KnownHosts/AllKnownHosts filter on action <>
// ActionRemovedHost — caller should log such an entry first).
func (s *SQLStore) RemoveHost(hostname string) {
	if hostname == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		logErr("RemoveHost.Begin", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	stmts := []string{
		`DELETE FROM grace_sessions      WHERE hostname = ?`,
		`DELETE FROM escrowed_hosts      WHERE hostname = ?`,
		`DELETE FROM escrow_ciphertexts  WHERE hostname = ?`,
		`DELETE FROM rotate_breakglass_before WHERE hostname = ?`,
		`DELETE FROM agents              WHERE hostname = ?`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, s.q(q), hostname); err != nil {
			logErr("RemoveHost.Exec", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		logErr("RemoveHost.Commit", err)
		return
	}
	s.dirty.Store(true)
	s.refreshGraceMetric(ctx)
}

// ── RemoveUser ──────────────────────────────────────────────────────────────

// RemoveUser wipes all per-user state and bumps revoke_tokens_before so
// any cached token from before this point is rejected. Note: action_log
// entries are deleted (legacy behaviour), but the caller is expected to
// have already logged an ActionRemovedUser entry before calling — that
// entry survives because it was inserted in a prior transaction.
//
// We delete pending challenges so the per-user pending counter (now
// derived from a SELECT COUNT) reflects reality; resolved challenges are
// also removed for hygiene.
func (s *SQLStore) RemoveUser(username string) {
	if username == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		logErr("RemoveUser.Begin", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Count pending challenges before deletion so we can decrement the
	// gauge correctly.
	var pendingCount int
	_ = tx.QueryRowContext(ctx, s.q(
		`SELECT COUNT(*) FROM challenges WHERE username = ? AND status = ? AND expires_at > ?`),
		username, string(StatusPending), nowUnix()).Scan(&pendingCount)

	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM challenges            WHERE username = ?`, []any{username}},
		{`DELETE FROM grace_sessions        WHERE username = ?`, []any{username}},
		{`DELETE FROM action_log            WHERE username = ?`, []any{username}},
		{`DELETE FROM last_oidc_auth        WHERE username = ?`, []any{username}},
		{`INSERT INTO revoke_tokens_before (username, revoked_at) VALUES (?, ?)
		  ON CONFLICT (username) DO UPDATE SET revoked_at = excluded.revoked_at`,
			[]any{username, nowUnix()}},
	}
	for _, st := range stmts {
		if _, err := tx.ExecContext(ctx, s.q(st.q), st.args...); err != nil {
			logErr("RemoveUser.Exec", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		logErr("RemoveUser.Commit", err)
		return
	}
	s.dirty.Store(true)
	for i := 0; i < pendingCount; i++ {
		ActiveChallenges.Dec()
	}
	s.refreshGraceMetric(ctx)
}

// ── Reap goroutine ──────────────────────────────────────────────────────────

// reapInterval is how often the reap goroutine wakes up to mark expired
// pending challenges and clean stale rows. Matches the legacy 10s cadence.
const reapInterval = 10 * time.Second

// startReap launches the background reap goroutine. Stops when s.stopCh closes.
func (s *SQLStore) startReap() {
	s.stopWg.Add(1)
	go func() {
		defer s.stopWg.Done()
		ticker := time.NewTicker(reapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.reapOnce(context.Background())
			}
		}
	}()
}

// reapOnce finds pending challenges whose expiry has passed, marks them
// expired, fires the OnExpire callback (if any), and prunes stale rows
// from short-lived tables.
func (s *SQLStore) reapOnce(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("sqlstore.reap panic", "panic", r)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	now := nowUnix()

	// Snapshot expired pending challenges so we can fire OnExpire callbacks
	// after committing the status update.
	type expiredEntry struct {
		username string
		hostname string
		code     string
	}
	var expired []expiredEntry

	rows, err := s.query(ctx,
		`SELECT username, hostname, user_code FROM challenges
		 WHERE status = ? AND expires_at <= ?`,
		string(StatusPending), now)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			logErr("reap.select", err)
		}
		return
	}
	defer rows.Close()
	for rows.Next() {
		var e expiredEntry
		if err := rows.Scan(&e.username, &e.hostname, &e.code); err == nil {
			expired = append(expired, e)
		}
	}
	if err := rows.Err(); err != nil {
		logErr("reap.rows", err)
	}

	if len(expired) > 0 {
		if _, err := s.exec(ctx,
			`UPDATE challenges SET status = ?
			 WHERE status = ? AND expires_at <= ?`,
			string(StatusExpired), string(StatusPending), now); err != nil {
			logErr("reap.update", err)
			return
		}
		for _, e := range expired {
			challengesExpired.Inc()
			ActiveChallenges.Dec()
			if s.OnExpire != nil {
				s.OnExpire(e.username, e.hostname, e.code)
			}
		}
	}

	// Prune short-lived rows. Best-effort, ignore errors.
	_, _ = s.exec(ctx, `DELETE FROM session_nonces WHERE expires_at > 0 AND expires_at < ?`, now)
	_, _ = s.exec(ctx, `DELETE FROM grace_sessions WHERE expiry_unix < ?`, now)
	// Resolved challenges older than 1h are removed; the action log carries
	// the audit record, so the row itself is no longer useful.
	_, _ = s.exec(ctx, `DELETE FROM challenges
		WHERE status IN (?, ?, ?) AND expires_at < ?`,
		string(StatusApproved), string(StatusDenied), string(StatusExpired),
		now-3600)
	// Used escrow tokens older than 10 minutes are no longer needed for replay
	// protection (the source token's TTL is much shorter).
	_, _ = s.exec(ctx, `DELETE FROM used_escrow_tokens WHERE first_seen < ?`, now-600)
	// Revoked nonces older than 35 minutes are past the session cookie TTL.
	_, _ = s.exec(ctx, `DELETE FROM revoked_nonces WHERE revoked_at < ?`, now-(35*60))
}
