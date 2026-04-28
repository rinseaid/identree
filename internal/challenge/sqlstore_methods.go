package challenge

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Methods in this file are the "simple" Store interface implementations
// (single-table reads/writes with no transactional read-modify-write).
// The richer methods live in:
//   sqlstore_challenge.go — challenge CRUD + RMW + one-tap + queries
//   sqlstore_grace.go     — grace session math
//   sqlstore_cleanup.go   — RemoveHost / RemoveUser

// ── Token revocation ────────────────────────────────────────────────────────

func (s *SQLStore) RevokeTokensBefore(username string) time.Time {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var u int64
	err := s.queryRow(ctx, `SELECT revoked_at FROM revoke_tokens_before WHERE username = ?`, username).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}
	}
	if err != nil {
		logErr("RevokeTokensBefore", err)
		return time.Time{}
	}
	return unixToTime(u)
}

// ── OIDC auth tracking ──────────────────────────────────────────────────────

func (s *SQLStore) RecordOIDCAuth(username string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.exec(ctx,
		`INSERT INTO last_oidc_auth (username, at_unix) VALUES (?, ?)
		 ON CONFLICT (username) DO UPDATE SET at_unix = excluded.at_unix`,
		username, nowUnix())
	logErr("RecordOIDCAuth", err)
}

func (s *SQLStore) LastOIDCAuth(username string) time.Time {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var u int64
	err := s.queryRow(ctx, `SELECT at_unix FROM last_oidc_auth WHERE username = ?`, username).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}
	}
	if err != nil {
		logErr("LastOIDCAuth", err)
		return time.Time{}
	}
	return unixToTime(u)
}

// ── Action log ──────────────────────────────────────────────────────────────

func (s *SQLStore) LogAction(username, action, hostname, code, actor string) {
	s.LogActionAt(username, action, hostname, code, actor, time.Now())
}

func (s *SQLStore) LogActionWithReason(username, action, hostname, code, actor, reason string) {
	s.logActionAt(username, action, hostname, code, actor, reason, time.Now())
}

func (s *SQLStore) LogActionAt(username, action, hostname, code, actor string, at time.Time) {
	s.logActionAt(username, action, hostname, code, actor, "", at)
}

func (s *SQLStore) logActionAt(username, action, hostname, code, actor, reason string, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	// The legacy in-memory store omitted Actor when actor == username (self-action);
	// preserve that surface so the dashboard renders self-actions identically.
	storedActor := actor
	if actor == username {
		storedActor = ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.exec(ctx,
		`INSERT INTO action_log (username, action, hostname, code, actor, reason, ts_unix)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		username, action, hostname, code, storedActor, reason, at.Unix())
	logErr("LogAction", err)
}

func (s *SQLStore) ActionHistory(username string, limit int) []ActionLogEntry {
	if limit <= 0 {
		limit = 50
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT ts_unix, action, hostname, code, actor, reason
		 FROM action_log
		 WHERE username = ?
		 ORDER BY ts_unix DESC, id DESC
		 LIMIT ?`,
		username, limit)
	if err != nil {
		logErr("ActionHistory", err)
		return nil
	}
	defer rows.Close()
	var out []ActionLogEntry
	for rows.Next() {
		var e ActionLogEntry
		var ts int64
		if err := rows.Scan(&ts, &e.Action, &e.Hostname, &e.Code, &e.Actor, &e.Reason); err != nil {
			logErr("ActionHistory.Scan", err)
			continue
		}
		e.Timestamp = unixToTime(ts)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		logErr("ActionHistory", err)
		return nil
	}
	return out
}

func (s *SQLStore) AllActionHistory() []ActionLogEntry {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT ts_unix, action, hostname, code, actor, reason
		 FROM action_log
		 ORDER BY ts_unix DESC, id DESC`)
	if err != nil {
		logErr("AllActionHistory", err)
		return nil
	}
	defer rows.Close()
	var out []ActionLogEntry
	for rows.Next() {
		var e ActionLogEntry
		var ts int64
		if err := rows.Scan(&ts, &e.Action, &e.Hostname, &e.Code, &e.Actor, &e.Reason); err != nil {
			logErr("AllActionHistory.Scan", err)
			continue
		}
		e.Timestamp = unixToTime(ts)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		logErr("AllActionHistory", err)
		return nil
	}
	return out
}

func (s *SQLStore) AllActionHistoryWithUsers() []ActionLogEntryWithUser {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT username, ts_unix, action, hostname, code, actor, reason
		 FROM action_log
		 ORDER BY ts_unix DESC, id DESC`)
	if err != nil {
		logErr("AllActionHistoryWithUsers", err)
		return nil
	}
	defer rows.Close()
	var out []ActionLogEntryWithUser
	for rows.Next() {
		var e ActionLogEntryWithUser
		var ts int64
		if err := rows.Scan(&e.Username, &ts, &e.Action, &e.Hostname, &e.Code, &e.Actor, &e.Reason); err != nil {
			logErr("AllActionHistoryWithUsers.Scan", err)
			continue
		}
		e.Timestamp = unixToTime(ts)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		logErr("AllActionHistoryWithUsers", err)
		return nil
	}
	return out
}

// ── Hosts ───────────────────────────────────────────────────────────────────

func (s *SQLStore) KnownHosts(username string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Exclude rows whose action is ActionRemovedHost to match the legacy contract.
	rows, err := s.query(ctx,
		`SELECT DISTINCT hostname FROM action_log
		 WHERE username = ? AND hostname <> '' AND hostname <> '(unknown)' AND action <> ?
		 UNION
		 SELECT DISTINCT hostname FROM grace_sessions
		 WHERE username = ? AND hostname <> ''
		 ORDER BY 1`,
		username, ActionRemovedHost, username)
	if err != nil {
		logErr("KnownHosts", err)
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err == nil {
			out = append(out, h)
		}
	}
	if err := rows.Err(); err != nil {
		logErr("KnownHosts", err)
		return nil
	}
	return out
}

func (s *SQLStore) AllKnownHosts() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT DISTINCT hostname FROM action_log
		 WHERE hostname <> '' AND hostname <> '(unknown)' AND action <> ?
		 UNION
		 SELECT DISTINCT hostname FROM grace_sessions WHERE hostname <> ''
		 UNION
		 SELECT hostname FROM agents
		 ORDER BY 1`,
		ActionRemovedHost)
	if err != nil {
		logErr("AllKnownHosts", err)
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err == nil {
			out = append(out, h)
		}
	}
	if err := rows.Err(); err != nil {
		logErr("AllKnownHosts", err)
		return nil
	}
	return out
}

func (s *SQLStore) UsersWithHostActivity(hostname string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT DISTINCT username FROM action_log
		 WHERE hostname = ? AND username <> ''
		 UNION
		 SELECT DISTINCT username FROM grace_sessions
		 WHERE hostname = ? AND username <> ''
		 ORDER BY 1`,
		hostname, hostname)
	if err != nil {
		logErr("UsersWithHostActivity", err)
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			out = append(out, u)
		}
	}
	if err := rows.Err(); err != nil {
		logErr("UsersWithHostActivity", err)
		return nil
	}
	return out
}

// ── Escrow ──────────────────────────────────────────────────────────────────

func (s *SQLStore) RecordEscrow(hostname, itemID, vaultID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.exec(ctx,
		`INSERT INTO escrowed_hosts (hostname, ts_unix, item_id, vault_id)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (hostname) DO UPDATE SET
		   ts_unix  = excluded.ts_unix,
		   item_id  = excluded.item_id,
		   vault_id = excluded.vault_id`,
		hostname, nowUnix(), itemID, vaultID)
	logErr("RecordEscrow", err)
}

func (s *SQLStore) StoreEscrowCiphertext(hostname, ciphertext string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.exec(ctx,
		`INSERT INTO escrow_ciphertexts (hostname, ciphertext)
		 VALUES (?, ?)
		 ON CONFLICT (hostname) DO UPDATE SET ciphertext = excluded.ciphertext`,
		hostname, ciphertext)
	logErr("StoreEscrowCiphertext", err)
}

func (s *SQLStore) GetEscrowCiphertext(hostname string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var ct string
	err := s.queryRow(ctx, `SELECT ciphertext FROM escrow_ciphertexts WHERE hostname = ?`, hostname).Scan(&ct)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		logErr("GetEscrowCiphertext", err)
		return "", false
	}
	return ct, true
}

func (s *SQLStore) EscrowedHosts() map[string]EscrowRecord {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx, `SELECT hostname, ts_unix, item_id, vault_id FROM escrowed_hosts`)
	if err != nil {
		logErr("EscrowedHosts", err)
		return nil
	}
	defer rows.Close()
	out := make(map[string]EscrowRecord)
	for rows.Next() {
		var host string
		var ts int64
		var rec EscrowRecord
		if err := rows.Scan(&host, &ts, &rec.ItemID, &rec.VaultID); err != nil {
			logErr("EscrowedHosts.Scan", err)
			continue
		}
		rec.Timestamp = unixToTime(ts)
		out[host] = rec
	}
	if err := rows.Err(); err != nil {
		logErr("EscrowedHosts", err)
		return nil
	}
	return out
}

// ── Host rotation ───────────────────────────────────────────────────────────

func (s *SQLStore) SetHostRotateBefore(hostname string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.exec(ctx,
		`INSERT INTO rotate_breakglass_before (hostname, rotated_at)
		 VALUES (?, ?)
		 ON CONFLICT (hostname) DO UPDATE SET rotated_at = excluded.rotated_at`,
		hostname, nowUnix())
	logErr("SetHostRotateBefore", err)
}

func (s *SQLStore) HostRotateBefore(hostname string) time.Time {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var u int64
	err := s.queryRow(ctx, `SELECT rotated_at FROM rotate_breakglass_before WHERE hostname = ?`, hostname).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}
	}
	if err != nil {
		logErr("HostRotateBefore", err)
		return time.Time{}
	}
	return unixToTime(u)
}

func (s *SQLStore) SetAllHostsRotateBefore(hostnames []string) {
	if len(hostnames) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		logErr("SetAllHostsRotateBefore.Begin", err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	now := nowUnix()
	stmt, err := tx.PrepareContext(ctx, s.q(
		`INSERT INTO rotate_breakglass_before (hostname, rotated_at)
		 VALUES (?, ?)
		 ON CONFLICT (hostname) DO UPDATE SET rotated_at = excluded.rotated_at`))
	if err != nil {
		logErr("SetAllHostsRotateBefore.Prepare", err)
		return
	}
	defer stmt.Close()
	for _, h := range hostnames {
		if _, err := stmt.ExecContext(ctx, h, now); err != nil {
			logErr("SetAllHostsRotateBefore.Exec", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		logErr("SetAllHostsRotateBefore.Commit", err)
		return
	}
	s.dirty.Store(true)
}

// ── Users ───────────────────────────────────────────────────────────────────

func (s *SQLStore) AllUsers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT DISTINCT username FROM action_log WHERE username <> ''
		 UNION
		 SELECT DISTINCT username FROM grace_sessions WHERE username <> ''
		 UNION
		 SELECT DISTINCT username FROM challenges WHERE username <> ''
		 ORDER BY 1`)
	if err != nil {
		logErr("AllUsers", err)
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			out = append(out, u)
		}
	}
	if err := rows.Err(); err != nil {
		logErr("AllUsers", err)
		return nil
	}
	return out
}

// ── Session persistence ─────────────────────────────────────────────────────

func (s *SQLStore) PersistRevokedNonce(nonce string, at time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.exec(ctx,
		`INSERT INTO revoked_nonces (nonce, revoked_at) VALUES (?, ?)
		 ON CONFLICT (nonce) DO UPDATE SET revoked_at = excluded.revoked_at`,
		nonce, timeToUnix(at))
	logErr("PersistRevokedNonce", err)
}

func (s *SQLStore) PersistRevokedAdminSession(username string, at time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.exec(ctx,
		`INSERT INTO revoked_admin_sessions (username, revoked_at) VALUES (?, ?)
		 ON CONFLICT (username) DO UPDATE SET revoked_at = excluded.revoked_at`,
		username, timeToUnix(at))
	logErr("PersistRevokedAdminSession", err)
}

func (s *SQLStore) LoadRevokedNonces() map[string]time.Time {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx, `SELECT nonce, revoked_at FROM revoked_nonces`)
	if err != nil {
		logErr("LoadRevokedNonces", err)
		return nil
	}
	defer rows.Close()
	out := make(map[string]time.Time)
	for rows.Next() {
		var nonce string
		var u int64
		if err := rows.Scan(&nonce, &u); err == nil {
			out[nonce] = unixToTime(u)
		}
	}
	if err := rows.Err(); err != nil {
		logErr("LoadRevokedNonces", err)
		return nil
	}
	return out
}

func (s *SQLStore) LoadRevokedAdminSessions() map[string]time.Time {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx, `SELECT username, revoked_at FROM revoked_admin_sessions`)
	if err != nil {
		logErr("LoadRevokedAdminSessions", err)
		return nil
	}
	defer rows.Close()
	out := make(map[string]time.Time)
	for rows.Next() {
		var user string
		var u int64
		if err := rows.Scan(&user, &u); err == nil {
			out[user] = unixToTime(u)
		}
	}
	if err := rows.Err(); err != nil {
		logErr("LoadRevokedAdminSessions", err)
		return nil
	}
	return out
}

// ── Escrow token replay ─────────────────────────────────────────────────────

func (s *SQLStore) CheckAndRecordEscrowToken(tokenKey string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := s.exec(ctx,
		`INSERT INTO used_escrow_tokens (token_key, first_seen) VALUES (?, ?)
		 ON CONFLICT (token_key) DO NOTHING`,
		tokenKey, nowUnix())
	if err != nil {
		logErr("CheckAndRecordEscrowToken", err)
		// Fail safe: treat DB errors as "already seen" so a flake doesn't
		// allow replay. Caller should be alerted via the metric.
		return true
	}
	n, _ := res.RowsAffected()
	return n == 0
}

func (s *SQLStore) UsedEscrowTokenCount() int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(*) FROM used_escrow_tokens`).Scan(&n)
	if err != nil {
		logErr("UsedEscrowTokenCount", err)
		return 0
	}
	return n
}

// ── Session nonces (OIDC login state) ───────────────────────────────────────

func (s *SQLStore) StoreSessionNonce(nonce string, data SessionNonceData, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	expiresAt := time.Now().Add(ttl).Unix()
	if ttl <= 0 {
		expiresAt = 0
	}
	_, err := s.exec(ctx,
		`INSERT INTO session_nonces (nonce, issued_at, code_verifier, client_ip, expires_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (nonce) DO UPDATE SET
		   issued_at     = excluded.issued_at,
		   code_verifier = excluded.code_verifier,
		   client_ip     = excluded.client_ip,
		   expires_at    = excluded.expires_at`,
		nonce, timeToUnix(data.IssuedAt), data.CodeVerifier, data.ClientIP, expiresAt)
	return err
}

func (s *SQLStore) GetSessionNonce(nonce string) (SessionNonceData, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var (
		issuedAt  int64
		expiresAt int64
		data      SessionNonceData
	)
	err := s.queryRow(ctx,
		`SELECT issued_at, code_verifier, client_ip, expires_at
		 FROM session_nonces WHERE nonce = ?`, nonce).
		Scan(&issuedAt, &data.CodeVerifier, &data.ClientIP, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionNonceData{}, false
	}
	if err != nil {
		logErr("GetSessionNonce", err)
		return SessionNonceData{}, false
	}
	if expiresAt > 0 && expiresAt <= nowUnix() {
		_, _ = s.exec(ctx, `DELETE FROM session_nonces WHERE nonce = ?`, nonce)
		return SessionNonceData{}, false
	}
	data.IssuedAt = unixToTime(issuedAt)
	return data, true
}

func (s *SQLStore) DeleteSessionNonce(nonce string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.exec(ctx, `DELETE FROM session_nonces WHERE nonce = ?`, nonce)
	logErr("DeleteSessionNonce", err)
}
