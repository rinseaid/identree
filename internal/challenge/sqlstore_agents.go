package challenge

import (
	"context"
	"time"
)

// RecordHeartbeat upserts the agents row for h.Hostname, bumping
// last_seen to now and preserving first_seen if the row already exists.
func (s *SQLStore) RecordHeartbeat(h AgentHeartbeat) {
	if h.Hostname == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	now := nowUnix()
	_, err := s.exec(ctx,
		`INSERT INTO agents (hostname, version, os_info, ip, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (hostname) DO UPDATE SET
		   version   = excluded.version,
		   os_info   = excluded.os_info,
		   ip        = excluded.ip,
		   last_seen = excluded.last_seen`,
		h.Hostname, h.Version, h.OSInfo, h.IP, now, now)
	logErr("RecordHeartbeat", err)
}

// ListAgents returns every recorded agent ordered by last_seen DESC so
// the dashboard renders the most-recently-active host first.
func (s *SQLStore) ListAgents() []AgentStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.query(ctx,
		`SELECT hostname, version, os_info, ip, first_seen, last_seen
		 FROM agents
		 ORDER BY last_seen DESC`)
	if err != nil {
		logErr("ListAgents", err)
		return nil
	}
	defer rows.Close()
	var out []AgentStatus
	for rows.Next() {
		var (
			a                    AgentStatus
			firstSeen, lastSeen  int64
		)
		if err := rows.Scan(&a.Hostname, &a.Version, &a.OSInfo, &a.IP, &firstSeen, &lastSeen); err != nil {
			logErr("ListAgents.Scan", err)
			continue
		}
		a.FirstSeen = unixToTime(firstSeen)
		a.LastSeen = unixToTime(lastSeen)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		logErr("ListAgents", err)
		return nil
	}
	return out
}
