package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/rinseaid/identree/internal/randutil"
)

// Compile-time check: RedisStore implements Store.
var _ Store = (*RedisStore)(nil)

// RedisStore implements the Store interface backed by Redis (or Valkey).
// All state is stored as Redis keys with appropriate TTLs, and critical
// multi-key operations use Lua scripts for atomicity.
type RedisStore struct {
	client      redis.UniversalClient
	prefix      string
	ttl         time.Duration
	gracePeriod time.Duration

	stopCh   chan struct{}
	stopOnce sync.Once
	stopWg   sync.WaitGroup
}

// NewRedisStore creates a new RedisStore.
func NewRedisStore(client redis.UniversalClient, prefix string, ttl, gracePeriod time.Duration) *RedisStore {
	s := &RedisStore{
		client:      client,
		prefix:      prefix,
		ttl:         ttl,
		gracePeriod: gracePeriod,
		stopCh:      make(chan struct{}),
	}
	// Background reconciliation goroutine: reconcile pending counters every 5 minutes.
	s.stopWg.Add(1)
	go func() {
		defer s.stopWg.Done()
		s.reconcileLoop()
	}()
	return s
}

// ── Key helpers ─────────────────────────────────────────────────────────────

func (s *RedisStore) key(parts ...string) string {
	return s.prefix + strings.Join(parts, ":")
}

func (s *RedisStore) challengeKey(id string) string    { return s.key("challenge", id) }
func (s *RedisStore) byCodeKey(code string) string      { return s.key("bycode", code) }
func (s *RedisStore) pendingUserKey(user string) string  { return s.key("pending", user) }
func (s *RedisStore) pendingTotalKey() string            { return s.key("pending", "total") }
func (s *RedisStore) graceKey(user, host string) string {
	if host == "" {
		return s.key("grace", user)
	}
	return s.key("grace", user+"\x00"+host)
}
func (s *RedisStore) actionLogKey(user string) string     { return s.key("actionlog", user) }
func (s *RedisStore) knownHostsKey(user string) string    { return s.key("knownhosts", user) }
func (s *RedisStore) hostActivityKey(host string) string  { return s.key("hostactivity", host) }
func (s *RedisStore) usersAllKey() string                 { return s.key("users", "all") }
func (s *RedisStore) oneTapKey(id string) string          { return s.key("onetap", id) }
func (s *RedisStore) escrowKey(host string) string        { return s.key("escrow", host) }
func (s *RedisStore) escrowCipherKey(host string) string  { return s.key("escrow_cipher", host) }
func (s *RedisStore) revokeTokensKey(user string) string  { return s.key("revoketokens", user) }
func (s *RedisStore) rotateBreakKey(host string) string   { return s.key("rotatebreak", host) }
func (s *RedisStore) lastOIDCKey(user string) string      { return s.key("lastoidc", user) }
func (s *RedisStore) revokedNonceKey(nonce string) string { return s.key("revokednonce", nonce) }
func (s *RedisStore) revokedAdminKey(user string) string  { return s.key("revokedadmin", user) }
func (s *RedisStore) escrowTokenKey(tk string) string     { return s.key("escrowtoken", tk) }
func (s *RedisStore) sessionNonceKey(n string) string     { return s.key("sessionnonce", n) }

// challengeTTLWithBuffer returns the challenge TTL + 60s buffer for Redis key expiry.
func (s *RedisStore) challengeTTLWithBuffer() time.Duration {
	return s.ttl + 60*time.Second
}

func (s *RedisStore) ctx() context.Context {
	return context.Background()
}

// ── Lua scripts ─────────────────────────────────────────────────────────────

// luaCreate atomically checks caps, creates the challenge hash, sets the bycode
// index, and increments counters.
// KEYS[1]=challenge:{id} KEYS[2]=bycode:{code} KEYS[3]=pending:{user} KEYS[4]=pending:total
// ARGV[1]=JSON challenge data ARGV[2]=TTL seconds ARGV[3]=code ARGV[4]=maxPerUser ARGV[5]=maxTotal ARGV[6]=username
var luaCreate = redis.NewScript(`
local pendingUser = tonumber(redis.call('GET', KEYS[3]) or '0')
local pendingTotal = tonumber(redis.call('GET', KEYS[4]) or '0')
local maxPerUser = tonumber(ARGV[4])
local maxTotal = tonumber(ARGV[5])
if pendingTotal >= maxTotal then return redis.error_reply('too_many_total') end
if pendingUser >= maxPerUser then return redis.error_reply('too_many_user') end
if redis.call('EXISTS', KEYS[2]) == 1 then return redis.error_reply('code_collision') end
local ttl = tonumber(ARGV[2])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ttl)
redis.call('SET', KEYS[2], string.match(KEYS[1], '([^:]+)$'), 'EX', ttl)
redis.call('INCR', KEYS[3])
redis.call('EXPIRE', KEYS[3], ttl)
redis.call('INCR', KEYS[4])
redis.call('EXPIRE', KEYS[4], ttl)
return 'ok'
`)

// luaApprove atomically checks status=pending + not expired, sets approved, updates grace, decrements counters.
// KEYS[1]=challenge:{id} KEYS[2]=pending:{user} KEYS[3]=pending:total KEYS[4]=grace:{key}
// ARGV[1]=approvedBy ARGV[2]=now_unix ARGV[3]=grace_expiry_unix (0 = no grace) ARGV[4]=grace_ttl_seconds
// ARGV[5]=revokeTokensBefore_unix (0 = not set)
var luaApprove = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return redis.error_reply('not_found') end
local c = cjson.decode(data)
if c.status ~= 'pending' then return redis.error_reply('already_resolved') end
local now = tonumber(ARGV[2])
if now > tonumber(c.expires_at_unix) then return redis.error_reply('expired') end
local revokeTs = tonumber(ARGV[5])
if revokeTs > 0 and revokeTs > tonumber(c.created_at_unix) then return redis.error_reply('revoked') end
c.status = 'approved'
c.approved_by = ARGV[1]
c.approved_at_unix = ARGV[2]
local ttl = redis.call('TTL', KEYS[1])
if ttl < 1 then ttl = 60 end
redis.call('SET', KEYS[1], cjson.encode(c), 'EX', ttl)
local userPending = redis.call('DECR', KEYS[2])
if userPending < 0 then redis.call('SET', KEYS[2], '0') end
local totalPending = redis.call('DECR', KEYS[3])
if totalPending < 0 then redis.call('SET', KEYS[3], '0') end
local graceExpiry = tonumber(ARGV[3])
if graceExpiry > 0 then
  local graceTTL = tonumber(ARGV[4])
  redis.call('SET', KEYS[4], tostring(graceExpiry), 'EX', graceTTL)
end
return cjson.encode(c)
`)

// luaDeny atomically checks status=pending, sets denied, decrements counters.
// KEYS[1]=challenge:{id} KEYS[2]=pending:{user} KEYS[3]=pending:total
// ARGV[1]=now_unix ARGV[2]=deny_reason (optional, may be empty string)
var luaDeny = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return redis.error_reply('not_found') end
local c = cjson.decode(data)
if c.status ~= 'pending' then return redis.error_reply('already_resolved') end
local now = tonumber(ARGV[1])
if now > tonumber(c.expires_at_unix) then return redis.error_reply('expired') end
c.status = 'denied'
local reason = ARGV[2]
if reason and reason ~= '' then c.deny_reason = reason end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 1 then ttl = 60 end
redis.call('SET', KEYS[1], cjson.encode(c), 'EX', ttl)
local userPending = redis.call('DECR', KEYS[2])
if userPending < 0 then redis.call('SET', KEYS[2], '0') end
local totalPending = redis.call('DECR', KEYS[3])
if totalPending < 0 then redis.call('SET', KEYS[3], '0') end
return 'ok'
`)

// luaSetNonce atomically checks exists + pending + nonce empty, then sets nonce.
// KEYS[1]=challenge:{id}
// ARGV[1]=nonce ARGV[2]=now_unix
var luaSetNonce = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return redis.error_reply('not_found') end
local c = cjson.decode(data)
if tonumber(ARGV[2]) > tonumber(c.expires_at_unix) then return redis.error_reply('expired') end
if c.status ~= 'pending' then return redis.error_reply('already_resolved') end
if c.nonce and c.nonce ~= '' then return redis.error_reply('nonce_already_set') end
c.nonce = ARGV[1]
local ttl = redis.call('TTL', KEYS[1])
if ttl < 1 then ttl = 60 end
redis.call('SET', KEYS[1], cjson.encode(c), 'EX', ttl)
return 'ok'
`)

// luaConsumeOneTap atomically sets the one-tap key if not already set + checks challenge exists.
// KEYS[1]=onetap:{id} KEYS[2]=challenge:{id}
// ARGV[1]=ttl_seconds ARGV[2]=now_unix
var luaConsumeOneTap = redis.NewScript(`
local data = redis.call('GET', KEYS[2])
if not data then return redis.error_reply('not_found') end
local c = cjson.decode(data)
if tonumber(ARGV[2]) > tonumber(c.expires_at_unix) then return redis.error_reply('expired') end
if redis.call('EXISTS', KEYS[1]) == 1 then return redis.error_reply('already_used') end
redis.call('SET', KEYS[1], '1', 'EX', tonumber(ARGV[1]))
return 'ok'
`)

// luaConsumeAndApprove atomically consumes one-tap + approves the challenge.
// KEYS[1]=onetap:{id} KEYS[2]=challenge:{id} KEYS[3]=pending:{user} KEYS[4]=pending:total KEYS[5]=grace:{key}
// ARGV[1]=ttl_seconds ARGV[2]=approvedBy ARGV[3]=now_unix ARGV[4]=grace_expiry_unix ARGV[5]=grace_ttl_seconds
// ARGV[6]=revokeTokensBefore_unix
var luaConsumeAndApprove = redis.NewScript(`
local data = redis.call('GET', KEYS[2])
if not data then return redis.error_reply('not_found') end
local c = cjson.decode(data)
local now = tonumber(ARGV[3])
if now > tonumber(c.expires_at_unix) then return redis.error_reply('expired') end
if redis.call('EXISTS', KEYS[1]) == 1 then return redis.error_reply('already_used') end
if c.status ~= 'pending' then return redis.error_reply('already_resolved') end
local revokeTs = tonumber(ARGV[6])
if revokeTs > 0 and revokeTs > tonumber(c.created_at_unix) then return redis.error_reply('revoked') end
redis.call('SET', KEYS[1], '1', 'EX', tonumber(ARGV[1]))
c.status = 'approved'
c.approved_by = ARGV[2]
c.approved_at_unix = ARGV[3]
local ttl = redis.call('TTL', KEYS[2])
if ttl < 1 then ttl = 60 end
redis.call('SET', KEYS[2], cjson.encode(c), 'EX', ttl)
local userPending = redis.call('DECR', KEYS[3])
if userPending < 0 then redis.call('SET', KEYS[3], '0') end
local totalPending = redis.call('DECR', KEYS[4])
if totalPending < 0 then redis.call('SET', KEYS[4], '0') end
local graceExpiry = tonumber(ARGV[4])
if graceExpiry > 0 then
  local graceTTL = tonumber(ARGV[5])
  redis.call('SET', KEYS[5], tostring(graceExpiry), 'EX', graceTTL)
end
return cjson.encode(c)
`)

// luaSetRequestedGrace atomically checks status=pending before updating requested_grace_sec.
// KEYS[1]=challenge:{id}
// ARGV[1]=requested_grace_sec
var luaSetRequestedGrace = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return redis.error_reply('not_found') end
local c = cjson.decode(data)
if c.status ~= 'pending' then return 0 end
c.requested_grace_sec = tonumber(ARGV[1])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 1 then ttl = 60 end
redis.call('SET', KEYS[1], cjson.encode(c), 'EX', ttl)
return 1
`)

// luaAutoApproveGrace atomically checks grace + challenge pending, approves.
// KEYS[1]=grace:{key} KEYS[2]=challenge:{id} KEYS[3]=pending:{user} KEYS[4]=pending:total
// ARGV[1]=now_unix
var luaAutoApproveGrace = redis.NewScript(`
local graceData = redis.call('GET', KEYS[1])
if not graceData then return redis.error_reply('no_grace') end
local graceExpiry = tonumber(graceData)
local now = tonumber(ARGV[1])
if now >= graceExpiry then return redis.error_reply('grace_expired') end
local data = redis.call('GET', KEYS[2])
if not data then return redis.error_reply('not_found') end
local c = cjson.decode(data)
if c.status ~= 'pending' then return redis.error_reply('already_resolved') end
if now > tonumber(c.expires_at_unix) then return redis.error_reply('expired') end
c.status = 'approved'
c.approved_by = c.username
c.approved_at_unix = tostring(now)
local ttl = redis.call('TTL', KEYS[2])
if ttl < 1 then ttl = 60 end
redis.call('SET', KEYS[2], cjson.encode(c), 'EX', ttl)
local userPending = redis.call('DECR', KEYS[3])
if userPending < 0 then redis.call('SET', KEYS[3], '0') end
local totalPending = redis.call('DECR', KEYS[4])
if totalPending < 0 then redis.call('SET', KEYS[4], '0') end
return 'ok'
`)

// ── redisChallenge is the Redis-serializable form of Challenge ───────────

type redisChallenge struct {
	ID                     string `json:"id"`
	UserCode               string `json:"user_code"`
	Username               string `json:"username"`
	Status                 string `json:"status"`
	CreatedAtUnix          string `json:"created_at_unix"`
	ExpiresAtUnix          string `json:"expires_at_unix"`
	Nonce                  string `json:"nonce,omitempty"`
	Hostname               string `json:"hostname,omitempty"`
	Reason                 string `json:"reason,omitempty"`
	DenyReason             string `json:"deny_reason,omitempty"`
	PolicyName             string `json:"policy_name,omitempty"`
	RequiredApprovals      int    `json:"required_approvals,omitempty"`
	RequireAdmin           bool   `json:"require_admin,omitempty"`
	BreakglassRotateBefore string `json:"breakglass_rotate_before,omitempty"`
	RequestedGraceSec      int64  `json:"requested_grace_sec,omitempty"`
	RevokeTokensBefore     string `json:"revoke_tokens_before,omitempty"`
	ApprovedBy             string `json:"approved_by,omitempty"`
	ApprovedAtUnix         string `json:"approved_at_unix,omitempty"`
	RawIDToken             string `json:"raw_id_token,omitempty"`
}

func challengeToRedis(c *Challenge) redisChallenge {
	return redisChallenge{
		ID:                     c.ID,
		UserCode:               c.UserCode,
		Username:               c.Username,
		Status:                 string(c.Status),
		CreatedAtUnix:          strconv.FormatInt(c.CreatedAt.Unix(), 10),
		ExpiresAtUnix:          strconv.FormatInt(c.ExpiresAt.Unix(), 10),
		Nonce:                  c.Nonce,
		Hostname:               c.Hostname,
		Reason:                 c.Reason,
		DenyReason:             c.DenyReason,
		PolicyName:             c.PolicyName,
		RequiredApprovals:      c.RequiredApprovals,
		RequireAdmin:           c.RequireAdmin,
		BreakglassRotateBefore: c.BreakglassRotateBefore,
		RequestedGraceSec:      int64(c.RequestedGrace.Seconds()),
		RevokeTokensBefore:     c.RevokeTokensBefore,
		ApprovedBy:             c.ApprovedBy,
		ApprovedAtUnix:         formatUnixOptional(c.ApprovedAt),
		RawIDToken:             c.RawIDToken,
	}
}

func formatUnixOptional(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return strconv.FormatInt(t.Unix(), 10)
}

func redisToChallengeData(data string) (Challenge, error) {
	var rc redisChallenge
	if err := json.Unmarshal([]byte(data), &rc); err != nil {
		return Challenge{}, err
	}
	return redisToChallenge(rc), nil
}

func redisToChallenge(rc redisChallenge) Challenge {
	createdAt := parseUnixTime(rc.CreatedAtUnix)
	expiresAt := parseUnixTime(rc.ExpiresAtUnix)
	approvedAt := parseUnixTime(rc.ApprovedAtUnix)
	return Challenge{
		ID:                     rc.ID,
		UserCode:               rc.UserCode,
		Username:               rc.Username,
		Status:                 ChallengeStatus(rc.Status),
		CreatedAt:              createdAt,
		ExpiresAt:              expiresAt,
		Nonce:                  rc.Nonce,
		Hostname:               rc.Hostname,
		Reason:                 rc.Reason,
		DenyReason:             rc.DenyReason,
		PolicyName:             rc.PolicyName,
		RequiredApprovals:      rc.RequiredApprovals,
		RequireAdmin:           rc.RequireAdmin,
		BreakglassRotateBefore: rc.BreakglassRotateBefore,
		RequestedGrace:         time.Duration(rc.RequestedGraceSec) * time.Second,
		RevokeTokensBefore:     rc.RevokeTokensBefore,
		ApprovedBy:             rc.ApprovedBy,
		ApprovedAt:             approvedAt,
		RawIDToken:             rc.RawIDToken,
	}
}

func parseUnixTime(s string) time.Time {
	if s == "" || s == "0" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

func (s *RedisStore) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.stopWg.Wait()
	if err := s.client.Close(); err != nil {
		slog.Error("redis: close error", "err", err)
	}
}

func (s *RedisStore) SaveState() {
	// No-op for Redis — all state is already persisted.
}

// ── Challenge CRUD ──────────────────────────────────────────────────────────

func (s *RedisStore) Create(username, hostname, breakglassRotateBefore, reason string) (*Challenge, error) {
	id, err := randutil.Hex(16)
	if err != nil {
		return nil, fmt.Errorf("generating challenge ID: %w", err)
	}
	code, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}

	now := time.Now()

	// Snapshot revokeTokensBefore for this challenge.
	var revokeTokensBefore string
	if v, err := s.client.Get(s.ctx(), s.revokeTokensKey(username)).Result(); err == nil {
		revokeTokensBefore = v
	}

	// Check per-host rotate-before; use it if it's newer than the global one.
	if hostname != "" {
		if perHostStr, err := s.client.Get(s.ctx(), s.rotateBreakKey(hostname)).Result(); err == nil {
			perHostT, parseErr := time.Parse(time.RFC3339, perHostStr)
			if parseErr == nil {
				var globalT time.Time
				if breakglassRotateBefore != "" {
					globalT, _ = time.Parse(time.RFC3339, breakglassRotateBefore)
				}
				if perHostT.After(globalT) {
					breakglassRotateBefore = perHostT.Format(time.RFC3339)
				}
			}
		}
	}

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

	rc := challengeToRedis(c)
	data, err := json.Marshal(rc)
	if err != nil {
		return nil, fmt.Errorf("marshaling challenge: %w", err)
	}

	ttlSec := int(s.challengeTTLWithBuffer().Seconds())

	err = luaCreate.Run(s.ctx(), s.client,
		[]string{
			s.challengeKey(id),
			s.byCodeKey(code),
			s.pendingUserKey(username),
			s.pendingTotalKey(),
		},
		string(data),
		ttlSec,
		code,
		maxChallengesPerUser,
		maxTotalChallenges,
		username,
	).Err()

	if err != nil {
		if err.Error() == "too_many_total" {
			return nil, fmt.Errorf("try again later: %w", ErrTooManyChallenges)
		}
		if err.Error() == "too_many_user" {
			return nil, fmt.Errorf("user %q, wait for existing ones to expire: %w", username, ErrTooManyPerUser)
		}
		if err.Error() == "code_collision" {
			return nil, fmt.Errorf("user code collision, try again")
		}
		return nil, fmt.Errorf("redis create: %w", err)
	}

	// Track user in the global set.
	s.client.SAdd(s.ctx(), s.usersAllKey(), username)

	return c, nil
}

func (s *RedisStore) Get(id string) (Challenge, bool) {
	data, err := s.client.Get(s.ctx(), s.challengeKey(id)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			slog.Error("redis Get: connection error", "key", s.challengeKey(id), "err", err)
		}
		return Challenge{}, false
	}
	c, err := redisToChallengeData(data)
	if err != nil {
		return Challenge{}, false
	}
	if time.Now().After(c.ExpiresAt) {
		return Challenge{}, false
	}
	return c, true
}

func (s *RedisStore) GetByCode(code string) (Challenge, bool) {
	id, err := s.client.Get(s.ctx(), s.byCodeKey(code)).Result()
	if err != nil {
		return Challenge{}, false
	}
	return s.Get(id)
}

func (s *RedisStore) SetNonce(id string, nonce string) error {
	err := luaSetNonce.Run(s.ctx(), s.client,
		[]string{s.challengeKey(id)},
		nonce,
		time.Now().Unix(),
	).Err()
	if err != nil {
		switch err.Error() {
		case "not_found":
			return fmt.Errorf("challenge not found")
		case "expired":
			return fmt.Errorf("challenge expired")
		case "already_resolved":
			return fmt.Errorf("challenge already resolved")
		case "nonce_already_set":
			return fmt.Errorf("nonce already set (login already initiated)")
		}
		return fmt.Errorf("redis SetNonce: %w", err)
	}
	return nil
}

func (s *RedisStore) SetRequestedGrace(id string, d time.Duration) {
	graceSec := int64(d.Seconds())
	err := luaSetRequestedGrace.Run(s.ctx(), s.client,
		[]string{s.challengeKey(id)},
		graceSec,
	).Err()
	if err != nil {
		// not_found is expected when the challenge expired between PAM request
		// and grace negotiation; only log unexpected errors.
		if !strings.Contains(err.Error(), "not_found") {
			slog.Error("redis: SetRequestedGrace", "id", id, "err", err)
		}
	}
}

func (s *RedisStore) Approve(id string, approvedBy string) error {
	c, ok := s.Get(id)
	if !ok {
		return fmt.Errorf("challenge not found")
	}

	now := time.Now()

	// Determine grace settings.
	var graceExpiryUnix int64
	var graceTTLSec int64
	if s.gracePeriod > 0 {
		graceDur := time.Duration(c.RequestedGrace)
		if graceDur == 0 {
			graceDur = s.gracePeriod
		}
		graceExpiry := now.Add(graceDur)
		graceExpiryUnix = graceExpiry.Unix()
		graceTTLSec = int64(graceDur.Seconds()) + 60
	}

	// Get revokeTokensBefore for this user.
	var revokeUnix int64
	if v, err := s.client.Get(s.ctx(), s.revokeTokensKey(c.Username)).Result(); err == nil {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			revokeUnix = t.Unix()
		}
	}

	grKey := s.graceKey(c.Username, c.Hostname)

	result, err := luaApprove.Run(s.ctx(), s.client,
		[]string{
			s.challengeKey(id),
			s.pendingUserKey(c.Username),
			s.pendingTotalKey(),
			grKey,
		},
		approvedBy,
		now.Unix(),
		graceExpiryUnix,
		graceTTLSec,
		revokeUnix,
	).Result()
	if err != nil {
		switch err.Error() {
		case "not_found":
			return fmt.Errorf("challenge not found")
		case "expired":
			return fmt.Errorf("challenge expired")
		case "already_resolved":
			return fmt.Errorf("challenge already resolved")
		case "revoked":
			return fmt.Errorf("challenge superseded by session revocation")
		}
		return fmt.Errorf("redis Approve: %w", err)
	}
	_ = result

	s.updateGraceGauge()
	return nil
}

func (s *RedisStore) Deny(id, reason string) error {
	c, ok := s.Get(id)
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	err := luaDeny.Run(s.ctx(), s.client,
		[]string{
			s.challengeKey(id),
			s.pendingUserKey(c.Username),
			s.pendingTotalKey(),
		},
		time.Now().Unix(),
		reason,
	).Err()
	if err != nil {
		switch err.Error() {
		case "not_found":
			return fmt.Errorf("challenge not found")
		case "expired":
			return fmt.Errorf("challenge expired")
		case "already_resolved":
			return fmt.Errorf("challenge already resolved")
		}
		return fmt.Errorf("redis Deny: %w", err)
	}
	return nil
}

func (s *RedisStore) AutoApprove(id string) error {
	c, ok := s.Get(id)
	if !ok {
		return fmt.Errorf("challenge not found")
	}
	// AutoApprove does NOT update grace — use Approve Lua but with no grace params.
	now := time.Now()
	var revokeUnix int64 // don't check revocation for auto-approve
	_, err := luaApprove.Run(s.ctx(), s.client,
		[]string{
			s.challengeKey(id),
			s.pendingUserKey(c.Username),
			s.pendingTotalKey(),
			s.graceKey(c.Username, c.Hostname), // won't be set since graceExpiry=0
		},
		c.Username,
		now.Unix(),
		0, // no grace
		0, // no grace TTL
		revokeUnix,
	).Result()
	if err != nil {
		switch err.Error() {
		case "not_found":
			return fmt.Errorf("challenge not found")
		case "expired":
			return fmt.Errorf("challenge expired")
		case "already_resolved":
			return fmt.Errorf("challenge already resolved")
		}
		return fmt.Errorf("redis AutoApprove: %w", err)
	}
	return nil
}

func (s *RedisStore) AutoApproveIfWithinGracePeriod(username, hostname, id string) bool {
	if s.gracePeriod <= 0 {
		return false
	}
	now := time.Now()
	grKey := s.graceKey(username, hostname)
	err := luaAutoApproveGrace.Run(s.ctx(), s.client,
		[]string{
			grKey,
			s.challengeKey(id),
			s.pendingUserKey(username),
			s.pendingTotalKey(),
		},
		now.Unix(),
	).Err()
	return err == nil
}

// ── One-tap ─────────────────────────────────────────────────────────────────

func (s *RedisStore) ConsumeOneTap(challengeID string) error {
	err := luaConsumeOneTap.Run(s.ctx(), s.client,
		[]string{
			s.oneTapKey(challengeID),
			s.challengeKey(challengeID),
		},
		int(s.challengeTTLWithBuffer().Seconds()),
		time.Now().Unix(),
	).Err()
	if err != nil {
		switch err.Error() {
		case "not_found", "expired":
			return fmt.Errorf("challenge not found or expired")
		case "already_used":
			return fmt.Errorf("one-tap already used")
		}
		return fmt.Errorf("redis ConsumeOneTap: %w", err)
	}
	return nil
}

func (s *RedisStore) ConsumeAndApprove(challengeID, approvedBy string) error {
	c, ok := s.Get(challengeID)
	if !ok {
		return fmt.Errorf("challenge not found or expired")
	}

	now := time.Now()
	var graceExpiryUnix int64
	var graceTTLSec int64
	if s.gracePeriod > 0 {
		graceDur := c.RequestedGrace
		if graceDur == 0 {
			graceDur = s.gracePeriod
		}
		graceExpiry := now.Add(graceDur)
		graceExpiryUnix = graceExpiry.Unix()
		graceTTLSec = int64(graceDur.Seconds()) + 60
	}

	var revokeUnix int64
	if v, err := s.client.Get(s.ctx(), s.revokeTokensKey(c.Username)).Result(); err == nil {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			revokeUnix = t.Unix()
		}
	}

	grKey := s.graceKey(c.Username, c.Hostname)

	_, err := luaConsumeAndApprove.Run(s.ctx(), s.client,
		[]string{
			s.oneTapKey(challengeID),
			s.challengeKey(challengeID),
			s.pendingUserKey(c.Username),
			s.pendingTotalKey(),
			grKey,
		},
		int(s.challengeTTLWithBuffer().Seconds()),
		approvedBy,
		now.Unix(),
		graceExpiryUnix,
		graceTTLSec,
		revokeUnix,
	).Result()
	if err != nil {
		switch err.Error() {
		case "not_found", "expired":
			return fmt.Errorf("challenge not found or expired")
		case "already_used":
			return fmt.Errorf("one-tap already used")
		case "already_resolved":
			return fmt.Errorf("challenge already resolved")
		case "revoked":
			return fmt.Errorf("challenge superseded by session revocation")
		}
		return fmt.Errorf("redis ConsumeAndApprove: %w", err)
	}

	s.updateGraceGauge()
	return nil
}

// ── Grace period / sessions ─────────────────────────────────────────────────

func (s *RedisStore) WithinGracePeriod(username, hostname string) bool {
	if s.gracePeriod <= 0 {
		return false
	}
	v, err := s.client.Get(s.ctx(), s.graceKey(username, hostname)).Result()
	if err != nil {
		return false
	}
	expiryUnix, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Before(time.Unix(expiryUnix, 0))
}

func (s *RedisStore) GraceRemaining(username, hostname string) time.Duration {
	if s.gracePeriod <= 0 {
		return 0
	}
	v, err := s.client.Get(s.ctx(), s.graceKey(username, hostname)).Result()
	if err != nil {
		return 0
	}
	expiryUnix, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	remaining := time.Until(time.Unix(expiryUnix, 0))
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (s *RedisStore) ActiveSessions(username string) []GraceSession {
	return s.scanGraceSessions(s.prefix+"grace:"+username+"*", username)
}

func (s *RedisStore) AllActiveSessions() []GraceSession {
	return s.scanGraceSessions(s.prefix+"grace:*", "")
}

func (s *RedisStore) ActiveSessionsForHost(hostname string) []GraceSession {
	pattern := s.prefix + "grace:*\x00" + hostname
	return s.scanGraceSessions(pattern, "")
}

func (s *RedisStore) scanGraceSessions(pattern, filterUsername string) []GraceSession {
	now := time.Now()
	var sessions []GraceSession
	var cursor uint64
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		for _, key := range keys {
			v, err := s.client.Get(s.ctx(), key).Result()
			if err != nil {
				continue
			}
			expiryUnix, err := strconv.ParseInt(v, 10, 64)
			if err != nil || now.After(time.Unix(expiryUnix, 0)) {
				continue
			}
			// Parse username and hostname from key.
			suffix := strings.TrimPrefix(key, s.prefix+"grace:")
			parts := strings.SplitN(suffix, "\x00", 2)
			user := parts[0]
			host := "(unknown)"
			if len(parts) == 2 {
				host = parts[1]
			}
			if filterUsername != "" && user != filterUsername {
				continue
			}
			sessions = append(sessions, GraceSession{
				Username:  user,
				Hostname:  host,
				ExpiresAt: time.Unix(expiryUnix, 0),
			})
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return sessions
}

func (s *RedisStore) CreateGraceSession(username, hostname string, duration time.Duration) {
	expiry := time.Now().Add(duration)
	ttl := duration + 60*time.Second
	s.client.Set(s.ctx(), s.graceKey(username, hostname), expiry.Unix(), ttl)
	s.updateGraceGauge()
}

func (s *RedisStore) ExtendGraceSession(username, hostname string) (time.Duration, error) {
	key := s.graceKey(username, hostname)
	v, err := s.client.Get(s.ctx(), key).Result()
	if err != nil {
		return 0, nil
	}
	expiryUnix, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, nil
	}
	remaining := time.Until(time.Unix(expiryUnix, 0))
	if remaining > s.gracePeriod*3/4 {
		return remaining, ErrSessionSufficientlyExtended
	}
	newExpiry := time.Now().Add(s.gracePeriod)
	ttl := s.gracePeriod + 60*time.Second
	s.client.Set(s.ctx(), key, newExpiry.Unix(), ttl)
	return s.gracePeriod, nil
}

func (s *RedisStore) ForceExtendGraceSession(username, hostname string) time.Duration {
	if s.gracePeriod <= 0 {
		return 0
	}
	key := s.graceKey(username, hostname)
	_, err := s.client.Get(s.ctx(), key).Result()
	if err != nil {
		return 0
	}
	newExpiry := time.Now().Add(s.gracePeriod)
	ttl := s.gracePeriod + 60*time.Second
	s.client.Set(s.ctx(), key, newExpiry.Unix(), ttl)
	return s.gracePeriod
}

func (s *RedisStore) ExtendGraceSessionFor(username, hostname string, dur time.Duration) time.Duration {
	if s.gracePeriod <= 0 {
		return 0
	}
	key := s.graceKey(username, hostname)
	_, err := s.client.Get(s.ctx(), key).Result()
	if err != nil {
		return 0
	}
	if dur > s.gracePeriod {
		dur = s.gracePeriod
	}
	newExpiry := time.Now().Add(dur)
	ttl := dur + 60*time.Second
	s.client.Set(s.ctx(), key, newExpiry.Unix(), ttl)
	return dur
}

func (s *RedisStore) RevokeSession(username, hostname string) {
	s.client.Del(s.ctx(), s.graceKey(username, hostname))
	s.client.Set(s.ctx(), s.revokeTokensKey(username), time.Now().Format(time.RFC3339), 30*24*time.Hour)
	s.updateGraceGauge()
}

// ── Challenge queries ───────────────────────────────────────────────────────

func (s *RedisStore) PendingChallenges(username string) []Challenge {
	return s.scanChallenges(func(c Challenge) bool {
		return c.Username == username && c.Status == StatusPending && time.Now().Before(c.ExpiresAt)
	})
}

func (s *RedisStore) AllPendingChallenges() []Challenge {
	return s.scanChallenges(func(c Challenge) bool {
		return c.Status == StatusPending && time.Now().Before(c.ExpiresAt)
	})
}

func (s *RedisStore) scanChallenges(filter func(Challenge) bool) []Challenge {
	var result []Challenge
	var cursor uint64
	pattern := s.prefix + "challenge:*"
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		for _, key := range keys {
			data, err := s.client.Get(s.ctx(), key).Result()
			if err != nil {
				continue
			}
			c, err := redisToChallengeData(data)
			if err != nil {
				continue
			}
			if filter(c) {
				result = append(result, c)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return result
}

// ── Revocation ──────────────────────────────────────────────────────────────

func (s *RedisStore) RevokeTokensBefore(username string) time.Time {
	v, err := s.client.Get(s.ctx(), s.revokeTokensKey(username)).Result()
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ── OIDC auth tracking ──────────────────────────────────────────────────────

func (s *RedisStore) RecordOIDCAuth(username string) {
	s.client.Set(s.ctx(), s.lastOIDCKey(username), time.Now().Unix(), 30*24*time.Hour)
}

func (s *RedisStore) LastOIDCAuth(username string) time.Time {
	v, err := s.client.Get(s.ctx(), s.lastOIDCKey(username)).Result()
	if err != nil {
		return time.Time{}
	}
	ts, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

// ── Action log ──────────────────────────────────────────────────────────────

const redisActionLogMax = 2000

func (s *RedisStore) LogAction(username, action, hostname, code, actor string) {
	s.LogActionAt(username, action, hostname, code, actor, time.Now())
}

func (s *RedisStore) LogActionWithReason(username, action, hostname, code, actor, reason string) {
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
	s.pushActionLog(username, entry)
}

func (s *RedisStore) LogActionAt(username, action, hostname, code, actor string, at time.Time) {
	entry := ActionLogEntry{
		Timestamp: at,
		Action:    action,
		Hostname:  hostname,
		Code:      code,
	}
	if actor != "" && actor != username {
		entry.Actor = actor
	}
	s.pushActionLog(username, entry)
}

func (s *RedisStore) pushActionLog(username string, entry ActionLogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		slog.Error("redis: marshal action log entry", "err", err)
		return
	}
	pipe := s.client.Pipeline()
	pipe.LPush(s.ctx(), s.actionLogKey(username), string(data))
	pipe.LTrim(s.ctx(), s.actionLogKey(username), 0, redisActionLogMax-1)
	// Track user and host in secondary indexes.
	pipe.SAdd(s.ctx(), s.usersAllKey(), username)
	if entry.Hostname != "" && entry.Hostname != "(unknown)" {
		pipe.SAdd(s.ctx(), s.knownHostsKey(username), entry.Hostname)
		pipe.SAdd(s.ctx(), s.hostActivityKey(entry.Hostname), username)
	}
	if _, err := pipe.Exec(s.ctx()); err != nil {
		slog.Error("redis: push action log", "err", err)
	}
}

func (s *RedisStore) ActionHistory(username string, limit int) []ActionLogEntry {
	end := int64(-1)
	if limit > 0 {
		end = int64(limit - 1)
	}
	items, err := s.client.LRange(s.ctx(), s.actionLogKey(username), 0, end).Result()
	if err != nil {
		return nil
	}
	result := make([]ActionLogEntry, 0, len(items))
	for _, item := range items {
		var entry ActionLogEntry
		if json.Unmarshal([]byte(item), &entry) == nil {
			result = append(result, entry)
		}
	}
	return result
}

func (s *RedisStore) AllActionHistory() []ActionLogEntry {
	users, err := s.client.SMembers(s.ctx(), s.usersAllKey()).Result()
	if err != nil {
		return nil
	}
	var all []ActionLogEntry
	for _, user := range users {
		all = append(all, s.ActionHistory(user, 0)...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Timestamp.After(all[j].Timestamp) })
	return all
}

func (s *RedisStore) AllActionHistoryWithUsers() []ActionLogEntryWithUser {
	users, err := s.client.SMembers(s.ctx(), s.usersAllKey()).Result()
	if err != nil {
		return nil
	}
	var all []ActionLogEntryWithUser
	for _, user := range users {
		for _, e := range s.ActionHistory(user, 0) {
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

// ── Host data ───────────────────────────────────────────────────────────────

func (s *RedisStore) KnownHosts(username string) []string {
	hosts, err := s.client.SMembers(s.ctx(), s.knownHostsKey(username)).Result()
	if err != nil {
		return nil
	}
	// Filter out hosts that only have "removed_host" entries.
	// For Redis, the SADD approach means we need to check if the host was removed.
	// This is a simplification — the set tracks all seen hosts.
	sort.Strings(hosts)
	return hosts
}

func (s *RedisStore) AllKnownHosts() []string {
	users, err := s.client.SMembers(s.ctx(), s.usersAllKey()).Result()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	for _, user := range users {
		hosts, err := s.client.SMembers(s.ctx(), s.knownHostsKey(user)).Result()
		if err != nil {
			continue
		}
		for _, h := range hosts {
			seen[h] = true
		}
	}
	result := make([]string, 0, len(seen))
	for h := range seen {
		result = append(result, h)
	}
	sort.Strings(result)
	return result
}

func (s *RedisStore) UsersWithHostActivity(hostname string) []string {
	users, err := s.client.SMembers(s.ctx(), s.hostActivityKey(hostname)).Result()
	if err != nil {
		return nil
	}
	return users
}

func (s *RedisStore) RemoveHost(hostname string) {
	// Remove host from all known host sets.
	users, _ := s.client.SMembers(s.ctx(), s.hostActivityKey(hostname)).Result()
	for _, user := range users {
		s.client.SRem(s.ctx(), s.knownHostsKey(user), hostname)
	}
	// Delete host activity set, escrow, and grace sessions.
	s.client.Del(s.ctx(), s.hostActivityKey(hostname))
	s.client.Del(s.ctx(), s.escrowKey(hostname))
	s.client.Del(s.ctx(), s.escrowCipherKey(hostname))
	// Remove grace sessions for this host.
	var cursor uint64
	pattern := s.prefix + "grace:*\x00" + hostname
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		for _, key := range keys {
			s.client.Del(s.ctx(), key)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}

// ── Escrow ──────────────────────────────────────────────────────────────────

func (s *RedisStore) RecordEscrow(hostname, itemID, vaultID string) {
	rec := EscrowRecord{Timestamp: time.Now(), ItemID: itemID, VaultID: vaultID}
	data, _ := json.Marshal(rec)
	s.client.Set(s.ctx(), s.escrowKey(hostname), string(data), 120*24*time.Hour)
}

func (s *RedisStore) StoreEscrowCiphertext(hostname, ciphertext string) {
	s.client.Set(s.ctx(), s.escrowCipherKey(hostname), ciphertext, 120*24*time.Hour)
}

func (s *RedisStore) GetEscrowCiphertext(hostname string) (string, bool) {
	v, err := s.client.Get(s.ctx(), s.escrowCipherKey(hostname)).Result()
	if err != nil {
		return "", false
	}
	return v, true
}

func (s *RedisStore) EscrowedHosts() map[string]EscrowRecord {
	result := make(map[string]EscrowRecord)
	var cursor uint64
	pattern := s.prefix + "escrow:*"
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		for _, key := range keys {
			// Skip escrow_cipher keys.
			if strings.Contains(key, "escrow_cipher:") {
				continue
			}
			hostname := strings.TrimPrefix(key, s.prefix+"escrow:")
			data, err := s.client.Get(s.ctx(), key).Result()
			if err != nil {
				continue
			}
			var rec EscrowRecord
			if json.Unmarshal([]byte(data), &rec) == nil {
				result[hostname] = rec
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return result
}

// ── Host rotation ───────────────────────────────────────────────────────────

func (s *RedisStore) SetHostRotateBefore(hostname string) {
	s.client.Set(s.ctx(), s.rotateBreakKey(hostname), time.Now().Format(time.RFC3339), 30*24*time.Hour)
}

func (s *RedisStore) HostRotateBefore(hostname string) time.Time {
	v, err := s.client.Get(s.ctx(), s.rotateBreakKey(hostname)).Result()
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (s *RedisStore) SetAllHostsRotateBefore(hostnames []string) {
	now := time.Now().Format(time.RFC3339)
	pipe := s.client.Pipeline()
	for _, h := range hostnames {
		pipe.Set(s.ctx(), s.rotateBreakKey(h), now, 30*24*time.Hour)
	}
	pipe.Exec(s.ctx())
}

// ── User management ─────────────────────────────────────────────────────────

func (s *RedisStore) AllUsers() []string {
	users, err := s.client.SMembers(s.ctx(), s.usersAllKey()).Result()
	if err != nil {
		return nil
	}
	sort.Strings(users)
	return users
}

func (s *RedisStore) RemoveUser(username string) {
	// Cancel pending challenges.
	for _, c := range s.PendingChallenges(username) {
		s.client.Del(s.ctx(), s.challengeKey(c.ID))
		s.client.Del(s.ctx(), s.byCodeKey(c.UserCode))
		s.client.Del(s.ctx(), s.oneTapKey(c.ID))
	}
	// Reset pending counters for this user.
	s.client.Del(s.ctx(), s.pendingUserKey(username))

	// Remove grace sessions.
	var cursor uint64
	pattern := s.prefix + "grace:" + username + "*"
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		for _, key := range keys {
			s.client.Del(s.ctx(), key)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	// Set revocation timestamp.
	s.client.Set(s.ctx(), s.revokeTokensKey(username), time.Now().Format(time.RFC3339), 30*24*time.Hour)

	// Remove action log.
	s.client.Del(s.ctx(), s.actionLogKey(username))

	// Remove OIDC auth timestamp.
	s.client.Del(s.ctx(), s.lastOIDCKey(username))

	// Remove known hosts set.
	s.client.Del(s.ctx(), s.knownHostsKey(username))

	// Remove from global user set.
	s.client.SRem(s.ctx(), s.usersAllKey(), username)
}

// ── Session persistence (revoked nonces / admin sessions) ───────────────────

func (s *RedisStore) PersistRevokedNonce(nonce string, at time.Time) {
	s.client.Set(s.ctx(), s.revokedNonceKey(nonce), at.Unix(), 35*time.Minute)
}

func (s *RedisStore) PersistRevokedAdminSession(username string, at time.Time) {
	s.client.Set(s.ctx(), s.revokedAdminKey(username), at.Unix(), 35*time.Minute)
}

func (s *RedisStore) LoadRevokedNonces() map[string]time.Time {
	result := make(map[string]time.Time)
	var cursor uint64
	pattern := s.prefix + "revokednonce:*"
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		for _, key := range keys {
			v, err := s.client.Get(s.ctx(), key).Result()
			if err != nil {
				continue
			}
			ts, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			nonce := strings.TrimPrefix(key, s.prefix+"revokednonce:")
			result[nonce] = time.Unix(ts, 0)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return result
}

func (s *RedisStore) LoadRevokedAdminSessions() map[string]time.Time {
	result := make(map[string]time.Time)
	var cursor uint64
	pattern := s.prefix + "revokedadmin:*"
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		for _, key := range keys {
			v, err := s.client.Get(s.ctx(), key).Result()
			if err != nil {
				continue
			}
			ts, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			username := strings.TrimPrefix(key, s.prefix+"revokedadmin:")
			result[username] = time.Unix(ts, 0)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return result
}

// ── Escrow token replay prevention ──────────────────────────────────────────

// CheckAndRecordEscrowToken returns true if tokenKey was already seen (replay).
// On Redis errors the method fails closed (returns true) to prevent replay.
func (s *RedisStore) CheckAndRecordEscrowToken(tokenKey string) (alreadySeen bool) {
	set, err := s.client.SetNX(s.ctx(), s.escrowTokenKey(tokenKey), "1", 10*time.Minute).Result()
	if err != nil {
		slog.Error("redis: CheckAndRecordEscrowToken (failing closed)", "err", err)
		return true
	}
	return !set // SetNX returns false if key already existed
}

func (s *RedisStore) UsedEscrowTokenCount() int {
	var count int
	var cursor uint64
	pattern := s.prefix + "escrowtoken:*"
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		count += len(keys)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return count
}

// ── Health check ────────────────────────────────────────────────────────────

func (s *RedisStore) HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.client.Ping(ctx).Err()
}

// ── Session nonces ──────────────────────────────────────────────────────────

func (s *RedisStore) StoreSessionNonce(nonce string, data SessionNonceData, ttl time.Duration) error {
	d, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis StoreSessionNonce: %w", err)
	}
	return s.client.Set(s.ctx(), s.sessionNonceKey(nonce), string(d), ttl).Err()
}

func (s *RedisStore) GetSessionNonce(nonce string) (SessionNonceData, bool) {
	v, err := s.client.Get(s.ctx(), s.sessionNonceKey(nonce)).Result()
	if err != nil {
		return SessionNonceData{}, false
	}
	var data SessionNonceData
	if json.Unmarshal([]byte(v), &data) != nil {
		return SessionNonceData{}, false
	}
	return data, true
}

func (s *RedisStore) DeleteSessionNonce(nonce string) {
	s.client.Del(s.ctx(), s.sessionNonceKey(nonce))
}

// ── Background reconciliation ───────────────────────────────────────────────

func (s *RedisStore) reconcileLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reconcilePendingCounters()
		case <-s.stopCh:
			return
		}
	}
}

// reconcilePendingCounters scans all challenge keys, counts pending challenges,
// and corrects the pending counters if they've drifted.
func (s *RedisStore) reconcilePendingCounters() {
	now := time.Now()
	perUser := make(map[string]int)
	total := 0
	var cursor uint64
	pattern := s.prefix + "challenge:*"
	for {
		keys, nextCursor, err := s.client.Scan(s.ctx(), cursor, pattern, 100).Result()
		if err != nil {
			slog.Warn("redis: reconcile scan error", "err", err)
			return
		}
		for _, key := range keys {
			data, err := s.client.Get(s.ctx(), key).Result()
			if err != nil {
				continue
			}
			c, err := redisToChallengeData(data)
			if err != nil || c.Status != StatusPending || now.After(c.ExpiresAt) {
				continue
			}
			perUser[c.Username]++
			total++
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	// Correct the total pending counter.
	currentTotal, _ := s.client.Get(s.ctx(), s.pendingTotalKey()).Int()
	if currentTotal != total {
		slog.Info("redis: reconciling pending total counter", "was", currentTotal, "actual", total)
		s.client.Set(s.ctx(), s.pendingTotalKey(), total, s.challengeTTLWithBuffer())
	}

	// Correct per-user pending counters.
	for user, count := range perUser {
		currentUser, _ := s.client.Get(s.ctx(), s.pendingUserKey(user)).Int()
		if currentUser != count {
			slog.Info("redis: reconciling pending user counter", "user", user, "was", currentUser, "actual", count)
			s.client.Set(s.ctx(), s.pendingUserKey(user), count, s.challengeTTLWithBuffer())
		}
	}

	// Update the active challenges gauge.
	ActiveChallenges.Set(float64(total))
}

// updateGraceGauge updates the grace sessions gauge by scanning grace keys.
func (s *RedisStore) updateGraceGauge() {
	sessions := s.AllActiveSessions()
	graceSessions.Set(float64(len(sessions)))
}
