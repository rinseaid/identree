package challenge

// SQL schema for the identree state store.
//
// Two dialects are supported: SQLite (modernc.org/sqlite, single-node homelab
// deploys) and PostgreSQL (HA / enterprise). All timestamps are stored as
// INTEGER Unix seconds (or 0 sentinel) to avoid datetime-type portability
// issues across dialects and to keep range index lookups fast.
//
// The schema is applied with CREATE TABLE IF NOT EXISTS at startup. No
// migration framework is in place yet; v1 is greenfield and we add a real
// migrator the first time the schema needs to evolve.

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS challenges (
  id                          TEXT    PRIMARY KEY,
  user_code                   TEXT    NOT NULL UNIQUE,
  username                    TEXT    NOT NULL,
  status                      TEXT    NOT NULL,
  hostname                    TEXT    NOT NULL DEFAULT '',
  reason                      TEXT    NOT NULL DEFAULT '',
  nonce                       TEXT    NOT NULL DEFAULT '',
  created_at                  INTEGER NOT NULL,
  expires_at                  INTEGER NOT NULL,
  approved_by                 TEXT    NOT NULL DEFAULT '',
  approved_at                 INTEGER NOT NULL DEFAULT 0,
  deny_reason                 TEXT    NOT NULL DEFAULT '',
  breakglass_rotate_before    TEXT    NOT NULL DEFAULT '',
  requested_grace_ns          INTEGER NOT NULL DEFAULT 0,
  revoke_tokens_before        TEXT    NOT NULL DEFAULT '',
  policy_name                 TEXT    NOT NULL DEFAULT '',
  required_approvals          INTEGER NOT NULL DEFAULT 0,
  require_admin               INTEGER NOT NULL DEFAULT 0,
  breakglass_override         INTEGER NOT NULL DEFAULT 0,
  breakglass_bypass_allowed   INTEGER NOT NULL DEFAULT 0,
  one_tap_used                INTEGER NOT NULL DEFAULT 0,
  approvals_json              TEXT    NOT NULL DEFAULT '[]',
  raw_id_token                TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_challenges_user_status ON challenges(username, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_expires    ON challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_status     ON challenges(status, expires_at);

CREATE TABLE IF NOT EXISTS action_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT    NOT NULL,
  action      TEXT    NOT NULL,
  hostname    TEXT    NOT NULL DEFAULT '',
  code        TEXT    NOT NULL DEFAULT '',
  actor       TEXT    NOT NULL DEFAULT '',
  reason      TEXT    NOT NULL DEFAULT '',
  ts_unix     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_log_user_ts ON action_log(username, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_action_log_ts      ON action_log(ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_action_log_host_ts ON action_log(hostname, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_action_log_action  ON action_log(action, ts_unix DESC);

CREATE TABLE IF NOT EXISTS grace_sessions (
  username    TEXT    NOT NULL,
  hostname    TEXT    NOT NULL DEFAULT '',
  expiry_unix INTEGER NOT NULL,
  hmac_hex    TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (username, hostname)
);
CREATE INDEX IF NOT EXISTS idx_grace_expiry ON grace_sessions(expiry_unix);
CREATE INDEX IF NOT EXISTS idx_grace_host   ON grace_sessions(hostname);

CREATE TABLE IF NOT EXISTS revoked_nonces (
  nonce      TEXT    PRIMARY KEY,
  revoked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_nonces_at ON revoked_nonces(revoked_at);

CREATE TABLE IF NOT EXISTS revoked_admin_sessions (
  username   TEXT    PRIMARY KEY,
  revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revoke_tokens_before (
  username   TEXT    PRIMARY KEY,
  revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rotate_breakglass_before (
  hostname   TEXT    PRIMARY KEY,
  rotated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS last_oidc_auth (
  username   TEXT    PRIMARY KEY,
  at_unix    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS escrowed_hosts (
  hostname   TEXT    PRIMARY KEY,
  ts_unix    INTEGER NOT NULL,
  item_id    TEXT    NOT NULL DEFAULT '',
  vault_id   TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS escrow_ciphertexts (
  hostname   TEXT    PRIMARY KEY,
  ciphertext TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS used_escrow_tokens (
  token_key  TEXT    PRIMARY KEY,
  first_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_used_escrow_tokens_at ON used_escrow_tokens(first_seen);

CREATE TABLE IF NOT EXISTS session_nonces (
  nonce         TEXT    PRIMARY KEY,
  issued_at     INTEGER NOT NULL,
  code_verifier TEXT    NOT NULL DEFAULT '',
  client_ip     TEXT    NOT NULL DEFAULT '',
  expires_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_nonces_exp ON session_nonces(expires_at);

CREATE TABLE IF NOT EXISTS agents (
  hostname    TEXT    PRIMARY KEY,
  version     TEXT    NOT NULL DEFAULT '',
  os_info     TEXT    NOT NULL DEFAULT '',
  ip          TEXT    NOT NULL DEFAULT '',
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);

CREATE TABLE IF NOT EXISTS cluster_messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  topic      TEXT    NOT NULL,
  payload    TEXT    NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cluster_messages_at ON cluster_messages(created_at);

CREATE TABLE IF NOT EXISTS notify_admin_prefs (
  username   TEXT    PRIMARY KEY,
  prefs_json TEXT    NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS notify_config (
  config_key  TEXT    PRIMARY KEY,
  config_json TEXT    NOT NULL DEFAULT '{}'
);
`

const postgresSchema = `
CREATE TABLE IF NOT EXISTS challenges (
  id                          TEXT     PRIMARY KEY,
  user_code                   TEXT     NOT NULL UNIQUE,
  username                    TEXT     NOT NULL,
  status                      TEXT     NOT NULL,
  hostname                    TEXT     NOT NULL DEFAULT '',
  reason                      TEXT     NOT NULL DEFAULT '',
  nonce                       TEXT     NOT NULL DEFAULT '',
  created_at                  BIGINT   NOT NULL,
  expires_at                  BIGINT   NOT NULL,
  approved_by                 TEXT     NOT NULL DEFAULT '',
  approved_at                 BIGINT   NOT NULL DEFAULT 0,
  deny_reason                 TEXT     NOT NULL DEFAULT '',
  breakglass_rotate_before    TEXT     NOT NULL DEFAULT '',
  requested_grace_ns          BIGINT   NOT NULL DEFAULT 0,
  revoke_tokens_before        TEXT     NOT NULL DEFAULT '',
  policy_name                 TEXT     NOT NULL DEFAULT '',
  required_approvals          INTEGER  NOT NULL DEFAULT 0,
  require_admin               SMALLINT NOT NULL DEFAULT 0,
  breakglass_override         SMALLINT NOT NULL DEFAULT 0,
  breakglass_bypass_allowed   SMALLINT NOT NULL DEFAULT 0,
  one_tap_used                SMALLINT NOT NULL DEFAULT 0,
  approvals_json              TEXT     NOT NULL DEFAULT '[]',
  raw_id_token                TEXT     NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_challenges_user_status ON challenges(username, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_expires    ON challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_status     ON challenges(status, expires_at);

CREATE TABLE IF NOT EXISTS action_log (
  id          BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username    TEXT    NOT NULL,
  action      TEXT    NOT NULL,
  hostname    TEXT    NOT NULL DEFAULT '',
  code        TEXT    NOT NULL DEFAULT '',
  actor       TEXT    NOT NULL DEFAULT '',
  reason      TEXT    NOT NULL DEFAULT '',
  ts_unix     BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_log_user_ts ON action_log(username, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_action_log_ts      ON action_log(ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_action_log_host_ts ON action_log(hostname, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_action_log_action  ON action_log(action, ts_unix DESC);

CREATE TABLE IF NOT EXISTS grace_sessions (
  username    TEXT   NOT NULL,
  hostname    TEXT   NOT NULL DEFAULT '',
  expiry_unix BIGINT NOT NULL,
  hmac_hex    TEXT   NOT NULL DEFAULT '',
  PRIMARY KEY (username, hostname)
);
CREATE INDEX IF NOT EXISTS idx_grace_expiry ON grace_sessions(expiry_unix);
CREATE INDEX IF NOT EXISTS idx_grace_host   ON grace_sessions(hostname);

CREATE TABLE IF NOT EXISTS revoked_nonces (
  nonce      TEXT   PRIMARY KEY,
  revoked_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_nonces_at ON revoked_nonces(revoked_at);

CREATE TABLE IF NOT EXISTS revoked_admin_sessions (
  username   TEXT   PRIMARY KEY,
  revoked_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoke_tokens_before (
  username   TEXT   PRIMARY KEY,
  revoked_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS rotate_breakglass_before (
  hostname   TEXT   PRIMARY KEY,
  rotated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS last_oidc_auth (
  username   TEXT   PRIMARY KEY,
  at_unix    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS escrowed_hosts (
  hostname   TEXT   PRIMARY KEY,
  ts_unix    BIGINT NOT NULL,
  item_id    TEXT   NOT NULL DEFAULT '',
  vault_id   TEXT   NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS escrow_ciphertexts (
  hostname   TEXT   PRIMARY KEY,
  ciphertext TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS used_escrow_tokens (
  token_key  TEXT   PRIMARY KEY,
  first_seen BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_used_escrow_tokens_at ON used_escrow_tokens(first_seen);

CREATE TABLE IF NOT EXISTS session_nonces (
  nonce         TEXT   PRIMARY KEY,
  issued_at     BIGINT NOT NULL,
  code_verifier TEXT   NOT NULL DEFAULT '',
  client_ip     TEXT   NOT NULL DEFAULT '',
  expires_at    BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_nonces_exp ON session_nonces(expires_at);

CREATE TABLE IF NOT EXISTS agents (
  hostname    TEXT   PRIMARY KEY,
  version     TEXT   NOT NULL DEFAULT '',
  os_info     TEXT   NOT NULL DEFAULT '',
  ip          TEXT   NOT NULL DEFAULT '',
  first_seen  BIGINT NOT NULL,
  last_seen   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);

CREATE TABLE IF NOT EXISTS cluster_messages (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  topic      TEXT   NOT NULL,
  payload    TEXT   NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cluster_messages_at ON cluster_messages(created_at);

CREATE TABLE IF NOT EXISTS notify_admin_prefs (
  username   TEXT   PRIMARY KEY,
  prefs_json TEXT   NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS notify_config (
  config_key  TEXT  PRIMARY KEY,
  config_json TEXT  NOT NULL DEFAULT '{}'
);
`
