package challenge

import (
	"context"
	"fmt"
	"log/slog"
)

// migration defines a single forward-only schema change. Each migration
// provides dialect-specific SQL; the framework picks the right one at
// runtime. Migrations run inside a transaction and are recorded in
// schema_migrations on success. If a transaction fails it rolls back
// and the version row is never written, so the next startup retries.
//
// SQLite notes for future migration authors:
//   - CREATE TABLE, ALTER TABLE ADD COLUMN, CREATE INDEX all work inside
//     transactions.
//   - ALTER TABLE RENAME COLUMN requires SQLite 3.25+ (modernc provides it).
//   - ALTER TABLE DROP COLUMN requires SQLite 3.35+ (modernc provides it).
type migration struct {
	Version     int
	Description string
	SQLite      string
	Postgres    string
}

// migrationLockID is the Postgres advisory lock key used to prevent
// concurrent replicas from running migrations simultaneously.
const migrationLockID int64 = 7294829183

// migrations is the ordered list of all schema migrations. Append only.
// Each entry's Version must be strictly increasing.
var migrations = []migration{
	{
		Version:     1,
		Description: "baseline schema",
		SQLite:      sqliteSchema,
		Postgres:    postgresSchema,
	},
}

// migrate creates the schema_migrations table, acquires a Postgres advisory
// lock if needed, and applies any pending migrations. Called once during
// NewSQLStore before the store is returned to the caller.
func (s *SQLStore) migrate(ctx context.Context) error {
	if err := s.ensureMigrationsTable(ctx); err != nil {
		return err
	}
	if s.dialect == DialectPostgres {
		conn, err := s.db.Conn(ctx)
		if err != nil {
			return fmt.Errorf("migrate: conn: %w", err)
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
			return fmt.Errorf("migrate: advisory lock: %w", err)
		}
		defer conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", migrationLockID) //nolint:errcheck
	}
	return s.runMigrations(ctx, migrations)
}

// runMigrations applies all unapplied migrations from the given slice.
// Separated from migrate() so tests can inject custom migration lists.
func (s *SQLStore) runMigrations(ctx context.Context, migs []migration) error {
	var current int
	err := s.db.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&current)
	if err != nil {
		return fmt.Errorf("migrate: read version: %w", err)
	}

	applied := 0
	for _, m := range migs {
		if m.Version <= current {
			continue
		}
		ddl := m.SQLite
		if s.dialect == DialectPostgres {
			ddl = m.Postgres
		}
		if err := s.applyMigration(ctx, m.Version, m.Description, ddl); err != nil {
			return err
		}
		applied++
	}
	if applied == 0 {
		slog.Info("schema up to date", "version", current)
	}
	return nil
}

// applyMigration runs a single migration inside a transaction.
func (s *SQLStore) applyMigration(ctx context.Context, version int, description, ddl string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate v%d: begin: %w", version, err)
	}
	if _, err := tx.ExecContext(ctx, ddl); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("migrate v%d (%s): %w", version, description, err)
	}
	if _, err := tx.ExecContext(ctx,
		s.q("INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)"),
		version, description, nowUnix()); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("migrate v%d: record: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate v%d: commit: %w", version, err)
	}
	slog.Info("migration applied", "version", version, "description", description)
	return nil
}

// ensureMigrationsTable creates the version-tracking table if absent.
// This is the one table that is never itself a migration.
func (s *SQLStore) ensureMigrationsTable(ctx context.Context) error {
	ddl := `CREATE TABLE IF NOT EXISTS schema_migrations (
		version     INTEGER PRIMARY KEY,
		description TEXT    NOT NULL,
		applied_at  INTEGER NOT NULL
	)`
	if s.dialect == DialectPostgres {
		ddl = `CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INTEGER PRIMARY KEY,
			description TEXT    NOT NULL,
			applied_at  BIGINT  NOT NULL
		)`
	}
	_, err := s.db.ExecContext(ctx, ddl)
	return err
}

// schemaVersion returns the current schema version, or 0 if no
// migrations have been applied. Exported for diagnostics.
func (s *SQLStore) SchemaVersion() int {
	var v int
	err := s.db.QueryRowContext(context.Background(),
		"SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&v)
	if err != nil {
		return 0
	}
	return v
}

// appliedMigrations returns all recorded migrations ordered by version.
// Used by tests and the admin info endpoint.
func (s *SQLStore) appliedMigrations(ctx context.Context) ([]struct {
	Version     int
	Description string
	AppliedAt   int64
}, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT version, description, applied_at FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []struct {
		Version     int
		Description string
		AppliedAt   int64
	}
	for rows.Next() {
		var m struct {
			Version     int
			Description string
			AppliedAt   int64
		}
		if err := rows.Scan(&m.Version, &m.Description, &m.AppliedAt); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

func init() {
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version <= migrations[i-1].Version {
			panic(fmt.Sprintf("migrations: version %d is not greater than %d",
				migrations[i].Version, migrations[i-1].Version))
		}
	}
}
