package challenge

import (
	"context"
	"testing"
	"time"
)

func TestMigrate_FreshDatabase(t *testing.T) {
	s := newTestSQLStore(t)
	v := s.SchemaVersion(context.Background())
	if v != 1 {
		t.Fatalf("SchemaVersion: got %d, want 1", v)
	}
	migs, err := s.appliedMigrations(context.Background())
	if err != nil {
		t.Fatalf("appliedMigrations: %v", err)
	}
	if len(migs) != 1 {
		t.Fatalf("applied migrations: got %d, want 1", len(migs))
	}
	if migs[0].Version != 1 || migs[0].Description != "baseline schema" {
		t.Errorf("migration 1: got version=%d desc=%q", migs[0].Version, migs[0].Description)
	}
	if migs[0].AppliedAt == 0 {
		t.Error("migration 1: applied_at is zero")
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	s := newTestSQLStore(t)
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	v := s.SchemaVersion(context.Background())
	if v != 1 {
		t.Fatalf("SchemaVersion after second migrate: got %d, want 1", v)
	}
	migs, err := s.appliedMigrations(context.Background())
	if err != nil {
		t.Fatalf("appliedMigrations: %v", err)
	}
	if len(migs) != 1 {
		t.Fatalf("applied migrations after second migrate: got %d, want 1", len(migs))
	}
}

func TestMigrate_PreExistingSchema(t *testing.T) {
	driver, dsn := backendForTest(t)
	db, dialect, err := Open(SQLConfig{Driver: driver, DSN: dsn})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Simulate a pre-migration deployment: apply the raw schema directly.
	schema := sqliteSchema
	if dialect == DialectPostgres {
		schema = postgresSchema
	}
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		t.Fatalf("apply raw schema: %v", err)
	}

	// Now create the store, which runs migrate(). Migration 1 should
	// succeed because all its statements use IF NOT EXISTS.
	store, err := NewSQLStore(db, dialect, 5*time.Minute, 30*time.Minute)
	if err != nil {
		t.Fatalf("NewSQLStore on pre-existing schema: %v", err)
	}
	t.Cleanup(store.Stop)

	if v := store.SchemaVersion(context.Background()); v != 1 {
		t.Fatalf("SchemaVersion: got %d, want 1", v)
	}
}

func TestMigrate_SkipsApplied(t *testing.T) {
	driver, dsn := backendForTest(t)
	db, dialect, err := Open(SQLConfig{Driver: driver, DSN: dsn})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := &SQLStore{db: db, dialect: dialect, stopCh: make(chan struct{})}
	if err := s.ensureMigrationsTable(context.Background()); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}

	// Pre-insert version 1 as already applied.
	if _, err := db.ExecContext(context.Background(),
		s.q("INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)"),
		1, "baseline schema", nowUnix()); err != nil {
		t.Fatalf("insert v1: %v", err)
	}

	// runMigrations should skip migration 1 entirely.
	if err := s.runMigrations(context.Background(), migrations); err != nil {
		t.Fatalf("runMigrations: %v", err)
	}

	migs, err := s.appliedMigrations(context.Background())
	if err != nil {
		t.Fatalf("appliedMigrations: %v", err)
	}
	if len(migs) != 1 {
		t.Fatalf("expected 1 migration row, got %d", len(migs))
	}
}

func TestMigrate_FailureRollback(t *testing.T) {
	driver, dsn := backendForTest(t)
	db, dialect, err := Open(SQLConfig{Driver: driver, DSN: dsn})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := &SQLStore{db: db, dialect: dialect, stopCh: make(chan struct{})}
	if err := s.ensureMigrationsTable(context.Background()); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}

	badMigrations := []migration{
		migrations[0], // baseline (will succeed)
		{
			Version:     2,
			Description: "intentionally broken",
			SQLite:      "CREATE TABLE this_is_bad (INVALID SYNTAX HERE",
			Postgres:    "CREATE TABLE this_is_bad (INVALID SYNTAX HERE",
		},
	}

	err = s.runMigrations(context.Background(), badMigrations)
	if err == nil {
		t.Fatal("expected error from broken migration, got nil")
	}

	// Version 1 should have been applied, but version 2 should not.
	v := s.SchemaVersion(context.Background())
	if v != 1 {
		t.Fatalf("SchemaVersion after failed migration: got %d, want 1", v)
	}
}

func TestMigrate_VersionOrdering(t *testing.T) {
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version <= migrations[i-1].Version {
			t.Errorf("migration %d (v%d) is not greater than migration %d (v%d)",
				i, migrations[i].Version, i-1, migrations[i-1].Version)
		}
	}
}
