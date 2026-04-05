package adminnotify

import (
	"path/filepath"
	"testing"
)

func TestStoreNewEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if len(s.All()) != 0 {
		t.Errorf("expected empty store, got %d prefs", len(s.All()))
	}
}

func TestStoreCRUD(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Set
	pref := Preference{
		Username: "alice",
		Channels: []string{"ops-slack"},
		Events:   []string{"*"},
		Enabled:  true,
	}
	if err := s.Set(pref); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Get
	got := s.Get("alice")
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Username != "alice" || len(got.Channels) != 1 || !got.Enabled {
		t.Errorf("unexpected pref: %+v", got)
	}

	// Update
	pref.Events = []string{"challenge_created"}
	if err := s.Set(pref); err != nil {
		t.Fatalf("Set update: %v", err)
	}
	got = s.Get("alice")
	if len(got.Events) != 1 || got.Events[0] != "challenge_created" {
		t.Errorf("update not reflected: %+v", got)
	}

	// All
	if len(s.All()) != 1 {
		t.Errorf("expected 1 pref, got %d", len(s.All()))
	}

	// Delete
	if err := s.Delete("alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if s.Get("alice") != nil {
		t.Error("pref still exists after delete")
	}
	if len(s.All()) != 0 {
		t.Errorf("expected 0 prefs after delete, got %d", len(s.All()))
	}
}

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)
	s.Set(Preference{Username: "bob", Channels: []string{"ch1"}, Events: []string{"*"}, Enabled: true})

	// Reload from disk.
	s2, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore reload: %v", err)
	}
	got := s2.Get("bob")
	if got == nil {
		t.Fatal("persisted pref not found on reload")
	}
	if got.Username != "bob" || len(got.Channels) != 1 {
		t.Errorf("unexpected pref after reload: %+v", got)
	}
}

func TestStoreMatchingChannels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)
	s.Set(Preference{
		Username: "alice",
		Channels: []string{"ops-slack", "oncall-ntfy"},
		Events:   []string{"*"},
		Enabled:  true,
	})
	s.Set(Preference{
		Username: "bob",
		Channels: []string{"dev-slack"},
		Events:   []string{"challenge_created"},
		Hosts:    []string{"prod-*"},
		Enabled:  true,
	})
	s.Set(Preference{
		Username: "carol",
		Channels: []string{"disabled-ch"},
		Events:   []string{"*"},
		Enabled:  false, // disabled
	})

	// Alice's wildcard matches everything.
	got := s.MatchingChannels("challenge_created", "dev-app-01", "dave")
	if !got["ops-slack"] || !got["oncall-ntfy"] {
		t.Errorf("alice's wildcard should match: %v", got)
	}
	// Bob only matches prod-* hosts with challenge_created.
	if got["dev-slack"] {
		t.Errorf("bob should not match dev-app-01: %v", got)
	}
	// Carol is disabled.
	if got["disabled-ch"] {
		t.Errorf("carol is disabled, should not match: %v", got)
	}

	// Bob matches prod hosts.
	got2 := s.MatchingChannels("challenge_created", "prod-web-01", "dave")
	if !got2["dev-slack"] {
		t.Errorf("bob should match prod-web-01: %v", got2)
	}

	// Bob doesn't match non-challenge events.
	got3 := s.MatchingChannels("config_changed", "prod-web-01", "dave")
	if got3["dev-slack"] {
		t.Errorf("bob should not match config_changed: %v", got3)
	}
}

func TestStoreDeleteNonexistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)
	// Should not error.
	if err := s.Delete("nonexistent"); err != nil {
		t.Fatalf("Delete nonexistent: %v", err)
	}
}
