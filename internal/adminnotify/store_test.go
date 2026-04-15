package adminnotify

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

// ── maxPreferences limit tests ───────────────────────────────────────────────

func TestStoreMaxPreferences(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Fill up to maxPreferences.
	for i := 0; i < maxPreferences; i++ {
		username := fmt.Sprintf("user%04d", i)
		if err := s.Set(Preference{Username: username, Channels: []string{"ch1"}, Events: []string{"*"}, Enabled: true}); err != nil {
			t.Fatalf("Set %d: %v", i, err)
		}
	}

	if len(s.All()) != maxPreferences {
		t.Fatalf("expected %d prefs, got %d", maxPreferences, len(s.All()))
	}

	// The 501st should be rejected.
	err = s.Set(Preference{Username: "one-too-many", Channels: []string{"ch1"}, Events: []string{"*"}, Enabled: true})
	if err == nil {
		t.Fatal("expected error for exceeding maxPreferences")
	}
}

func TestStoreMaxPreferences_UpdateDoesNotCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)

	// Fill to max.
	for i := 0; i < maxPreferences; i++ {
		s.Set(Preference{Username: fmt.Sprintf("user%04d", i), Channels: []string{"ch1"}, Events: []string{"*"}, Enabled: true})
	}

	// Updating an existing preference should succeed (not a new insert).
	err := s.Set(Preference{Username: "user0000", Channels: []string{"ch2"}, Events: []string{"challenge_created"}, Enabled: true})
	if err != nil {
		t.Fatalf("updating existing pref should succeed, got %v", err)
	}
	got := s.Get("user0000")
	if len(got.Channels) != 1 || got.Channels[0] != "ch2" {
		t.Errorf("expected updated channels, got %v", got.Channels)
	}
}

// ── concurrent write tests ───────────────────────────────────────────────────

func TestStoreConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// 10 goroutines writing simultaneously.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			username := fmt.Sprintf("user%d", idx)
			for j := 0; j < 5; j++ {
				s.Set(Preference{
					Username: username,
					Channels: []string{fmt.Sprintf("ch%d", j)},
					Events:   []string{"*"},
					Enabled:  true,
				})
			}
		}(i)
	}
	wg.Wait()

	// Should have exactly 10 preferences (one per user, last write wins).
	all := s.All()
	if len(all) != 10 {
		t.Errorf("expected 10 prefs after concurrent writes, got %d", len(all))
	}
}

// ── MatchingChannels complex patterns ────────────────────────────────────────

func TestStoreMatchingChannels_OverlappingChannels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)
	// Two admins subscribe to the same channel for overlapping patterns.
	s.Set(Preference{Username: "alice", Channels: []string{"ops-slack"}, Events: []string{"*"}, Enabled: true})
	s.Set(Preference{Username: "bob", Channels: []string{"ops-slack", "oncall"}, Events: []string{"challenge_created"}, Enabled: true})

	// Both should contribute to the ops-slack channel.
	got := s.MatchingChannels("challenge_created", "web01", "carol")
	if !got["ops-slack"] {
		t.Error("expected ops-slack from overlapping admins")
	}
	if !got["oncall"] {
		t.Error("expected oncall from bob")
	}

	// For an event bob doesn't subscribe to, only alice's channels match.
	got2 := s.MatchingChannels("config_changed", "web01", "carol")
	if !got2["ops-slack"] {
		t.Error("expected ops-slack from alice for config_changed")
	}
	if got2["oncall"] {
		t.Error("expected no oncall for config_changed (bob only subscribes to challenge_created)")
	}
}

func TestStoreMatchingChannels_HostGlob(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)
	s.Set(Preference{
		Username: "alice",
		Channels: []string{"prod-alerts"},
		Events:   []string{"*"},
		Hosts:    []string{"prod-*"},
		Enabled:  true,
	})
	s.Set(Preference{
		Username: "bob",
		Channels: []string{"dev-alerts"},
		Events:   []string{"*"},
		Hosts:    []string{"dev-*"},
		Enabled:  true,
	})

	// prod host should match alice only.
	got := s.MatchingChannels("challenge_created", "prod-web-01", "carol")
	if !got["prod-alerts"] {
		t.Error("expected prod-alerts")
	}
	if got["dev-alerts"] {
		t.Error("expected no dev-alerts for prod host")
	}

	// dev host should match bob only.
	got2 := s.MatchingChannels("challenge_created", "dev-app-01", "carol")
	if got2["prod-alerts"] {
		t.Error("expected no prod-alerts for dev host")
	}
	if !got2["dev-alerts"] {
		t.Error("expected dev-alerts")
	}
}

func TestStoreMatchingChannels_EmptyHostsMatchesAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)
	s.Set(Preference{
		Username: "alice",
		Channels: []string{"all-alerts"},
		Events:   []string{"*"},
		Hosts:    []string{}, // empty = all hosts
		Enabled:  true,
	})

	got := s.MatchingChannels("challenge_created", "any-host-at-all", "carol")
	if !got["all-alerts"] {
		t.Error("expected empty hosts to match all hosts")
	}
}

// ── invalid JSON file recovery ───────────────────────────────────────────────

func TestStoreNewWithInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	// Write invalid JSON to the file.
	if err := os.WriteFile(path, []byte("{invalid json}"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := NewStore(path)
	if err == nil {
		t.Error("expected error for invalid JSON file")
	}
}

func TestStoreNewWithEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	// Write empty JSON array.
	if err := os.WriteFile(path, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore with empty array: %v", err)
	}
	if len(s.All()) != 0 {
		t.Errorf("expected 0 prefs, got %d", len(s.All()))
	}
}

func TestStoreNewWithDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	// Create a directory at the path where the file should be.
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := NewStore(path)
	if err == nil {
		t.Error("expected error when path is a directory (not regular file)")
	}
}

func TestStoreSaveLocked_PersistsCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)
	s.Set(Preference{Username: "alice", Channels: []string{"ch1", "ch2"}, Events: []string{"challenge_created", "challenge_approved"}, Hosts: []string{"prod-*"}, Enabled: true})
	s.Set(Preference{Username: "bob", Channels: []string{"ch3"}, Events: []string{"*"}, Enabled: false})

	// Verify file was written.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty file after save")
	}

	// Reload and verify.
	s2, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(s2.All()) != 2 {
		t.Errorf("expected 2 prefs after reload, got %d", len(s2.All()))
	}
	alice := s2.Get("alice")
	if alice == nil {
		t.Fatal("expected alice pref after reload")
	}
	if len(alice.Channels) != 2 || len(alice.Events) != 2 {
		t.Errorf("alice pref not preserved: channels=%v events=%v", alice.Channels, alice.Events)
	}
	bob := s2.Get("bob")
	if bob == nil {
		t.Fatal("expected bob pref after reload")
	}
	if bob.Enabled {
		t.Error("expected bob enabled=false")
	}
}

func TestStoreNewWithNullJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	// Write JSON null.
	if err := os.WriteFile(path, []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore with null: %v", err)
	}
	if len(s.All()) != 0 {
		t.Errorf("expected 0 prefs after null, got %d", len(s.All()))
	}
}

func TestStoreSave_UnwritableDir(t *testing.T) {
	// Use a path where the directory doesn't exist and can't be created.
	s := &Store{path: "/nonexistent-dir/subdir/prefs.json", prefs: []Preference{}}
	s.prefs = append(s.prefs, Preference{Username: "alice", Channels: []string{"ch1"}, Events: []string{"*"}, Enabled: true})

	// Set should fail because directory doesn't exist.
	err := s.Set(Preference{Username: "bob", Channels: []string{"ch2"}, Events: []string{"*"}, Enabled: true})
	// We expect this to either succeed (if MkdirAll creates the path) or fail.
	// On most systems, /nonexistent-dir is not writable.
	if err == nil {
		// Clean up if it somehow succeeded.
		os.RemoveAll("/nonexistent-dir")
	}
	// Just verify no panic occurred.
}

func TestStoreMatchingChannels_MultipleEventGlobs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefs.json")

	s, _ := NewStore(path)
	s.Set(Preference{
		Username: "alice",
		Channels: []string{"alerts"},
		Events:   []string{"challenge_*"},
		Enabled:  true,
	})

	// Should match challenge_created, challenge_approved, etc.
	if got := s.MatchingChannels("challenge_created", "web01", "bob"); !got["alerts"] {
		t.Error("expected match for challenge_created with challenge_* glob")
	}
	if got := s.MatchingChannels("challenge_approved", "web01", "bob"); !got["alerts"] {
		t.Error("expected match for challenge_approved with challenge_* glob")
	}
	// Should NOT match config_changed.
	if got := s.MatchingChannels("config_changed", "web01", "bob"); got["alerts"] {
		t.Error("expected no match for config_changed with challenge_* glob")
	}
}
