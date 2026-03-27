package sudorules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sudorules.json")
}

func TestNewStore_NoFile(t *testing.T) {
	s, err := NewStore(tmpPath(t))
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if rules := s.Rules(); len(rules) != 0 {
		t.Errorf("expected empty rules, got %d", len(rules))
	}
}

func TestNewStore_LoadExisting(t *testing.T) {
	path := tmpPath(t)
	initial := []SudoRule{
		{Group: "sysadmins", Commands: "/usr/bin/apt", Hosts: "ALL"},
	}
	data, _ := json.Marshal(initial)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rules := s.Rules()
	if len(rules) != 1 || rules[0].Group != "sysadmins" {
		t.Errorf("unexpected rules: %+v", rules)
	}
}

func TestNewStore_InvalidJSON(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestRules_ReturnsCopy(t *testing.T) {
	s, _ := NewStore(tmpPath(t))
	_ = s.Add(SudoRule{Group: "ops", Commands: "/usr/bin/systemctl"})

	rules := s.Rules()
	rules[0].Group = "modified"

	fresh := s.Rules()
	if fresh[0].Group == "modified" {
		t.Error("Rules() returned reference instead of copy")
	}
}

func TestSet(t *testing.T) {
	path := tmpPath(t)
	s, _ := NewStore(path)

	rules := []SudoRule{
		{Group: "a", Commands: "/usr/bin/apt"},
		{Group: "b", Commands: "/usr/bin/systemctl"},
	}
	if err := s.Set(rules); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if got := s.Rules(); len(got) != 2 {
		t.Errorf("expected 2 rules, got %d", len(got))
	}

	// Replace with a different set
	if err := s.Set([]SudoRule{{Group: "c", Commands: "/usr/bin/id"}}); err != nil {
		t.Fatal(err)
	}
	got := s.Rules()
	if len(got) != 1 || got[0].Group != "c" {
		t.Errorf("unexpected rules after Set: %+v", got)
	}

	// Verify persistence
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := s2.Rules(); len(r) != 1 || r[0].Group != "c" {
		t.Errorf("persisted rules mismatch: %+v", r)
	}
}

func TestAdd(t *testing.T) {
	path := tmpPath(t)
	s, _ := NewStore(path)

	r1 := SudoRule{Group: "ops", Commands: "/usr/bin/apt", Hosts: "server1"}
	if err := s.Add(r1); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if rules := s.Rules(); len(rules) != 1 || rules[0].Group != "ops" {
		t.Errorf("unexpected rules: %+v", rules)
	}

	// Verify persistence by reloading
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := s2.Rules(); len(r) != 1 || r[0].Group != "ops" {
		t.Errorf("persisted rules mismatch: %+v", r)
	}
}

func TestAdd_DuplicateGroup(t *testing.T) {
	s, _ := NewStore(tmpPath(t))
	_ = s.Add(SudoRule{Group: "ops", Commands: "/usr/bin/apt"})
	if err := s.Add(SudoRule{Group: "ops", Commands: "/usr/bin/id"}); err == nil {
		t.Error("expected error for duplicate group")
	}
}

func TestRemove(t *testing.T) {
	path := tmpPath(t)
	s, _ := NewStore(path)
	_ = s.Add(SudoRule{Group: "a", Commands: "/usr/bin/apt"})
	_ = s.Add(SudoRule{Group: "b", Commands: "/usr/bin/id"})

	if err := s.Remove("a"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	rules := s.Rules()
	if len(rules) != 1 || rules[0].Group != "b" {
		t.Errorf("unexpected rules after Remove: %+v", rules)
	}

	// Reload and verify
	s2, _ := NewStore(path)
	if r := s2.Rules(); len(r) != 1 || r[0].Group != "b" {
		t.Errorf("persisted rules mismatch after Remove: %+v", r)
	}
}

func TestRemove_NotFound(t *testing.T) {
	s, _ := NewStore(tmpPath(t))
	if err := s.Remove("nonexistent"); err == nil {
		t.Error("expected error when removing nonexistent group")
	}
}

func TestUpdate(t *testing.T) {
	path := tmpPath(t)
	s, _ := NewStore(path)
	_ = s.Add(SudoRule{Group: "ops", Commands: "/usr/bin/apt"})

	updated := SudoRule{Group: "ops", Commands: "/usr/bin/apt,/usr/bin/systemctl", Hosts: "server1"}
	if err := s.Update(updated); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	rules := s.Rules()
	if rules[0].Commands != "/usr/bin/apt,/usr/bin/systemctl" || rules[0].Hosts != "server1" {
		t.Errorf("unexpected rule after Update: %+v", rules[0])
	}

	// Reload and verify
	s2, _ := NewStore(path)
	if r := s2.Rules(); r[0].Commands != "/usr/bin/apt,/usr/bin/systemctl" {
		t.Errorf("persisted update mismatch: %+v", r)
	}
}

func TestUpdate_NotFound(t *testing.T) {
	s, _ := NewStore(tmpPath(t))
	if err := s.Update(SudoRule{Group: "nonexistent", Commands: "/usr/bin/id"}); err == nil {
		t.Error("expected error when updating nonexistent group")
	}
}

func TestAtomicWrite(t *testing.T) {
	path := tmpPath(t)
	s, _ := NewStore(path)
	_ = s.Add(SudoRule{Group: "ops", Commands: "/usr/bin/apt"})

	// Ensure .tmp file is cleaned up (rename succeeded)
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("expected .tmp file to be gone after flush")
	}
	// Primary file must exist
	if _, err := os.Stat(path); err != nil {
		t.Errorf("primary file not created: %v", err)
	}
}

func TestNewStore_ReadError(t *testing.T) {
	path := tmpPath(t)
	// Write a file then make it unreadable
	if err := os.WriteFile(path, []byte(`[]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Skip("cannot chmod — skipping read error test")
	}
	t.Cleanup(func() { os.Chmod(path, 0600) })
	_, err := NewStore(path)
	if err == nil {
		t.Error("expected error for unreadable file")
	}
}

func TestNewStore_NullJSON(t *testing.T) {
	// A file containing JSON null should yield an empty store.
	path := tmpPath(t)
	if err := os.WriteFile(path, []byte(`null`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("unexpected error for null JSON: %v", err)
	}
	if rules := s.Rules(); len(rules) != 0 {
		t.Errorf("expected empty rules for null JSON, got %d", len(rules))
	}
}

func TestFlush_WriteError(t *testing.T) {
	// Place a regular file where the parent directory would need to be,
	// so MkdirAll fails (can't mkdir over an existing file).
	base := t.TempDir()
	blocker := filepath.Join(base, "notadir")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "sudorules.json")
	s := &Store{path: path, rules: []SudoRule{{Group: "x", Commands: "/usr/bin/id"}}}
	if err := s.flush(); err == nil {
		t.Error("expected error when parent path is a file, not a directory")
	}
}

func TestFlush_CreatesParentDir(t *testing.T) {
	// flush should create the parent directory if it doesn't exist.
	path := filepath.Join(t.TempDir(), "subdir", "rules.json")
	s := &Store{path: path, rules: []SudoRule{{Group: "ops", Commands: "/usr/bin/apt"}}}
	if err := s.flush(); err != nil {
		t.Fatalf("expected flush to succeed after creating parent dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should exist after flush: %v", err)
	}
}

func TestFlush_RenameError(t *testing.T) {
	// Make s.path a directory so os.Rename(tmp, dir) fails with EISDIR.
	dir := t.TempDir()
	path := filepath.Join(dir, "rules")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	s := &Store{path: path, rules: []SudoRule{{Group: "x", Commands: "/usr/bin/id"}}}
	err := s.flush()
	// Clean up the tmp file if it was created
	_ = os.Remove(path + ".tmp")
	if err == nil {
		t.Error("expected rename error when s.path is a directory")
	}
}

func TestConcurrentAccess(t *testing.T) {
	s, _ := NewStore(tmpPath(t))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		group := "group" // will conflict — errors are expected
		go func(g string) {
			defer wg.Done()
			_ = s.Add(SudoRule{Group: g + "x", Commands: "/usr/bin/id"})
			_ = s.Rules()
		}(group)
	}
	wg.Wait()
	// No race or panic — verified by -race flag
}

func TestSet_NilInput(t *testing.T) {
	path := tmpPath(t)
	s, _ := NewStore(path)
	_ = s.Add(SudoRule{Group: "x", Commands: "/usr/bin/id"})

	if err := s.Set(nil); err != nil {
		t.Fatalf("Set(nil) failed: %v", err)
	}
	if rules := s.Rules(); len(rules) != 0 {
		t.Errorf("expected 0 rules after Set(nil), got %d", len(rules))
	}

	// Reload
	s2, _ := NewStore(path)
	if r := s2.Rules(); len(r) != 0 {
		t.Errorf("expected 0 persisted rules, got %d", len(r))
	}
}
