package uidmap

import (
	"os"
	"path/filepath"
	"testing"
)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "uidmap.json")
}

func TestNewUIDMap_Fresh(t *testing.T) {
	path := tmpPath(t)
	m, err := NewUIDMap(path, 100000, 100000)
	if err != nil {
		t.Fatalf("NewUIDMap: %v", err)
	}

	// First UID/GID should be the base value.
	uid := m.UID("user-aaa")
	if uid != 100000 {
		t.Errorf("first UID = %d, want 100000", uid)
	}
	gid := m.GID("group-aaa")
	if gid != 100000 {
		t.Errorf("first GID = %d, want 100000", gid)
	}
}

func TestNewUIDMap_DefaultBase(t *testing.T) {
	path := tmpPath(t)
	// Invalid firstUID/firstGID should fall back to defaults.
	m, err := NewUIDMap(path, -1, 0)
	if err != nil {
		t.Fatalf("NewUIDMap: %v", err)
	}
	uid := m.UID("user-bbb")
	if uid != 200000 {
		t.Errorf("UID = %d, want 200000 (default)", uid)
	}
}

func TestUIDMap_SameKeyStableID(t *testing.T) {
	path := tmpPath(t)
	m, err := NewUIDMap(path, 100000, 100000)
	if err != nil {
		t.Fatalf("NewUIDMap: %v", err)
	}

	uid1 := m.UID("user-x")
	uid2 := m.UID("user-x")
	if uid1 != uid2 {
		t.Errorf("same key returned different UIDs: %d vs %d", uid1, uid2)
	}

	gid1 := m.GID("group-x")
	gid2 := m.GID("group-x")
	if gid1 != gid2 {
		t.Errorf("same key returned different GIDs: %d vs %d", gid1, gid2)
	}
}

func TestUIDMap_DifferentKeysDifferentIDs(t *testing.T) {
	path := tmpPath(t)
	m, err := NewUIDMap(path, 100000, 100000)
	if err != nil {
		t.Fatalf("NewUIDMap: %v", err)
	}

	uid1 := m.UID("user-a")
	uid2 := m.UID("user-b")
	if uid1 == uid2 {
		t.Errorf("different keys returned same UID: %d", uid1)
	}
}

func TestUIDMap_MonotonicallyIncreasing(t *testing.T) {
	path := tmpPath(t)
	m, err := NewUIDMap(path, 100000, 100000)
	if err != nil {
		t.Fatalf("NewUIDMap: %v", err)
	}

	var uids []int
	for i := 0; i < 10; i++ {
		uids = append(uids, m.UID("user-"+string(rune('A'+i))))
	}
	for i := 1; i < len(uids); i++ {
		if uids[i] <= uids[i-1] {
			t.Errorf("UIDs not strictly increasing: uids[%d]=%d <= uids[%d]=%d",
				i, uids[i], i-1, uids[i-1])
		}
	}
}

func TestUIDMap_Persistence(t *testing.T) {
	path := tmpPath(t)

	// Create map and assign some IDs.
	m1, err := NewUIDMap(path, 100000, 100000)
	if err != nil {
		t.Fatalf("NewUIDMap (first): %v", err)
	}
	uidA := m1.UID("user-persist-a")
	uidB := m1.UID("user-persist-b")
	gidX := m1.GID("group-persist-x")

	if err := m1.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// The file written by Flush is mode 0600. On macOS running as non-root,
	// the file will be owned by the current user, not root. NewUIDMap logs a
	// warning for non-root ownership but does not fail — it only hard-fails
	// on group/world-writable permissions. Verify the file exists and is
	// readable before reloading.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after Flush: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("flushed file is empty")
	}

	// Reload from the same file.
	m2, err := NewUIDMap(path, 100000, 100000)
	if err != nil {
		t.Fatalf("NewUIDMap (reload): %v", err)
	}

	if got := m2.UID("user-persist-a"); got != uidA {
		t.Errorf("reloaded UID for user-persist-a = %d, want %d", got, uidA)
	}
	if got := m2.UID("user-persist-b"); got != uidB {
		t.Errorf("reloaded UID for user-persist-b = %d, want %d", got, uidB)
	}
	if got := m2.GID("group-persist-x"); got != gidX {
		t.Errorf("reloaded GID for group-persist-x = %d, want %d", got, gidX)
	}

	// New assignments after reload should not collide.
	uidC := m2.UID("user-persist-c")
	if uidC <= uidB {
		t.Errorf("new UID after reload (%d) should be > previous max (%d)", uidC, uidB)
	}
}

func TestUIDMap_FlushNoOpWhenClean(t *testing.T) {
	path := tmpPath(t)
	m, err := NewUIDMap(path, 100000, 100000)
	if err != nil {
		t.Fatalf("NewUIDMap: %v", err)
	}

	// Flush on a fresh map with no assignments should not create a file.
	if err := m.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected file to not exist after no-op Flush, got err=%v", err)
	}
}
