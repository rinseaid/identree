package uidmap

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// UIDMap provides stable UID/GID assignments for PocketID users and groups.
// Assignments are persisted to a JSON file so they survive restarts.
// Once assigned, a UID or GID is never reused even if the user/group is deleted.
type UIDMap struct {
	mu      sync.Mutex
	path    string
	data    uidMapData
	dirty   bool
}

type uidMapData struct {
	// UIDs maps PocketID user UUID → posix UID
	UIDs    map[string]int `json:"uids"`
	// GIDs maps PocketID group UUID → posix GID
	GIDs    map[string]int `json:"gids"`
	// NextUID is the next UID to assign (monotonically increasing)
	NextUID int            `json:"nextUID"`
	// NextGID is the next GID to assign (monotonically increasing)
	NextGID int            `json:"nextGID"`
}

const (
	defaultFirstUID = 200000
	defaultFirstGID = 200000
	// maxUID/maxGID is the maximum valid POSIX UID/GID (2^32 - 2; -1 is reserved as "nobody"/"nogroup").
	maxUID = 4294967294
	maxGID = 4294967294
)

// NewUIDMap loads (or creates) a UID map from the given path.
func NewUIDMap(path string, firstUID, firstGID int) (*UIDMap, error) {
	if firstUID <= 0 || firstUID > maxUID {
		firstUID = defaultFirstUID
	}
	if firstGID <= 0 || firstGID > maxGID {
		firstGID = defaultFirstGID
	}
	m := &UIDMap{
		path: path,
		data: uidMapData{
			UIDs:    make(map[string]int),
			GIDs:    make(map[string]int),
			NextUID: firstUID,
			NextGID: firstGID,
		},
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("uidmap: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &m.data); err != nil {
		return nil, fmt.Errorf("uidmap: parse %s: %w", path, err)
	}
	// Ensure maps are non-nil after unmarshal
	if m.data.UIDs == nil {
		m.data.UIDs = make(map[string]int)
	}
	if m.data.GIDs == nil {
		m.data.GIDs = make(map[string]int)
	}
	// Clamp counters loaded from disk to the valid range.
	if m.data.NextUID <= 0 || m.data.NextUID > maxUID {
		m.data.NextUID = firstUID
	}
	if m.data.NextGID <= 0 || m.data.NextGID > maxGID {
		m.data.NextGID = firstGID
	}
	// Validate and clamp existing map entries. A corrupted or hand-edited file
	// could contain UID/GID <= 0 (including -1 which maps to nobody/root on
	// POSIX clients) or values above maxUID. Remove invalid entries so they
	// get re-assigned from the counter on the next Refresh.
	for uuid, uid := range m.data.UIDs {
		if uid <= 0 || uid > maxUID {
			delete(m.data.UIDs, uuid)
		}
	}
	for uuid, gid := range m.data.GIDs {
		if gid <= 0 || gid > maxGID {
			delete(m.data.GIDs, uuid)
		}
	}
	// Ensure NextUID/NextGID is strictly above all already-assigned values.
	// Guards against corruption where the counter was reset below existing
	// entries, which would cause the next new assignment to collide.
	for _, uid := range m.data.UIDs {
		if uid >= m.data.NextUID {
			m.data.NextUID = uid + 1
		}
	}
	for _, gid := range m.data.GIDs {
		if gid >= m.data.NextGID {
			m.data.NextGID = gid + 1
		}
	}
	return m, nil
}

// UID returns the posix UID for the given PocketID user UUID,
// assigning a new one if this is the first time we've seen this user.
// Returns -1 and logs an error if the UID space is exhausted.
func (m *UIDMap) UID(uuid string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if uid, ok := m.data.UIDs[uuid]; ok {
		return uid
	}
	if m.data.NextUID > maxUID {
		return -1
	}
	uid := m.data.NextUID
	m.data.NextUID++
	m.data.UIDs[uuid] = uid
	m.dirty = true
	return uid
}

// GID returns the posix GID for the given PocketID group UUID,
// assigning a new one if this is the first time we've seen this group.
// Returns -1 and logs an error if the GID space is exhausted.
func (m *UIDMap) GID(uuid string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if gid, ok := m.data.GIDs[uuid]; ok {
		return gid
	}
	if m.data.NextGID > maxGID {
		return -1
	}
	gid := m.data.NextGID
	m.data.NextGID++
	m.data.GIDs[uuid] = gid
	m.dirty = true
	return gid
}

// Flush writes any pending changes to disk. It is a no-op if nothing changed.
func (m *UIDMap) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dirty {
		return nil
	}
	return m.flushLocked()
}

// FlushForce writes the map to disk unconditionally.
func (m *UIDMap) FlushForce() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushLocked()
}

func (m *UIDMap) flushLocked() error {
	data, err := json.MarshalIndent(m.data, "", "  ")
	if err != nil {
		return fmt.Errorf("uidmap: marshal: %w", err)
	}
	// Write to a temp file, sync, and rename for atomicity + durability.
	tmp := m.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("uidmap: open %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("uidmap: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("uidmap: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("uidmap: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("uidmap: rename to %s: %w", m.path, err)
	}
	m.dirty = false
	return nil
}

// ImportLegacy imports existing UID/GID assignments from a legacy uidmap.json
// (the format used by glauth-pocketid). It only sets values not already present.
// The legacy format uses the same JSON schema, so a direct merge is safe.
func (m *UIDMap) ImportLegacy(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("uidmap: import legacy %s: %w", path, err)
	}
	var legacy uidMapData
	if err := json.Unmarshal(data, &legacy); err != nil {
		return fmt.Errorf("uidmap: import legacy parse: %w", err)
	}

	for uuid, uid := range legacy.UIDs {
		if uid < 1 || uid > maxUID {
			continue // skip out-of-range values from legacy file
		}
		if _, exists := m.data.UIDs[uuid]; !exists {
			m.data.UIDs[uuid] = uid
			m.dirty = true
		}
	}
	for uuid, gid := range legacy.GIDs {
		if gid < 1 || gid > maxGID {
			continue // skip out-of-range values from legacy file
		}
		if _, exists := m.data.GIDs[uuid]; !exists {
			m.data.GIDs[uuid] = gid
			m.dirty = true
		}
	}
	if legacy.NextUID > m.data.NextUID && legacy.NextUID <= maxUID {
		m.data.NextUID = legacy.NextUID
		m.dirty = true
	}
	if legacy.NextGID > m.data.NextGID && legacy.NextGID <= maxGID {
		m.data.NextGID = legacy.NextGID
		m.dirty = true
	}
	return nil
}
