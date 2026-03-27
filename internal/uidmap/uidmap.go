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
)

// NewUIDMap loads (or creates) a UID map from the given path.
func NewUIDMap(path string) (*UIDMap, error) {
	m := &UIDMap{
		path: path,
		data: uidMapData{
			UIDs:    make(map[string]int),
			GIDs:    make(map[string]int),
			NextUID: defaultFirstUID,
			NextGID: defaultFirstGID,
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
	return m, nil
}

// UID returns the posix UID for the given PocketID user UUID,
// assigning a new one if this is the first time we've seen this user.
func (m *UIDMap) UID(uuid string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if uid, ok := m.data.UIDs[uuid]; ok {
		return uid
	}
	uid := m.data.NextUID
	m.data.NextUID++
	m.data.UIDs[uuid] = uid
	m.dirty = true
	return uid
}

// GID returns the posix GID for the given PocketID group UUID,
// assigning a new one if this is the first time we've seen this group.
func (m *UIDMap) GID(uuid string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if gid, ok := m.data.GIDs[uuid]; ok {
		return gid
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
	// Write to a temp file and rename for atomicity
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("uidmap: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
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
		if _, exists := m.data.UIDs[uuid]; !exists {
			m.data.UIDs[uuid] = uid
			m.dirty = true
		}
	}
	for uuid, gid := range legacy.GIDs {
		if _, exists := m.data.GIDs[uuid]; !exists {
			m.data.GIDs[uuid] = gid
			m.dirty = true
		}
	}
	if legacy.NextUID > m.data.NextUID {
		m.data.NextUID = legacy.NextUID
		m.dirty = true
	}
	if legacy.NextGID > m.data.NextGID {
		m.data.NextGID = legacy.NextGID
		m.dirty = true
	}
	return nil
}
