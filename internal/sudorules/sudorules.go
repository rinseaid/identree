package sudorules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SudoRule defines sudo permissions for a named group.
// In bridge mode the LDAP server emits a sudoRole entry for each rule using
// %groupname syntax so membership resolves via the upstream LDAP directory.
type SudoRule struct {
	Group      string `json:"group"`                // POSIX group name; used as sudoRole CN
	Hosts      string `json:"hosts,omitempty"`      // comma-separated hosts (default: ALL)
	Commands   string `json:"commands"`             // comma-separated commands; required
	RunAsUser  string `json:"runAsUser,omitempty"`  // run-as user (default: root)
	RunAsGroup string `json:"runAsGroup,omitempty"` // run-as group (optional)
	Options    string `json:"options,omitempty"`    // comma-separated sudo options
}

// maxRules is the maximum number of sudo rules the store will hold.
// Prevents unbounded memory growth and linear LDAP search performance degradation.
const maxRules = 1000

// Store persists sudo rules to a JSON file using atomic writes.
// Safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	path  string
	rules []SudoRule
}

// NewStore loads (or creates) a store at path.
// If the file does not exist an empty store is returned without error.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, rules: []SudoRule{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sudorules: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.rules); err != nil {
		return nil, fmt.Errorf("sudorules: parse %s: %w", path, err)
	}
	if s.rules == nil {
		s.rules = []SudoRule{}
	}
	return s, nil
}

// Rules returns a copy of the current rule list.
func (s *Store) Rules() []SudoRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SudoRule, len(s.rules))
	copy(out, s.rules)
	return out
}

// Set replaces all rules atomically and persists to disk.
// Returns an error if the new set exceeds the maximum rule count.
func (s *Store) Set(rules []SudoRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(rules) > maxRules {
		return fmt.Errorf("sudorules: cannot set %d rules: maximum is %d", len(rules), maxRules)
	}
	cp := make([]SudoRule, len(rules))
	copy(cp, rules)
	s.rules = cp
	return s.flush()
}

// Add appends a new rule. Returns an error if a rule for that group already exists
// or if the maximum rule count would be exceeded.
func (s *Store) Add(rule SudoRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rules) >= maxRules {
		return fmt.Errorf("sudorules: maximum rule count (%d) reached; remove a rule before adding another", maxRules)
	}
	for _, r := range s.rules {
		if r.Group == rule.Group {
			return fmt.Errorf("sudorules: rule for group %q already exists", rule.Group)
		}
	}
	s.rules = append(s.rules, rule)
	return s.flush()
}

// Remove deletes the rule for the named group.
// Returns an error if no such rule exists.
func (s *Store) Remove(group string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.rules {
		if r.Group == group {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			return s.flush()
		}
	}
	return fmt.Errorf("sudorules: no rule for group %q", group)
}

// Update replaces the rule for rule.Group in place.
// Returns an error if no such rule exists.
func (s *Store) Update(rule SudoRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.rules {
		if r.Group == rule.Group {
			s.rules[i] = rule
			return s.flush()
		}
	}
	return fmt.Errorf("sudorules: no rule for group %q", rule.Group)
}

// flush marshals and atomically writes s.rules to s.path.
// Caller must hold s.mu.
func (s *Store) flush() error {
	data, err := json.MarshalIndent(s.rules, "", "  ")
	if err != nil {
		return fmt.Errorf("sudorules: marshal: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("sudorules: mkdir %s: %w", dir, err)
		}
	}
	// Use CreateTemp so concurrent processes writing to the same directory
	// each get a unique temp filename, preventing last-writer-wins corruption.
	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, ".sudorules-tmp-*")
	if err != nil {
		return fmt.Errorf("sudorules: create temp: %w", err)
	}
	tmp := f.Name()
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("sudorules: chmod %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("sudorules: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("sudorules: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("sudorules: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("sudorules: rename to %s: %w", s.path, err)
	}
	// Sync the parent directory so the rename is durable on power loss.
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
