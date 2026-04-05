package adminnotify

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/rinseaid/identree/internal/notify"
)

// RedisStore implements PrefStore backed by a Redis key.
// It keeps an in-memory cache that is refreshed on every mutation
// (and can be reloaded explicitly).
type RedisStore struct {
	client redis.UniversalClient
	key    string // e.g. "identree:notify:prefs"
	mu     sync.RWMutex
	prefs  []Preference
}

// NewRedisStore creates a Redis-backed admin preference store and loads
// the current preferences from Redis. Returns an empty store if the key
// does not exist.
func NewRedisStore(client redis.UniversalClient, prefix string) (*RedisStore, error) {
	s := &RedisStore{
		client: client,
		key:    prefix + "notify:prefs",
		prefs:  []Preference{},
	}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload refreshes the in-memory cache from Redis. Exported so the server
// can call it on cluster reload_notify_config messages.
func (s *RedisStore) Reload() error {
	return s.reload()
}

func (s *RedisStore) reload() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := s.client.Get(ctx, s.key).Bytes()
	if err == redis.Nil {
		s.mu.Lock()
		s.prefs = []Preference{}
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("adminnotify: redis GET %s: %w", s.key, err)
	}

	var prefs []Preference
	if err := json.Unmarshal(data, &prefs); err != nil {
		return fmt.Errorf("adminnotify: redis parse %s: %w", s.key, err)
	}
	if prefs == nil {
		prefs = []Preference{}
	}

	s.mu.Lock()
	s.prefs = prefs
	s.mu.Unlock()
	return nil
}

func (s *RedisStore) save() error {
	data, err := json.Marshal(s.prefs)
	if err != nil {
		return fmt.Errorf("adminnotify: marshal: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.client.Set(ctx, s.key, data, 0).Err(); err != nil {
		return fmt.Errorf("adminnotify: redis SET %s: %w", s.key, err)
	}
	return nil
}

// All returns a copy of all preferences.
func (s *RedisStore) All() []Preference {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Preference, len(s.prefs))
	copy(out, s.prefs)
	return out
}

// Get returns the preference for a specific admin, or nil if not found.
func (s *RedisStore) Get(username string) *Preference {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.prefs {
		if p.Username == username {
			cp := p
			return &cp
		}
	}
	return nil
}

// Set creates or updates the preference for an admin.
func (s *RedisStore) Set(pref Preference) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for i, p := range s.prefs {
		if p.Username == pref.Username {
			s.prefs[i] = pref
			found = true
			break
		}
	}
	if !found {
		if len(s.prefs) >= maxPreferences {
			return fmt.Errorf("adminnotify: maximum preferences (%d) reached", maxPreferences)
		}
		s.prefs = append(s.prefs, pref)
	}
	return s.save()
}

// Delete removes the preference for an admin.
func (s *RedisStore) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.prefs {
		if p.Username == username {
			s.prefs = append(s.prefs[:i], s.prefs[i+1:]...)
			return s.save()
		}
	}
	return nil // not found = no-op
}

// MatchingChannels returns the set of channel names that should receive a
// notification based on all enabled admin preferences.
func (s *RedisStore) MatchingChannels(event, hostname, username string) map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	channels := make(map[string]bool)
	for _, p := range s.prefs {
		if !p.Enabled {
			continue
		}
		if !notify.MatchesGlob(event, p.Events) {
			continue
		}
		if !notify.MatchesGlob(hostname, p.Hosts) {
			continue
		}
		for _, ch := range p.Channels {
			channels[ch] = true
		}
	}
	return channels
}
