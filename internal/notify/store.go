package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ConfigStore abstracts persistence of notification channels and routes.
// Both the file-based and Redis-backed implementations satisfy this interface.
type ConfigStore interface {
	Load() (*NotificationConfig, error)
	Save(cfg *NotificationConfig) error
}

// ── File-based implementation ────────────────────────────────────────────────

// FileConfigStore wraps the existing Load/Save functions as a ConfigStore.
type FileConfigStore struct {
	Path string
}

func (s *FileConfigStore) Load() (*NotificationConfig, error) {
	return LoadNotificationConfig(s.Path)
}

func (s *FileConfigStore) Save(cfg *NotificationConfig) error {
	return SaveNotificationConfig(s.Path, cfg)
}

// ── Redis-backed implementation ──────────────────────────────────────────────

// RedisConfigStore implements ConfigStore backed by a Redis key.
type RedisConfigStore struct {
	client redis.UniversalClient
	key    string // e.g. "identree:notify:config"
}

// NewRedisConfigStore returns a Redis-backed notification config store.
func NewRedisConfigStore(client redis.UniversalClient, prefix string) *RedisConfigStore {
	return &RedisConfigStore{
		client: client,
		key:    prefix + "notify:config",
	}
}

func (s *RedisConfigStore) Load() (*NotificationConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := s.client.Get(ctx, s.key).Bytes()
	if err == redis.Nil {
		return &NotificationConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("notify: redis GET %s: %w", s.key, err)
	}

	cfg := &NotificationConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("notify: redis parse %s: %w", s.key, err)
	}
	return cfg, nil
}

func (s *RedisConfigStore) Save(cfg *NotificationConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("notify: marshal config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.client.Set(ctx, s.key, data, 0).Err(); err != nil {
		return fmt.Errorf("notify: redis SET %s: %w", s.key, err)
	}
	return nil
}
