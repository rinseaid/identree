package notify

import (
	"path/filepath"
	"testing"
)

// Compile-time interface compliance checks.
var (
	_ ConfigStore = (*FileConfigStore)(nil)
	_ ConfigStore = (*RedisConfigStore)(nil)
)

func TestFileConfigStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notify.json")
	store := &FileConfigStore{Path: path}

	// Load nonexistent returns empty.
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load nonexistent: %v", err)
	}
	if len(cfg.Channels) != 0 || len(cfg.Routes) != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}

	// Save and reload.
	cfg.Channels = []Channel{
		{Name: "test-ch", Backend: "webhook", URL: "https://example.com"},
	}
	cfg.Routes = []Route{
		{Channels: []string{"test-ch"}, Events: []string{"*"}},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg2, err := store.Load()
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	if len(cfg2.Channels) != 1 || cfg2.Channels[0].Name != "test-ch" {
		t.Errorf("channels mismatch: %+v", cfg2.Channels)
	}
	if len(cfg2.Routes) != 1 {
		t.Errorf("routes mismatch: %+v", cfg2.Routes)
	}
}
