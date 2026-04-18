package notify

// ConfigStore abstracts persistence of notification channels and routes.
type ConfigStore interface {
	Load() (*NotificationConfig, error)
	Save(cfg *NotificationConfig) error
}

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
