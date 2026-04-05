package adminnotify

// Compile-time interface compliance checks.
var (
	_ PrefStore = (*Store)(nil)
	_ PrefStore = (*RedisStore)(nil)
)
