// Package adminnotify manages per-admin notification preferences.
package adminnotify

// PrefStore abstracts persistence of admin notification preferences.
// Both the file-based Store and Redis-backed RedisStore satisfy this interface.
type PrefStore interface {
	All() []Preference
	Get(username string) *Preference
	Set(pref Preference) error
	Delete(username string) error
	MatchingChannels(event, hostname, username string) map[string]bool
}
