package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rinseaid/identree/internal/adminnotify"
	"github.com/rinseaid/identree/internal/notify"
)

// channelNameRe validates notification channel names. Must be lowercase
// alphanumeric with hyphens, dots, or underscores (safe for env var construction).
var channelNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// notifyCfgForSave returns a deep copy of the notification config with
// secrets (Token, Command) stripped. This prevents env-injected secrets
// from leaking to the JSON config file on disk.
func (s *Server) notifyCfgForSave() *notify.NotificationConfig {
	s.notifyCfgMu.RLock()
	defer s.notifyCfgMu.RUnlock()
	channels := make([]notify.Channel, len(s.notifyCfg.Channels))
	for i, ch := range s.notifyCfg.Channels {
		channels[i] = notify.Channel{
			Name:    ch.Name,
			Backend: ch.Backend,
			URL:     ch.URL,
			Timeout: ch.Timeout,
			// Token and Command intentionally omitted — env-only secrets.
		}
	}
	routes := make([]notify.Route, len(s.notifyCfg.Routes))
	copy(routes, s.notifyCfg.Routes)
	return &notify.NotificationConfig{Channels: channels, Routes: routes}
}

// validateGlobPattern checks if a glob pattern is syntactically valid.
func validateGlobPattern(pattern string) bool {
	_, err := filepath.Match(pattern, "")
	return err == nil
}

// handleAdminNotifications renders the notification channels, routes, and
// per-admin preferences management page.
// GET /admin/notifications
func (s *Server) handleAdminNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if setLanguageCookie(w, r) {
		return
	}
	lang := detectLanguage(r)
	t := T(lang)

	username := s.getSessionUser(r)
	if username == "" {
		s.setFlashCookie(w, "expired:")
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}
	role := s.getSessionRole(r)
	s.setSessionCookie(w, username, role)
	if role != "admin" {
		http.Redirect(w, r, s.baseURL+"/", http.StatusSeeOther)
		return
	}

	var flashes []string
	if flashParam := s.getAndClearFlash(w, r); flashParam != "" {
		for _, f := range strings.Split(flashParam, ",") {
			parts := strings.SplitN(f, ":", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "channel_added":
				flashes = append(flashes, "Channel added: "+parts[1])
			case "channel_updated":
				flashes = append(flashes, "Channel updated: "+parts[1])
			case "channel_deleted":
				flashes = append(flashes, "Channel deleted: "+parts[1])
			case "route_added":
				flashes = append(flashes, "Route added")
			case "route_deleted":
				flashes = append(flashes, "Route deleted")
			case "pref_saved":
				flashes = append(flashes, "Notification preferences saved")
			case "pref_deleted":
				flashes = append(flashes, "Notification preferences removed")
			case "test_sent":
				flashes = append(flashes, "Test notification sent to: "+parts[1])
			case "test_failed":
				flashes = append(flashes, "Test notification failed: "+parts[1])
			}
		}
	}

	now := time.Now()
	csrfTs := strconv.FormatInt(now.Unix(), 10)
	csrfToken := computeCSRFToken(s.hmacBase(), username, csrfTs)

	adminTZ := "UTC"
	if c, err := r.Cookie("pam_tz"); err == nil && c.Value != "" {
		if _, tzErr := time.LoadLocation(c.Value); tzErr == nil {
			adminTZ = c.Value
		}
	}

	s.notifyCfgMu.RLock()
	channels := make([]notify.Channel, len(s.notifyCfg.Channels))
	copy(channels, s.notifyCfg.Channels)
	routes := make([]notify.Route, len(s.notifyCfg.Routes))
	copy(routes, s.notifyCfg.Routes)
	s.notifyCfgMu.RUnlock()

	// Mask tokens for display.
	for i := range channels {
		if channels[i].Token != "" {
			channels[i].Token = "****"
		}
		if channels[i].Command != "" {
			channels[i].Command = "****"
		}
	}

	var myPref *adminnotify.Preference
	if s.adminNotifyStore != nil {
		myPref = s.adminNotifyStore.Get(username)
	}

	// Channel names for the preference dropdown.
	var channelNames []string
	s.notifyCfgMu.RLock()
	for _, ch := range s.notifyCfg.Channels {
		channelNames = append(channelNames, ch.Name)
	}
	s.notifyCfgMu.RUnlock()

	w.Header().Set("Content-Type", "text/html")
	if err := adminTmpl.Execute(w, map[string]interface{}{
		"Username":              username,
		"Initial":               strings.ToUpper(username[:1]),
		"Avatar":                getAvatar(r),
		"Timezone":              adminTZ,
		"Flashes":               flashes,
		"ActivePage":            "admin",
		"AdminTab":              "notifications",
		"BridgeMode":            s.isBridgeMode(),
		"Theme":                 getTheme(r),
		"CSPNonce":              cspNonce(r),
		"T":                     t,
		"Lang":                  lang,
		"Languages":             supportedLanguages,
		"IsAdmin":               true,
		"NotifyChannels":        channels,
		"NotifyRoutes":          routes,
		"MyNotifyPref":          myPref,
		"ChannelNames":          channelNames,
		"Pending":               s.buildAllPendingViews(lang),
		"JustificationChoices":  func() []string { c, _ := s.justificationTemplateData(); return c }(),
		"RequireJustification":  func() bool { _, r := s.justificationTemplateData(); return r }(),
		"CSRFToken":             csrfToken,
		"CSRFTs":                csrfTs,
	}); err != nil {
		slog.Error("template execution", "err", err)
	}
}

// handleNotifyChannelAdd adds a new notification channel.
// POST /api/notification/channels/add
func (s *Server) handleNotifyChannelAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ch := notify.Channel{
		Name:    strings.TrimSpace(r.FormValue("name")),
		Backend: strings.TrimSpace(r.FormValue("backend")),
		URL:     strings.TrimSpace(r.FormValue("url")),
	}

	if ch.Name == "" || ch.Backend == "" {
		http.Error(w, "name and backend are required", http.StatusBadRequest)
		return
	}
	if !channelNameRe.MatchString(ch.Name) {
		http.Error(w, "channel name must be lowercase alphanumeric with hyphens/dots/underscores (1-64 chars)", http.StatusBadRequest)
		return
	}

	switch ch.Backend {
	case "ntfy", "slack", "discord", "apprise", "webhook", "custom":
	default:
		http.Error(w, "invalid backend", http.StatusBadRequest)
		return
	}

	s.notifyCfgMu.Lock()
	for _, existing := range s.notifyCfg.Channels {
		if existing.Name == ch.Name {
			s.notifyCfgMu.Unlock()
			http.Error(w, "channel already exists: "+ch.Name, http.StatusConflict)
			return
		}
	}
	s.notifyCfg.Channels = append(s.notifyCfg.Channels, ch)
	s.notifyCfgMu.Unlock()

	saveCfg := s.notifyCfgForSave()
	s.cfgMu.RLock()
	path := s.cfg.NotificationConfigFile
	s.cfgMu.RUnlock()

	if err := notify.SaveNotificationConfig(path, saveCfg); err != nil {
		slog.Error("failed to save notification config", "err", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}

	// Reload to pick up env-injected secrets.
	s.reloadNotificationConfig()

	slog.Info("NOTIFY_CHANNEL_ADDED", "admin", adminUser, "channel", ch.Name, "backend", ch.Backend)
	s.dispatchNotification(notify.WebhookData{
		Event:     "notification_channel_added",
		Actor:     adminUser,
		Hostname:  ch.Name,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	s.setFlashCookie(w, "channel_added:"+ch.Name)
	http.Redirect(w, r, s.baseURL+"/admin/notifications", http.StatusSeeOther)
}

// handleNotifyChannelDelete removes a notification channel.
// POST /api/notification/channels/delete
func (s *Server) handleNotifyChannelDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	s.notifyCfgMu.Lock()
	found := false
	for i, ch := range s.notifyCfg.Channels {
		if ch.Name == name {
			s.notifyCfg.Channels = append(s.notifyCfg.Channels[:i], s.notifyCfg.Channels[i+1:]...)
			found = true
			break
		}
	}
	s.notifyCfgMu.Unlock()

	if !found {
		http.Error(w, "channel not found", http.StatusNotFound)
		return
	}

	saveCfg := s.notifyCfgForSave()
	s.cfgMu.RLock()
	path := s.cfg.NotificationConfigFile
	s.cfgMu.RUnlock()

	if err := notify.SaveNotificationConfig(path, saveCfg); err != nil {
		slog.Error("failed to save notification config", "err", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}

	slog.Info("NOTIFY_CHANNEL_DELETED", "admin", adminUser, "channel", name)
	s.dispatchNotification(notify.WebhookData{
		Event:     "notification_channel_deleted",
		Actor:     adminUser,
		Hostname:  name,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	s.setFlashCookie(w, "channel_deleted:"+name)
	http.Redirect(w, r, s.baseURL+"/admin/notifications", http.StatusSeeOther)
}

// handleNotifyRouteAdd adds a new notification route.
// POST /api/notification/routes/add
func (s *Server) handleNotifyRouteAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	route := notify.Route{
		Channels: splitTrimmed(r.FormValue("channels")),
		Events:   splitTrimmed(r.FormValue("events")),
		Hosts:    splitTrimmed(r.FormValue("hosts")),
		Users:    splitTrimmed(r.FormValue("users")),
	}

	if len(route.Channels) == 0 || len(route.Events) == 0 {
		http.Error(w, "channels and events are required", http.StatusBadRequest)
		return
	}

	// Validate glob patterns.
	for _, patterns := range [][]string{route.Events, route.Hosts, route.Users} {
		for _, p := range patterns {
			if !validateGlobPattern(p) {
				http.Error(w, "invalid glob pattern: "+p, http.StatusBadRequest)
				return
			}
		}
	}

	s.notifyCfgMu.Lock()
	s.notifyCfg.Routes = append(s.notifyCfg.Routes, route)
	s.notifyCfgMu.Unlock()

	saveCfg := s.notifyCfgForSave()
	s.cfgMu.RLock()
	path := s.cfg.NotificationConfigFile
	s.cfgMu.RUnlock()

	if err := notify.SaveNotificationConfig(path, saveCfg); err != nil {
		slog.Error("failed to save notification config", "err", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}

	slog.Info("NOTIFY_ROUTE_ADDED", "admin", adminUser, "channels", route.Channels, "events", route.Events)
	s.dispatchNotification(notify.WebhookData{
		Event:     "notification_route_added",
		Actor:     adminUser,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	s.setFlashCookie(w, "route_added:")
	http.Redirect(w, r, s.baseURL+"/admin/notifications", http.StatusSeeOther)
}

// handleNotifyRouteDelete removes a notification route by index.
// POST /api/notification/routes/delete
func (s *Server) handleNotifyRouteDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	idx, err := strconv.Atoi(r.FormValue("index"))
	if err != nil || idx < 0 {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}

	s.notifyCfgMu.Lock()
	if idx >= len(s.notifyCfg.Routes) {
		s.notifyCfgMu.Unlock()
		http.Error(w, "index out of range", http.StatusBadRequest)
		return
	}
	s.notifyCfg.Routes = append(s.notifyCfg.Routes[:idx], s.notifyCfg.Routes[idx+1:]...)
	s.notifyCfgMu.Unlock()

	saveCfg := s.notifyCfgForSave()
	s.cfgMu.RLock()
	path := s.cfg.NotificationConfigFile
	s.cfgMu.RUnlock()

	if err := notify.SaveNotificationConfig(path, saveCfg); err != nil {
		slog.Error("failed to save notification config", "err", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}

	slog.Info("NOTIFY_ROUTE_DELETED", "admin", adminUser, "index", idx)
	s.dispatchNotification(notify.WebhookData{
		Event:     "notification_route_deleted",
		Actor:     adminUser,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	s.setFlashCookie(w, "route_deleted:")
	http.Redirect(w, r, s.baseURL+"/admin/notifications", http.StatusSeeOther)
}

// handleAdminNotifyPrefSave saves the current admin's notification preferences.
// POST /api/admin/notification-preferences
func (s *Server) handleAdminNotifyPrefSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	action := r.FormValue("action")
	if action == "delete" {
		if err := s.adminNotifyStore.Delete(adminUser); err != nil {
			slog.Error("failed to delete admin notify pref", "user", adminUser, "err", err)
		}
		s.setFlashCookie(w, "pref_deleted:")
		http.Redirect(w, r, s.baseURL+"/admin/notifications", http.StatusSeeOther)
		return
	}

	pref := adminnotify.Preference{
		Username: adminUser,
		Channels: splitTrimmed(r.FormValue("channels")),
		Events:   splitTrimmed(r.FormValue("events")),
		Hosts:    splitTrimmed(r.FormValue("hosts")),
		Enabled:  r.FormValue("enabled") == "true" || r.FormValue("enabled") == "on",
	}

	if len(pref.Channels) == 0 || len(pref.Events) == 0 {
		http.Error(w, "channels and events are required", http.StatusBadRequest)
		return
	}

	if err := s.adminNotifyStore.Set(pref); err != nil {
		slog.Error("failed to save admin notify pref", "user", adminUser, "err", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}

	slog.Info("ADMIN_NOTIFY_PREF_SAVED", "user", adminUser, "channels", pref.Channels, "events", pref.Events)
	s.setFlashCookie(w, "pref_saved:")
	http.Redirect(w, r, s.baseURL+"/admin/notifications", http.StatusSeeOther)
}

// handleAdminTestNotifyChannel sends a test notification to a specific channel.
// POST /api/admin/test-channel
func (s *Server) handleAdminTestNotifyChannel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adminUser := s.verifyFormAuth(w, r)
	if adminUser == "" {
		return
	}
	if s.getSessionRole(r) != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	channelName := strings.TrimSpace(r.FormValue("channel"))
	channelMap := s.notifyChannelMap()
	ch, ok := channelMap[channelName]
	if !ok {
		s.setFlashCookie(w, "test_failed:unknown channel "+channelName)
		http.Redirect(w, r, s.baseURL+"/admin/notifications", http.StatusSeeOther)
		return
	}

	d := notify.WebhookData{
		Event:     "test",
		Username:  "test-user",
		Hostname:  "test-host",
		UserCode:  "TEST-001",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     adminUser,
	}

	timeout := s.notifyDefaultTimeout()
	if err := notify.Deliver(ch, d, timeout); err != nil {
		slog.Warn("test notification failed", "admin", adminUser, "channel", channelName, "err", err)
		s.setFlashCookie(w, "test_failed:"+channelName+" - "+err.Error())
	} else {
		slog.Info("test notification sent", "admin", adminUser, "channel", channelName)
		s.setFlashCookie(w, "test_sent:"+channelName)
	}
	http.Redirect(w, r, s.baseURL+"/admin/notifications", http.StatusSeeOther)
}

// splitTrimmed splits a comma-separated string and trims whitespace from each element.
// Returns nil if the input is empty.
func splitTrimmed(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// notifyChannelListJSON returns the notification channels as JSON for API consumers.
// GET /api/notification/channels
func (s *Server) handleNotifyChannelList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.verifyJSONAdminAuth(w, r) == "" {
		return
	}

	s.notifyCfgMu.RLock()
	channels := make([]notify.Channel, len(s.notifyCfg.Channels))
	copy(channels, s.notifyCfg.Channels)
	s.notifyCfgMu.RUnlock()

	// Strip secrets from API response.
	for i := range channels {
		channels[i].Token = ""
		channels[i].Command = ""
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(channels); err != nil {
		slog.Error("encoding notification channels", "err", err)
	}
}
