package server

import (
	"fmt"
	"net/http"
	"time"

	i18npkg "github.com/rinseaid/identree/internal/i18n"
)

// LangOption is a re-export of i18n.LangOption for use in templates.
type LangOption = i18npkg.LangOption

// supportedLanguages is the ordered list for the language selector.
var supportedLanguages = i18npkg.SupportedLanguages

// T returns a translation function for the given language.
func T(lang string) func(string) string {
	return i18npkg.T(lang)
}

// detectLanguage determines the user's preferred language.
func detectLanguage(r *http.Request) string {
	return i18npkg.DetectLanguage(r)
}

// setLanguageCookie checks for a lang query parameter and sets the cookie.
func setLanguageCookie(w http.ResponseWriter, r *http.Request) bool {
	return i18npkg.SetLanguageCookie(w, r)
}

// formatDuration formats a duration for display in the UI.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 && m > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh", h)
	}
	if m > 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
