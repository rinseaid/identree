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

// formatDuration formats a duration for display in the UI using localized suffixes.
// t is a translation lookup function (e.g. from T(lang)); if nil, English suffixes are used.
func formatDuration(t func(string) string, d time.Duration) string {
	lookup := func(key, fallback string) string {
		if t != nil {
			if v := t(key); v != key && v != "" {
				return v
			}
		}
		return fallback
	}
	if d <= 0 {
		return "0s"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	hSuffix := lookup("hour_abbr", "h")
	mSuffix := lookup("minute_abbr", "m")
	if h > 0 && m > 0 {
		return fmt.Sprintf("%d%s %d%s", h, hSuffix, m, mSuffix)
	}
	if h > 0 {
		return fmt.Sprintf("%d%s", h, hSuffix)
	}
	if m > 0 {
		return fmt.Sprintf("%d%s", m, mSuffix)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
