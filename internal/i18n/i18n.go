package i18n

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

//go:embed translations/*.json
var translationsFS embed.FS

// translations maps language code -> key -> translated string
var translations map[string]map[string]string

// LangOption represents a supported language for the selector dropdown.
type LangOption struct {
	Code string
	Name string
}

// SupportedLanguages is the ordered list for the language selector.
var SupportedLanguages = []LangOption{
	{"en", "English"},
	{"es", "Español"},
	{"fr", "Français"},
	{"de", "Deutsch"},
	{"ja", "日本語"},
	{"zh", "中文"},
	{"pt", "Português"},
	{"ko", "한국어"},
}

func init() {
	translations = make(map[string]map[string]string)
	for _, lang := range SupportedLanguages {
		data, err := translationsFS.ReadFile("translations/" + lang.Code + ".json")
		if err != nil {
			log.Printf("WARNING: translation file for %s not found", lang.Code)
			continue
		}
		var t map[string]string
		if err := json.Unmarshal(data, &t); err != nil {
			log.Printf("WARNING: invalid translation file for %s: %v", lang.Code, err)
			continue
		}
		translations[lang.Code] = t
	}
}

// T returns a translation function for the given language.
// Falls back to English if the key is not found in the requested language.
func T(lang string) func(string) string {
	return func(key string) string {
		if t, ok := translations[lang]; ok {
			if v, ok := t[key]; ok {
				return v
			}
		}
		// Fallback to English
		if t, ok := translations["en"]; ok {
			if v, ok := t[key]; ok {
				return v
			}
		}
		return key // return the key itself as last resort
	}
}

// DetectLanguage determines the user's preferred language.
// Priority: identree_lang cookie > Accept-Language header > "en"
func DetectLanguage(r *http.Request) string {
	// Check cookie first
	if c, err := r.Cookie("identree_lang"); err == nil && c.Value != "" {
		for _, lang := range SupportedLanguages {
			if lang.Code == c.Value {
				return c.Value
			}
		}
	}

	// Parse Accept-Language header
	accept := r.Header.Get("Accept-Language")
	if accept != "" {
		// Simple parser: take the first matching language
		for _, part := range strings.Split(accept, ",") {
			lang := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
			lang = strings.SplitN(lang, "-", 2)[0] // "en-US" -> "en"
			for _, supported := range SupportedLanguages {
				if supported.Code == lang {
					return lang
				}
			}
		}
	}

	return "en"
}

// terminalLang detects the user's preferred language from environment variables.
// Checks LC_ALL, LC_MESSAGES, LANG in order. Parses "es_ES.UTF-8" -> "es".
// Falls back to "en" if no supported language is found.
func TerminalLang() string {
	for _, envVar := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		val := os.Getenv(envVar)
		if val == "" || val == "C" || val == "POSIX" {
			continue
		}
		// Strip encoding (e.g., ".UTF-8")
		if idx := strings.Index(val, "."); idx > 0 {
			val = val[:idx]
		}
		// Strip country (e.g., "_ES")
		if idx := strings.Index(val, "_"); idx > 0 {
			val = val[:idx]
		}
		// Check if it's a supported language
		for _, lang := range SupportedLanguages {
			if lang.Code == val {
				return val
			}
		}
	}
	return "en"
}

// SetLanguageCookie checks for a lang query parameter and sets the identree_lang cookie.
// Returns true if a redirect should occur (lang param was present).
func SetLanguageCookie(w http.ResponseWriter, r *http.Request) bool {
	langParam := r.URL.Query().Get("lang")
	if langParam == "" {
		return false
	}
	for _, l := range SupportedLanguages {
		if l.Code == langParam {
			http.SetCookie(w, &http.Cookie{
				Name:     "identree_lang",
				Value:    langParam,
				Path:     "/",
				MaxAge:   365 * 24 * 60 * 60,
				SameSite: http.SameSiteLaxMode,
			})
			break
		}
	}
	// Redirect to clean URL (strip lang param)
	q := r.URL.Query()
	q.Del("lang")
	cleanURL := r.URL.Path
	if encoded := q.Encode(); encoded != "" {
		cleanURL += "?" + encoded
	}
	http.Redirect(w, r, cleanURL, http.StatusSeeOther)
	return true
}
