package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTranslationsLoaded(t *testing.T) {
	// All supported languages should be loaded
	for _, lang := range SupportedLanguages {
		if _, ok := translations[lang.Code]; !ok {
			t.Errorf("translations for %s (%s) not loaded", lang.Name, lang.Code)
		}
	}
}

func TestTFallbackToEnglish(t *testing.T) {
	tr := T("xx") // unsupported language
	got := tr("app_name")
	if got != "identree" {
		t.Errorf("T('xx')('app_name') = %q, want %q", got, "identree")
	}
}

func TestTReturnsKeyAsLastResort(t *testing.T) {
	tr := T("en")
	got := tr("nonexistent_key_xyz")
	if got != "nonexistent_key_xyz" {
		t.Errorf("T('en')('nonexistent_key_xyz') = %q, want %q", got, "nonexistent_key_xyz")
	}
}

func TestTSpanish(t *testing.T) {
	tr := T("es")
	got := tr("sessions")
	if got != "Sesiones" {
		t.Errorf("T('es')('sessions') = %q, want %q", got, "Sesiones")
	}
}

func TestDetectLanguageCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "identree_lang", Value: "fr"})
	lang := DetectLanguage(r)
	if lang != "fr" {
		t.Errorf("DetectLanguage with cookie = %q, want %q", lang, "fr")
	}
}

func TestDetectLanguageAcceptHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
	lang := DetectLanguage(r)
	if lang != "de" {
		t.Errorf("DetectLanguage with Accept-Language = %q, want %q", lang, "de")
	}
}

func TestDetectLanguageDefault(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	lang := DetectLanguage(r)
	if lang != "en" {
		t.Errorf("DetectLanguage default = %q, want %q", lang, "en")
	}
}

func TestDetectLanguageCookiePriority(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "identree_lang", Value: "ja"})
	r.Header.Set("Accept-Language", "de-DE")
	lang := DetectLanguage(r)
	if lang != "ja" {
		t.Errorf("DetectLanguage cookie should take priority, got %q, want %q", lang, "ja")
	}
}

func TestSetLanguageCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/hosts?lang=es", nil)
	w := httptest.NewRecorder()
	redirected := SetLanguageCookie(w, r)
	if !redirected {
		t.Error("SetLanguageCookie should return true for valid lang param")
	}
	// Check the cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "identree_lang" && c.Value == "es" {
			found = true
		}
	}
	if !found {
		t.Error("identree_lang cookie not set")
	}
}

func TestTerminalLang(t *testing.T) {
	// Should not panic regardless of environment
	_ = TerminalLang()
}

func TestAllTranslationKeysConsistent(t *testing.T) {
	// All languages should have the same keys as English
	enKeys := translations["en"]
	for _, lang := range SupportedLanguages {
		if lang.Code == "en" {
			continue
		}
		tr, ok := translations[lang.Code]
		if !ok {
			continue
		}
		for key := range enKeys {
			if _, ok := tr[key]; !ok {
				t.Errorf("language %s missing key %q", lang.Code, key)
			}
		}
	}
}
