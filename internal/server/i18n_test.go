package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-1 * time.Second, "0s"},
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{1*time.Hour + 30*time.Minute, "1h 30m"},
		{2 * time.Hour, "2h"},
		{25 * time.Hour, "1d 1h"},
		{48 * time.Hour, "2d"},
		{49*time.Hour + 30*time.Minute, "2d 1h 30m"},
		{24*time.Hour + 15*time.Minute, "1d 15m"},
	}

	for _, tc := range tests {
		got := formatDuration(nil, tc.d)
		if got != tc.want {
			t.Errorf("formatDuration(nil, %v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestFormatDuration_WithTranslation(t *testing.T) {
	tr := func(key string) string {
		switch key {
		case "day_abbr":
			return " Tag"
		case "hour_abbr":
			return " Std"
		case "minute_abbr":
			return " Min"
		}
		return key
	}

	got := formatDuration(tr, 2*time.Hour+15*time.Minute)
	if got != "2 Std 15 Min" {
		t.Errorf("formatDuration with translation = %q", got)
	}
}

func TestDetectLanguage_Default(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	lang := detectLanguage(r)
	if lang == "" {
		t.Error("expected non-empty language")
	}
}
