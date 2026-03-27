package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

const maxLogOutput = 4096

// limitedWriter wraps a writer and silently discards bytes beyond the limit.
type limitedWriter struct {
	w io.Writer
	n int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	total := len(p)
	if lw.n <= 0 {
		return total, nil
	}
	if int64(len(p)) > lw.n {
		p = p[:lw.n]
	}
	n, err := lw.w.Write(p)
	lw.n -= int64(n)
	return total, err
}

// truncateOutput trims whitespace and caps output for log messages.
func truncateOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLogOutput {
		truncLen := maxLogOutput
		for truncLen > 0 && !utf8.RuneStart(s[truncLen]) {
			truncLen--
		}
		return s[:truncLen] + "...(truncated)"
	}
	return s
}

// randomHex returns n random bytes encoded as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sanitizeForTerminal removes control characters (ANSI escapes, null bytes, etc.)
// from a string before displaying it on a terminal.
func sanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		if r >= 0x80 && r <= 0x9F {
			return -1
		}
		if r >= 0x202A && r <= 0x202E {
			return -1
		}
		if r >= 0x2066 && r <= 0x2069 {
			return -1
		}
		if r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF {
			return -1
		}
		return r
	}, s)
}

// verifyWebhookSignature validates HMAC-SHA256 webhook signatures from PocketID.
// Expected header format: "sha256=<hex>"
func verifyWebhookSignature(r *http.Request, secret, sig string) bool {
	if sig == "" {
		return false
	}
	sig = strings.TrimPrefix(sig, "sha256=")

	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		return false
	}
	// Replace body so it can be read again downstream if needed
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison
	if len(sig) != len(expected) {
		return false
	}
	var diff byte
	for i := range expected {
		diff |= expected[i] ^ sig[i]
	}
	return diff == 0
}
