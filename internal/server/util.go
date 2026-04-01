package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
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
// commitShort returns the last 8 characters of a commit hash for display,
// falling back to the full string if it is 8 characters or fewer.
func commitShort(c string) string {
	if len(c) <= 8 {
		return c
	}
	return c[len(c)-8:]
}

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

// verifyWebhookSignature validates HMAC-SHA256 webhook signatures from PocketID.
// Expected header format: "sha256=<hex>"
func verifyWebhookSignature(r *http.Request, secret, sig string) bool {
	if sig == "" {
		return false
	}
	sig = strings.TrimPrefix(sig, "sha256=")

	// 64 KB limit: large enough for any real PocketID webhook payload while
	// preventing memory exhaustion from oversized or malicious requests.
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		return false
	}
	// Replace body so it can be read again downstream if needed
	r.Body = io.NopCloser(bytes.NewReader(body))

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) == 1
}
