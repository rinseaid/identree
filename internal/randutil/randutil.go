package randutil

import (
	"crypto/rand"
	"encoding/hex"
)

// Hex returns n random bytes encoded as a hex string.
func Hex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
