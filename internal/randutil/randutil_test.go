package randutil

import (
	"regexp"
	"testing"
)

var hexPattern = regexp.MustCompile(`^[0-9a-f]+$`)

func TestHex_Length(t *testing.T) {
	for _, n := range []int{1, 8, 16, 32} {
		s, err := Hex(n)
		if err != nil {
			t.Fatalf("Hex(%d): %v", n, err)
		}
		if len(s) != 2*n {
			t.Errorf("Hex(%d) returned %d chars, want %d", n, len(s), 2*n)
		}
	}
}

func TestHex_ValidHex(t *testing.T) {
	s, err := Hex(16)
	if err != nil {
		t.Fatalf("Hex: %v", err)
	}
	if !hexPattern.MatchString(s) {
		t.Errorf("Hex(16) = %q, contains non-hex characters", s)
	}
}

func TestHex_Uniqueness(t *testing.T) {
	a, err := Hex(16)
	if err != nil {
		t.Fatalf("Hex: %v", err)
	}
	b, err := Hex(16)
	if err != nil {
		t.Fatalf("Hex: %v", err)
	}
	if a == b {
		t.Errorf("two Hex(16) calls returned identical values: %q", a)
	}
}

func TestHex_Zero(t *testing.T) {
	s, err := Hex(0)
	if err != nil {
		t.Fatalf("Hex(0): %v", err)
	}
	if s != "" {
		t.Errorf("Hex(0) = %q, want empty string", s)
	}
}
