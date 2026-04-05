package notify

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		// IPv4 loopback
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		// RFC1918
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		// Link-local / cloud metadata
		{"169.254.169.254", true},
		{"169.254.0.1", true},
		// Just outside RFC1918
		{"172.15.255.255", false},
		{"172.32.0.0", false},
		{"11.0.0.1", false},
		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		// IPv6 loopback
		{"::1", true},
		// IPv6 link-local
		{"fe80::1", true},
		// IPv6 ULA
		{"fd00::1", true},
		{"fc00::1", true},
		// IPv6 public
		{"2606:4700::1111", false},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("bad test IP: %s", tt.ip)
		}
		got := isPrivateIP(ip)
		if got != tt.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestSSRFSafeDialContext_RejectsLocalhost(t *testing.T) {
	// Verify that the dial function rejects localhost by name.
	// We call ssrfSafeDialContext directly — no HTTP server needed.
	conn, err := ssrfSafeDialContext(t.Context(), "tcp", "localhost:80")
	if conn != nil {
		conn.Close()
		t.Fatal("expected connection to be rejected, but got a connection")
	}
	if err == nil {
		t.Fatal("expected error for localhost, got nil")
	}
	if got := err.Error(); !contains(got, "denied") {
		t.Errorf("error should mention 'denied', got: %s", got)
	}
}

func TestSSRFSafeDialContext_RejectsPrivateIP(t *testing.T) {
	// Directly use a numeric IP to bypass DNS.
	conn, err := ssrfSafeDialContext(t.Context(), "tcp", "10.0.0.1:80")
	if conn != nil {
		conn.Close()
		t.Fatal("expected connection to be rejected, but got a connection")
	}
	if err == nil {
		t.Fatal("expected error for 10.0.0.1, got nil")
	}
	if got := err.Error(); !contains(got, "denied") {
		t.Errorf("error should mention 'denied', got: %s", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
