package server

import (
	"path/filepath"
	"testing"
)

func TestHostRegistry_EmptyRegistry(t *testing.T) {
	r := NewHostRegistry("")

	if r.IsEnabled() {
		t.Error("expected empty registry to be disabled")
	}
	if !r.HasHost("any") {
		t.Error("expected HasHost to return true for empty registry")
	}
	if !r.ValidateHost("any", "any-secret") {
		t.Error("expected ValidateHost to return true for empty registry")
	}
	if !r.ValidateAnyHost("any-secret") {
		t.Error("expected ValidateAnyHost to return true for empty registry")
	}
	if !r.IsUserAuthorized("any", "any-user") {
		t.Error("expected IsUserAuthorized to return true for empty registry")
	}
}

func TestHostRegistry_AddHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	secret, err := r.AddHost("web01", []string{"alice", "bob"}, "production")
	if err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if secret == "" {
		t.Error("expected non-empty secret")
	}

	if !r.IsEnabled() {
		t.Error("expected registry to be enabled after adding host")
	}
	if !r.HasHost("web01") {
		t.Error("expected HasHost to return true for registered host")
	}
	if r.HasHost("db01") {
		t.Error("expected HasHost to return false for unregistered host")
	}
}

func TestHostRegistry_ValidateHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	secret, _ := r.AddHost("web01", []string{"*"}, "")

	if !r.ValidateHost("web01", secret) {
		t.Error("expected ValidateHost to pass with correct secret")
	}
	if r.ValidateHost("web01", "wrong-secret") {
		t.Error("expected ValidateHost to fail with wrong secret")
	}
	if r.ValidateHost("nonexistent", secret) {
		t.Error("expected ValidateHost to fail for unregistered host")
	}
}

func TestHostRegistry_ValidateAnyHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	secret, _ := r.AddHost("web01", []string{"*"}, "")

	if !r.ValidateAnyHost(secret) {
		t.Error("expected ValidateAnyHost to pass with valid secret")
	}
	if r.ValidateAnyHost("wrong-secret") {
		t.Error("expected ValidateAnyHost to fail with wrong secret")
	}
}

func TestHostRegistry_IsUserAuthorized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	r.AddHost("web01", []string{"alice", "bob"}, "")

	if !r.IsUserAuthorized("web01", "alice") {
		t.Error("expected alice to be authorized")
	}
	if !r.IsUserAuthorized("web01", "bob") {
		t.Error("expected bob to be authorized")
	}
	if r.IsUserAuthorized("web01", "charlie") {
		t.Error("expected charlie to not be authorized")
	}
	if r.IsUserAuthorized("nonexistent", "alice") {
		t.Error("expected alice to not be authorized on unregistered host")
	}
}

func TestHostRegistry_IsUserAuthorized_Wildcard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	r.AddHost("web01", []string{"*"}, "")

	if !r.IsUserAuthorized("web01", "anybody") {
		t.Error("expected wildcard user to be authorized")
	}
}

func TestHostRegistry_RegisteredHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	r.AddHost("web02", []string{"*"}, "")
	r.AddHost("web01", []string{"*"}, "")

	hosts := r.RegisteredHosts()
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0] != "web01" || hosts[1] != "web02" {
		t.Errorf("expected sorted hosts [web01 web02], got %v", hosts)
	}
}

func TestHostRegistry_GetHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	r.AddHost("web01", []string{"alice"}, "production")

	users, group, regAt, ok := r.GetHost("web01")
	if !ok {
		t.Fatal("expected to find host")
	}
	if len(users) != 1 || users[0] != "alice" {
		t.Errorf("unexpected users: %v", users)
	}
	if group != "production" {
		t.Errorf("expected group 'production', got %q", group)
	}
	if regAt.IsZero() {
		t.Error("expected non-zero registered_at")
	}

	_, _, _, ok = r.GetHost("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent host")
	}
}

func TestHostRegistry_HostsForUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	r.AddHost("web01", []string{"alice", "bob"}, "")
	r.AddHost("web02", []string{"alice"}, "")
	r.AddHost("db01", []string{"bob"}, "")

	aliceHosts := r.HostsForUser("alice")
	if len(aliceHosts) != 2 {
		t.Errorf("expected 2 hosts for alice, got %d: %v", len(aliceHosts), aliceHosts)
	}

	bobHosts := r.HostsForUser("bob")
	if len(bobHosts) != 2 {
		t.Errorf("expected 2 hosts for bob, got %d: %v", len(bobHosts), bobHosts)
	}

	charlieHosts := r.HostsForUser("charlie")
	if len(charlieHosts) != 0 {
		t.Errorf("expected 0 hosts for charlie, got %d", len(charlieHosts))
	}
}

func TestHostRegistry_RemoveHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	r.AddHost("web01", []string{"*"}, "")

	err := r.RemoveHost("web01")
	if err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
	if r.HasHost("web01") {
		// Once removed it should not be found (but IsEnabled is false → HasHost returns true)
		if r.IsEnabled() {
			t.Error("expected registry to be disabled after removing last host")
		}
	}

	err = r.RemoveHost("nonexistent")
	if err == nil {
		t.Error("expected error when removing nonexistent host")
	}
}

func TestHostRegistry_AddHost_Duplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	r.AddHost("web01", []string{"*"}, "")
	_, err := r.AddHost("web01", []string{"*"}, "")
	if err == nil {
		t.Error("expected error for duplicate hostname")
	}
}

func TestHostRegistry_AddHost_Reserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	_, err := r.AddHost("localhost", []string{"*"}, "")
	if err == nil {
		t.Error("expected error for reserved hostname")
	}

	_, err = r.AddHost("123", []string{"*"}, "")
	if err == nil {
		t.Error("expected error for numeric hostname")
	}
}

func TestHostRegistry_AddHost_InvalidUsername(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	_, err := r.AddHost("web01", []string{"invalid user!"}, "")
	if err == nil {
		t.Error("expected error for invalid username")
	}
}

func TestHostRegistry_AddHost_InvalidGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	_, err := r.AddHost("web01", []string{"*"}, "invalid group!")
	if err == nil {
		t.Error("expected error for invalid group name")
	}
}

func TestHostRegistry_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	secret, _ := r.AddHost("Web01", []string{"*"}, "")

	if !r.HasHost("WEB01") {
		t.Error("expected case-insensitive HasHost")
	}
	if !r.ValidateHost("web01", secret) {
		t.Error("expected case-insensitive ValidateHost")
	}
}

func TestHostRegistry_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")

	r := NewHostRegistry(path)
	secret, _ := r.AddHost("web01", []string{"alice"}, "prod")

	// Create a new registry from the same file.
	r2 := NewHostRegistry(path)

	if !r2.IsEnabled() {
		t.Error("expected persisted registry to be enabled")
	}
	if !r2.ValidateHost("web01", secret) {
		t.Error("expected persisted host to validate")
	}
	if !r2.IsUserAuthorized("web01", "alice") {
		t.Error("expected persisted user authorization")
	}
	_, group, _, ok := r2.GetHost("web01")
	if !ok || group != "prod" {
		t.Errorf("expected persisted group 'prod', got %q (ok=%v)", group, ok)
	}
}

func TestHostRegistry_RotateSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	oldSecret, _ := r.AddHost("web01", []string{"*"}, "")

	newSecret, err := r.RotateSecret("web01")
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if newSecret == oldSecret {
		t.Error("expected different secret after rotation")
	}
	if !r.ValidateHost("web01", newSecret) {
		t.Error("expected new secret to be valid")
	}
	if r.ValidateHost("web01", oldSecret) {
		t.Error("expected old secret to be invalid after rotation")
	}
}

func TestHostRegistry_RotateSecret_NotFound(t *testing.T) {
	r := NewHostRegistry("")
	_, err := r.RotateSecret("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent host")
	}
}

func TestHostRegistry_RemoveUserFromAllHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.json")
	r := NewHostRegistry(path)

	r.AddHost("web01", []string{"alice", "bob"}, "")
	r.AddHost("web02", []string{"alice"}, "")

	r.RemoveUserFromAllHosts("alice")

	if r.IsUserAuthorized("web01", "alice") {
		t.Error("expected alice to be removed from web01")
	}
	if !r.IsUserAuthorized("web01", "bob") {
		t.Error("expected bob to still be authorized on web01")
	}
	if r.IsUserAuthorized("web02", "alice") {
		t.Error("expected alice to be removed from web02")
	}
}

func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Web01", "web01"},
		{"web01.", "web01"},
		{"WEB01.EXAMPLE.COM.", "web01.example.com"},
		{"web01", "web01"},
	}
	for _, tc := range tests {
		got := normalizeHostname(tc.input)
		if got != tc.want {
			t.Errorf("normalizeHostname(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
