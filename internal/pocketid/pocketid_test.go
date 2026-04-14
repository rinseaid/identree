package pocketid

import "testing"

// ── NewPocketIDClient ────────────────────────────────────────────────────────

func TestNewPocketIDClient_Valid(t *testing.T) {
	c := NewPocketIDClient("https://id.example.com", "my-api-key")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.baseURL != "https://id.example.com" {
		t.Errorf("baseURL = %q, want %q", c.baseURL, "https://id.example.com")
	}
	if c.apiKey != "my-api-key" {
		t.Errorf("apiKey = %q, want %q", c.apiKey, "my-api-key")
	}
}

func TestNewPocketIDClient_TrimsTrailingSlash(t *testing.T) {
	c := NewPocketIDClient("https://id.example.com///", "key")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.baseURL != "https://id.example.com" {
		t.Errorf("baseURL = %q, want trailing slashes trimmed", c.baseURL)
	}
}

func TestNewPocketIDClient_EmptyURL(t *testing.T) {
	c := NewPocketIDClient("", "key")
	if c != nil {
		t.Error("expected nil client for empty URL")
	}
}

func TestNewPocketIDClient_EmptyKey(t *testing.T) {
	c := NewPocketIDClient("https://id.example.com", "")
	if c != nil {
		t.Error("expected nil client for empty API key")
	}
}

func TestNewPocketIDClient_BothEmpty(t *testing.T) {
	c := NewPocketIDClient("", "")
	if c != nil {
		t.Error("expected nil client when both URL and key are empty")
	}
}

// ── NilClient safe methods ───────────────────────────────────────────────────

func TestNilClient_GetGroups(t *testing.T) {
	var c *PocketIDClient
	groups, err := c.GetGroups()
	if err != nil {
		t.Errorf("nil client GetGroups: unexpected error: %v", err)
	}
	if groups != nil {
		t.Errorf("nil client GetGroups: expected nil, got %v", groups)
	}
}

func TestNilClient_GetUserPermissions(t *testing.T) {
	var c *PocketIDClient
	perms, err := c.GetUserPermissions()
	if err != nil {
		t.Errorf("nil client GetUserPermissions: unexpected error: %v", err)
	}
	if perms != nil {
		t.Errorf("nil client GetUserPermissions: expected nil, got %v", perms)
	}
}

func TestNilClient_InvalidateCache(t *testing.T) {
	var c *PocketIDClient
	// Should not panic.
	c.InvalidateCache()
}

// ── stripNullBytes ───────────────────────────────────────────────────────────

func TestStripNullBytes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"he\x00llo", "hello"},
		{"\x00\x00\x00", ""},
		{"", ""},
		{"no nulls here", "no nulls here"},
	}
	for _, tt := range tests {
		got := stripNullBytes(tt.input)
		if got != tt.want {
			t.Errorf("stripNullBytes(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── ClaimsMap ────────────────────────────────────────────────────────────────

func TestClaimsMap(t *testing.T) {
	g := &PocketIDAdminGroup{
		CustomClaims: []Claim{
			{Key: "sudoCommands", Value: "ALL"},
			{Key: "access\x00Hosts", Value: "*.example\x00.com"},
		},
	}
	m := g.ClaimsMap()
	if m["sudoCommands"] != "ALL" {
		t.Errorf("sudoCommands = %q, want %q", m["sudoCommands"], "ALL")
	}
	if m["accessHosts"] != "*.example.com" {
		t.Errorf("accessHosts = %q, want null bytes stripped", m["accessHosts"])
	}
}

// ── NewUserDirectory ─────────────────────────────────────────────────────────

func TestNewUserDirectory(t *testing.T) {
	users := []PocketIDAdminUser{
		{ID: "u1", Username: "alice", Email: "alice@example.com"},
		{ID: "u2", Username: "bob", Email: "bob@example.com"},
	}
	groups := []PocketIDAdminGroup{
		{ID: "g1", Name: "admins", Members: []struct {
			ID string `json:"id"`
		}{{ID: "u1"}}},
	}

	dir := NewUserDirectory(users, groups)

	if dir.ByUsername["alice"] == nil {
		t.Error("expected alice in ByUsername")
	}
	if dir.ByUsername["bob"] == nil {
		t.Error("expected bob in ByUsername")
	}
	if dir.ByUserID["u1"] == nil {
		t.Error("expected u1 in ByUserID")
	}
	if dir.ByGroupID["g1"] == nil {
		t.Error("expected g1 in ByGroupID")
	}
	if dir.ByGroupID["nonexistent"] != nil {
		t.Error("expected nil for nonexistent group")
	}
}

// ── validAdminIDPattern ──────────────────────────────────────────────────────

func TestValidAdminIDPattern(t *testing.T) {
	valid := []string{
		"abc123",
		"550e8400-e29b-41d4-a716-446655440000",
		"AABB",
		"a-b-c",
	}
	invalid := []string{
		"",
		"../../../etc/passwd",
		"abc 123",
		"abc;rm -rf /",
		"abc\nxyz",
	}
	for _, s := range valid {
		if !validAdminIDPattern.MatchString(s) {
			t.Errorf("expected %q to match validAdminIDPattern", s)
		}
	}
	for _, s := range invalid {
		if validAdminIDPattern.MatchString(s) {
			t.Errorf("expected %q to NOT match validAdminIDPattern", s)
		}
	}
}
