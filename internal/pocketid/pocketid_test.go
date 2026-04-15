package pocketid

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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

// ── Helper: mock PocketID server ─────────────────────────────────────────────

// newTestClient creates a PocketIDClient that points at the given test server.
func newTestClient(ts *httptest.Server) *PocketIDClient {
	c := NewPocketIDClient(ts.URL, "test-api-key")
	c.cacheTTL = 1 * time.Second // short TTL for tests
	return c
}

// paginatedResponse wraps data with a pagination envelope.
func paginatedResponse(data any, page, totalPages int) []byte {
	b, _ := json.Marshal(map[string]any{
		"data":       data,
		"pagination": map[string]int{"totalPages": totalPages},
	})
	return b
}

// ── FetchDirectory — success ─────────────────────────────────────────────────

func TestFetchDirectory_Success(t *testing.T) {
	mux := http.NewServeMux()

	// /api/users — paginated user list
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		users := []map[string]any{
			{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com", "firstName": "Alice", "lastName": "Smith"},
			{"id": "a0000000-0000-0000-0000-000000000002", "username": "bob", "email": "bob@example.com", "firstName": "Bob", "lastName": "Jones"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(users, 1, 1))
	})

	// /api/user-groups — paginated group list
	mux.HandleFunc("/api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		groups := []map[string]string{
			{"id": "b0000000-0000-0000-0000-000000000001", "name": "admins"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(groups, 1, 1))
	})

	// /api/user-groups/b0000000-0000-0000-0000-000000000001 — group detail
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		detail := map[string]any{
			"id":   "b0000000-0000-0000-0000-000000000001",
			"name": "admins",
			"customClaims": []map[string]string{
				{"key": "sudoCommands", "value": "ALL"},
			},
			"users": []map[string]string{
				{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com"},
			},
		}
		b, _ := json.Marshal(detail)
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	dir, err := c.FetchDirectory()
	if err != nil {
		t.Fatalf("FetchDirectory: unexpected error: %v", err)
	}
	if len(dir.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(dir.Users))
	}
	if len(dir.Groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(dir.Groups))
	}
	if dir.ByUsername["alice"] == nil {
		t.Error("expected alice in ByUsername")
	}
	if dir.ByUsername["bob"] == nil {
		t.Error("expected bob in ByUsername")
	}
	if dir.ByGroupID["b0000000-0000-0000-0000-000000000001"] == nil {
		t.Error("expected group in ByGroupID")
	}
}

// ── FetchDirectory — server error ────────────────────────────────────────────

func TestFetchDirectory_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer ts.Close()

	c := newTestClient(ts)
	dir, err := c.FetchDirectory()
	if err == nil {
		t.Fatal("expected error from FetchDirectory when server returns 500")
	}
	if dir != nil {
		t.Error("expected nil directory on server error")
	}
}

// ── FetchDirectory — invalid JSON ────────────────────────────────────────────

func TestFetchDirectory_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer ts.Close()

	c := newTestClient(ts)
	dir, err := c.FetchDirectory()
	if err == nil {
		t.Fatal("expected error from FetchDirectory when server returns invalid JSON")
	}
	if dir != nil {
		t.Error("expected nil directory on invalid JSON")
	}
}

// ── FetchDirectory — pagination ──────────────────────────────────────────────

func TestFetchDirectory_Pagination(t *testing.T) {
	mux := http.NewServeMux()

	// Users: two pages
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("pagination[page]")
		w.Header().Set("Content-Type", "application/json")
		if page == "1" || page == "" {
			users := []map[string]any{
				{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com"},
			}
			w.Write(paginatedResponse(users, 1, 2))
		} else {
			users := []map[string]any{
				{"id": "a0000000-0000-0000-0000-000000000002", "username": "bob", "email": "bob@example.com"},
			}
			w.Write(paginatedResponse(users, 2, 2))
		}
	})

	// Groups: two pages
	mux.HandleFunc("/api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("pagination[page]")
		w.Header().Set("Content-Type", "application/json")
		if page == "1" || page == "" {
			w.Write(paginatedResponse([]map[string]string{{"id": "b0000000-0000-0000-0000-000000000001", "name": "group1"}}, 1, 2))
		} else {
			w.Write(paginatedResponse([]map[string]string{{"id": "b0000000-0000-0000-0000-000000000002", "name": "group2"}}, 2, 2))
		}
	})

	// Group details
	for _, gid := range []string{"b0000000-0000-0000-0000-000000000001", "b0000000-0000-0000-0000-000000000002"} {
		gid := gid
		mux.HandleFunc("/api/user-groups/"+gid, func(w http.ResponseWriter, r *http.Request) {
			detail := map[string]any{
				"id":           gid,
				"name":         gid,
				"customClaims": []map[string]string{},
				"users":        []map[string]string{},
			}
			b, _ := json.Marshal(detail)
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		})
	}

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	dir, err := c.FetchDirectory()
	if err != nil {
		t.Fatalf("FetchDirectory with pagination: unexpected error: %v", err)
	}
	if len(dir.Users) != 2 {
		t.Errorf("expected 2 users across 2 pages, got %d", len(dir.Users))
	}
	if len(dir.Groups) != 2 {
		t.Errorf("expected 2 groups across 2 pages, got %d", len(dir.Groups))
	}
}

// ── GetGroups — success ──────────────────────────────────────────────────────

func TestGetGroups_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		groups := []map[string]string{
			{"id": "b0000000-0000-0000-0000-000000000001", "name": "devs"},
			{"id": "b0000000-0000-0000-0000-000000000002", "name": "ops"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(groups, 1, 1))
	})
	for _, g := range []struct{ id, name string }{{"b0000000-0000-0000-0000-000000000001", "devs"}, {"b0000000-0000-0000-0000-000000000002", "ops"}} {
		g := g
		mux.HandleFunc("/api/user-groups/"+g.id, func(w http.ResponseWriter, r *http.Request) {
			detail := map[string]any{
				"id":   g.id,
				"name": g.name,
				"customClaims": []map[string]string{
					{"key": "sudoCommands", "value": "ALL"},
				},
				"users": []map[string]string{
					{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com"},
				},
			}
			b, _ := json.Marshal(detail)
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		})
	}

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	groups, err := c.GetGroups()
	if err != nil {
		t.Fatalf("GetGroups: unexpected error: %v", err)
	}
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Name != "devs" {
		t.Errorf("first group name = %q, want %q", groups[0].Name, "devs")
	}
}

// ── CachedAdminUsers — caching behavior ──────────────────────────────────────

func TestCachedAdminUsers_CacheHit(t *testing.T) {
	var hitCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		users := []map[string]any{
			{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(users, 1, 1))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	c.cacheTTL = 5 * time.Second // ensure cache does not expire between calls

	// First call: hits the server
	users1, err := c.CachedAdminUsers()
	if err != nil {
		t.Fatalf("first CachedAdminUsers: %v", err)
	}
	if len(users1) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users1))
	}

	// Second call: should come from cache
	users2, err := c.CachedAdminUsers()
	if err != nil {
		t.Fatalf("second CachedAdminUsers: %v", err)
	}
	if len(users2) != 1 {
		t.Fatalf("expected 1 user from cache, got %d", len(users2))
	}

	if hitCount.Load() != 1 {
		t.Errorf("expected 1 server hit (cached), got %d", hitCount.Load())
	}
}

// ── InvalidateCache — forces re-fetch ────────────────────────────────────────

func TestInvalidateCache_RefetchesAfterInvalidation(t *testing.T) {
	var hitCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		users := []map[string]any{
			{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(users, 1, 1))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	c.cacheTTL = 5 * time.Second

	// Populate cache
	_, err := c.CachedAdminUsers()
	if err != nil {
		t.Fatalf("first CachedAdminUsers: %v", err)
	}
	if hitCount.Load() != 1 {
		t.Fatalf("expected 1 hit after first call, got %d", hitCount.Load())
	}

	// Invalidate
	c.InvalidateCache()

	// Next call should hit the server again
	_, err = c.CachedAdminUsers()
	if err != nil {
		t.Fatalf("CachedAdminUsers after invalidation: %v", err)
	}
	if hitCount.Load() != 2 {
		t.Errorf("expected 2 server hits after invalidation, got %d", hitCount.Load())
	}
}

// ── GetUserPermissions — custom claims extraction ────────────────────────────

func TestGetUserPermissions_ClaimsExtraction(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		groups := []map[string]string{{"id": "b0000000-0000-0000-0000-000000000001", "name": "sudoers"}}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(groups, 1, 1))
	})
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		detail := map[string]any{
			"id":   "b0000000-0000-0000-0000-000000000001",
			"name": "sudoers",
			"customClaims": []map[string]string{
				{"key": "sudoCommands", "value": "/usr/bin/systemctl"},
				{"key": "sudoHosts", "value": "web*.example.com"},
				{"key": "sudoRunAsUser", "value": "root"},
				{"key": "accessHosts", "value": "10.0.0.0/8"},
			},
			"users": []map[string]string{
				{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com"},
				{"id": "a0000000-0000-0000-0000-000000000002", "username": "bob", "email": "bob@example.com"},
			},
		}
		b, _ := json.Marshal(detail)
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	perms, err := c.GetUserPermissions()
	if err != nil {
		t.Fatalf("GetUserPermissions: %v", err)
	}

	aliceGroups := perms["alice"]
	if len(aliceGroups) != 1 {
		t.Fatalf("expected 1 group for alice, got %d", len(aliceGroups))
	}
	g := aliceGroups[0]
	if g.Name != "sudoers" {
		t.Errorf("group name = %q, want %q", g.Name, "sudoers")
	}
	if g.SudoCommands != "/usr/bin/systemctl" {
		t.Errorf("SudoCommands = %q, want %q", g.SudoCommands, "/usr/bin/systemctl")
	}
	if g.SudoHosts != "web*.example.com" {
		t.Errorf("SudoHosts = %q, want %q", g.SudoHosts, "web*.example.com")
	}
	if g.SudoRunAs != "root" {
		t.Errorf("SudoRunAs = %q, want %q", g.SudoRunAs, "root")
	}
	if g.AccessHosts != "10.0.0.0/8" {
		t.Errorf("AccessHosts = %q, want %q", g.AccessHosts, "10.0.0.0/8")
	}

	bobGroups := perms["bob"]
	if len(bobGroups) != 1 {
		t.Fatalf("expected 1 group for bob, got %d", len(bobGroups))
	}
}

// ── Concurrent FetchDirectory calls ──────────────────────────────────────────

func TestFetchDirectory_Concurrent(t *testing.T) {
	var hitCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		users := []map[string]any{
			{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(users, 1, 1))
	})
	mux.HandleFunc("/api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		groups := []map[string]string{{"id": "b0000000-0000-0000-0000-000000000001", "name": "admins"}}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(groups, 1, 1))
	})
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		detail := map[string]any{
			"id": "b0000000-0000-0000-0000-000000000001", "name": "admins",
			"customClaims": []map[string]string{},
			"users":        []map[string]string{},
		}
		b, _ := json.Marshal(detail)
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir, err := c.FetchDirectory()
			if err != nil {
				errs <- err
				return
			}
			if dir == nil {
				errs <- fmt.Errorf("nil directory")
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent FetchDirectory error: %v", err)
	}
}

// ── UsersWithSSHKeys ─────────────────────────────────────────────────────────

func TestUsersWithSSHKeys(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		users := []map[string]any{
			{
				"username": "alice", "email": "alice@example.com",
				"customClaims": []map[string]string{
					{"key": "sshPublicKey", "value": "ssh-ed25519 AAAA alice@laptop"},
					{"key": "sshPublicKey1", "value": "ssh-rsa BBBB alice@desktop"},
				},
			},
			{
				"username": "bob", "email": "bob@example.com",
				"customClaims": []map[string]string{
					{"key": "someOtherClaim", "value": "irrelevant"},
				},
			},
			{
				"username": "carol", "email": "carol@example.com",
				"customClaims": []map[string]string{
					{"key": "sshPublicKey", "value": "ssh-ed25519 CCCC carol@laptop"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(users, 1, 1))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	sshUsers, err := c.UsersWithSSHKeys()
	if err != nil {
		t.Fatalf("UsersWithSSHKeys: %v", err)
	}
	if len(sshUsers) != 2 {
		t.Fatalf("expected 2 SSH users (alice, carol), got %d", len(sshUsers))
	}
	// alice should have 2 keys
	for _, u := range sshUsers {
		if u.Username == "alice" && len(u.SSHKeys) != 2 {
			t.Errorf("alice: expected 2 SSH keys, got %d", len(u.SSHKeys))
		}
		if u.Username == "carol" && len(u.SSHKeys) != 1 {
			t.Errorf("carol: expected 1 SSH key, got %d", len(u.SSHKeys))
		}
	}
}

// ── GetUserIDs ───────────────────────────────────────────────────────────────

func TestGetUserIDs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user-groups", func(w http.ResponseWriter, r *http.Request) {
		groups := []map[string]string{{"id": "b0000000-0000-0000-0000-000000000001", "name": "team"}}
		w.Header().Set("Content-Type", "application/json")
		w.Write(paginatedResponse(groups, 1, 1))
	})
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		detail := map[string]any{
			"id": "b0000000-0000-0000-0000-000000000001", "name": "team",
			"customClaims": []map[string]string{},
			"users": []map[string]string{
				{"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com"},
				{"id": "a0000000-0000-0000-0000-000000000002", "username": "bob", "email": "bob@example.com"},
			},
		}
		b, _ := json.Marshal(detail)
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	ids, err := c.GetUserIDs()
	if err != nil {
		t.Fatalf("GetUserIDs: %v", err)
	}
	if ids["alice"] != "a0000000-0000-0000-0000-000000000001" {
		t.Errorf("alice ID = %q, want UUID", ids["alice"])
	}
	if ids["bob"] != "a0000000-0000-0000-0000-000000000002" {
		t.Errorf("bob ID = %q, want UUID", ids["bob"])
	}
}

// ── GetAdminUserByID ─────────────────────────────────────────────────────────

func TestGetAdminUserByID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/a0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{
			"id": "a0000000-0000-0000-0000-000000000001", "username": "alice", "email": "alice@example.com",
			"firstName": "Alice", "lastName": "Smith", "isAdmin": true,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	u, err := c.GetAdminUserByID("a0000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("GetAdminUserByID: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("Username = %q, want %q", u.Username, "alice")
	}
	if !u.IsAdmin {
		t.Error("expected IsAdmin = true")
	}
}

func TestGetAdminUserByID_InvalidID(t *testing.T) {
	c := NewPocketIDClient("http://localhost", "key")
	_, err := c.GetAdminUserByID("../../../etc/passwd")
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
}

// ── GetAdminGroupByID ────────────────────────────────────────────────────────

func TestGetAdminGroupByID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user-groups/b0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{
			"id": "b0000000-0000-0000-0000-000000000001", "name": "admins", "friendlyName": "Admins",
			"customClaims": []map[string]string{{"key": "sudoCommands", "value": "ALL"}},
			"users":        []map[string]string{{"id": "a0000000-0000-0000-0000-000000000001"}},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	g, err := c.GetAdminGroupByID("b0000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("GetAdminGroupByID: %v", err)
	}
	if g.Name != "admins" {
		t.Errorf("Name = %q, want %q", g.Name, "admins")
	}
	if g.FriendlyName != "Admins" {
		t.Errorf("FriendlyName = %q, want %q", g.FriendlyName, "Admins")
	}
	if len(g.Members) != 1 {
		t.Errorf("expected 1 member, got %d", len(g.Members))
	}
}

// ── PutUserClaims / PutGroupClaims ───────────────────────────────────────────

func TestPutUserClaims(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/custom-claims/user/a0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.Header.Get("X-API-KEY") != "test-api-key" {
			t.Error("missing or wrong API key header")
		}
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	err := c.PutUserClaims("a0000000-0000-0000-0000-000000000001", []Claim{{Key: "sshPublicKey", Value: "ssh-ed25519 AAAA"}})
	if err != nil {
		t.Fatalf("PutUserClaims: %v", err)
	}
}

func TestPutGroupClaims(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/custom-claims/user-group/b0000000-0000-0000-0000-000000000001", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := newTestClient(ts)
	err := c.PutGroupClaims("b0000000-0000-0000-0000-000000000001", []Claim{{Key: "sudoCommands", Value: "ALL"}})
	if err != nil {
		t.Fatalf("PutGroupClaims: %v", err)
	}
}

func TestPutUserClaims_InvalidID(t *testing.T) {
	c := NewPocketIDClient("http://localhost", "key")
	err := c.PutUserClaims("../etc/passwd", nil)
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
}

// ── apiGet — API key header ──────────────────────────────────────────────────

func TestAPIGet_SetsAPIKeyHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-KEY"); got != "test-api-key" {
			t.Errorf("X-API-KEY = %q, want %q", got, "test-api-key")
		}
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	c := newTestClient(ts)
	_, err := c.apiGet(ts.URL + "/api/test")
	if err != nil {
		t.Fatalf("apiGet: %v", err)
	}
}

// ── AdminUsersCacheExpiry ────────────────────────────────────────────────────

func TestAdminUsersCacheExpiry_ZeroBeforePopulation(t *testing.T) {
	c := NewPocketIDClient("http://localhost", "key")
	exp := c.AdminUsersCacheExpiry()
	if !exp.IsZero() {
		t.Errorf("expected zero time before cache population, got %v", exp)
	}
}

// ── NilClient additional safety ──────────────────────────────────────────────

func TestNilClient_UsersWithSSHKeys(t *testing.T) {
	var c *PocketIDClient
	users, err := c.UsersWithSSHKeys()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if users != nil {
		t.Errorf("expected nil, got %v", users)
	}
}

func TestNilClient_AllAdminUsers(t *testing.T) {
	var c *PocketIDClient
	users, err := c.AllAdminUsers()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if users != nil {
		t.Errorf("expected nil, got %v", users)
	}
}

func TestNilClient_AllAdminGroups(t *testing.T) {
	var c *PocketIDClient
	groups, err := c.AllAdminGroups()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if groups != nil {
		t.Errorf("expected nil, got %v", groups)
	}
}

func TestNilClient_CachedAdminUsers(t *testing.T) {
	var c *PocketIDClient
	users, err := c.CachedAdminUsers()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if users != nil {
		t.Errorf("expected nil, got %v", users)
	}
}

func TestNilClient_FetchDirectory(t *testing.T) {
	var c *PocketIDClient
	dir, err := c.FetchDirectory()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// nil client returns an empty directory (not nil) because AllAdminUsers returns nil, nil
	// and NewUserDirectory is called with empty slices.
	if dir == nil {
		t.Error("expected non-nil directory from nil client")
	}
}
