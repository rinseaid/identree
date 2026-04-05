package ldap

import (
	"encoding/json"
	"testing"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/pocketid"
	"github.com/rinseaid/identree/internal/sudorules"
	"github.com/rinseaid/identree/internal/uidmap"
)

// ── isValidGroupName ──────────────────────────────────────────────────────────

func TestIsValidGroupName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid simple", "sysadmins", true},
		{"valid with hyphen", "web-admins", true},
		{"valid with dot", "ops.team", true},
		{"valid with underscore", "db_users", true},
		{"valid leading underscore", "_special", true},
		{"reserved root", "root", false},
		{"reserved wheel", "wheel", false},
		{"reserved sudo", "sudo", false},
		{"reserved admin", "admin", false},
		{"reserved docker", "docker", false},
		{"reserved all", "all", false},
		{"uppercase", "OpsTeam", false},
		{"leading digit", "1ops", false},
		{"too long", string(make([]byte, 257)), false},
		{"empty", "", false},
		{"path traversal", "../etc", false},
		{"with slash", "a/b", false},
		{"case insensitive reserved", "ROOT", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidGroupName(tc.input); got != tc.want {
				t.Errorf("isValidGroupName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ── validSudoCommand ─────────────────────────────────────────────────────────

func TestValidSudoCommand(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"absolute path", "/usr/bin/apt", true},
		{"ALL keyword", "ALL", true},
		{"with args", "/usr/bin/systemctl restart nginx", true},
		{"empty", "", false},
		{"whitespace only", "   ", false},
		{"relative path", "apt", false},
		{"negation", "!/usr/bin/apt", false},
		{"path traversal", "/usr/bin/../sbin/su", false},
		{"sudoedit bare", "sudoedit", false},
		{"sudoedit with space", "sudoedit /etc/hosts", false},
		{"sudoedit upper", "SUDOEDIT", false},
		{"null byte", "/usr/bin/\x00id", false},
		{"newline", "/usr/bin/apt\n", false},
		{"carriage return", "/usr/bin/apt\r", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := validSudoCommand(tc.input); got != tc.want {
				t.Errorf("validSudoCommand(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ── isSafeSudoOption ─────────────────────────────────────────────────────────

func TestIsSafeSudoOption(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"NOPASSWD", "NOPASSWD", true},
		{"LOG_INPUT", "LOG_INPUT", true},
		{"empty", "", false},
		{"authenticate blocked", "authenticate", false},
		{"!authenticate blocked", "!authenticate", false},
		{"setenv blocked", "setenv", false},
		{"!env_reset blocked", "!env_reset", false},
		{"env_keep LD_PRELOAD blocked", "env_keep+=LD_PRELOAD", false},
		{"env_keep PATH blocked", "env_keep+=PATH", false},
		{"env_keep HOME blocked", "env_keep+=HOME", false},
		{"secure_path blocked", "secure_path=/usr/bin", false},
		{"!noexec blocked", "!noexec", false},
		{"newline injection", "NOPASSWD\n", false},
		{"carriage return", "NOPASSWD\r", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSafeSudoOption(tc.input); got != tc.want {
				t.Errorf("isSafeSudoOption(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ── isNoAuthOption ───────────────────────────────────────────────────────────

func TestIsNoAuthOption(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"!authenticate", true},
		{"authenticate", true},
		{"  !authenticate  ", true},
		{"NOPASSWD", false},
		{"", false},
		{"!authenticate\n", false},  // control char bypass — must not match
		{"authenticate\r", false},
		{"!authenticate\x00", false},
	}
	for _, tc := range tests {
		if got := isNoAuthOption(tc.input); got != tc.want {
			t.Errorf("isNoAuthOption(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ── splitComma ───────────────────────────────────────────────────────────────

func TestSplitComma(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b , c ", []string{"a", "b", "c"}},
		{",,a,,", []string{"a"}},
	}
	for _, tc := range tests {
		got := splitComma(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("splitComma(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitComma(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

// ── splitClaim ───────────────────────────────────────────────────────────────

func TestSplitClaim(t *testing.T) {
	claims := map[string]string{
		"hosts":    "web1, web2",
		"empty":    "",
		"single":   "web1",
	}
	if got := splitClaim(claims, "hosts"); len(got) != 2 || got[0] != "web1" || got[1] != "web2" {
		t.Errorf("unexpected: %v", got)
	}
	if got := splitClaim(claims, "empty"); got != nil {
		t.Errorf("expected nil for empty value, got %v", got)
	}
	if got := splitClaim(claims, "missing"); got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

// ── escapeDNValue ────────────────────────────────────────────────────────────

func TestEscapeDNValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with,comma", `with\,comma`},
		{"with+plus", `with\+plus`},
		{"#leading", `\#leading`},
		{"trailing ", `trailing\ `},
		{" leading", `\ leading`},
		{"null\x00byte", `null\00byte`},
	}
	for _, tc := range tests {
		if got := escapeDNValue(tc.input); got != tc.want {
			t.Errorf("escapeDNValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── matchesFilter ────────────────────────────────────────────────────────────

func TestMatchesFilter(t *testing.T) {
	attrs := map[string][]string{
		"objectClass": {"top", "posixAccount"},
		"uid":         {"alice"},
		"cn":          {"Alice Smith"},
		"uidNumber":   {"200001"},
	}
	dn := "uid=alice,ou=people,dc=example,dc=com"

	tests := []struct {
		name   string
		filter string
		want   bool
	}{
		{"empty filter", "", true},
		{"objectClass=*", "(objectClass=*)", true},
		{"equality match", "(uid=alice)", true},
		{"equality no match", "(uid=bob)", false},
		{"presence present", "(uid=*)", true},
		{"presence absent", "(missing=*)", false},
		{"substring contains", "(cn=*Alice*)", true},
		{"substring no match", "(cn=*Bob*)", false},
		{"substring prefix", "(cn=Alice*)", true},
		{"substring suffix", "(cn=*Smith)", true},
		{"AND both match", "(&(uid=alice)(objectClass=posixAccount))", true},
		{"AND one no match", "(&(uid=alice)(objectClass=sudoRole))", false},
		{"OR one match", "(|(uid=alice)(uid=bob))", true},
		{"OR no match", "(|(uid=bob)(uid=carol))", false},
		{"NOT no match", "(!(uid=bob))", true},
		{"NOT match", "(!(uid=alice))", false},
		{"case insensitive value", "(UID=ALICE)", true},
		{"malformed filter", "((bad", false}, // malformed: fail closed
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesFilter(tc.filter, dn, attrs); got != tc.want {
				t.Errorf("matchesFilter(%q) = %v, want %v", tc.filter, got, tc.want)
			}
		})
	}
}

// ── buildUserHostMap ─────────────────────────────────────────────────────────

func TestBuildUserHostMap(t *testing.T) {
	// Use json.Unmarshal to create pocketid types without access to unexported types.
	var users []pocketid.PocketIDAdminUser
	if err := json.Unmarshal([]byte(`[
		{"id":"u1","username":"alice"},
		{"id":"u2","username":"bob"}
	]`), &users); err != nil {
		t.Fatal(err)
	}

	var groups []pocketid.PocketIDAdminGroup
	if err := json.Unmarshal([]byte(`[
		{
			"id":"g1","name":"webdevs",
			"customClaims":[{"key":"accessHosts","value":"web1,web2"}],
			"members":[{"id":"u1"}]
		},
		{
			"id":"g2","name":"dbadmins",
			"customClaims":[{"key":"accessHosts","value":"db1"}],
			"members":[{"id":"u1"},{"id":"u2"}]
		},
		{
			"id":"g3","name":"all-access",
			"customClaims":[{"key":"accessHosts","value":"ALL"}],
			"members":[{"id":"u2"}]
		},
		{
			"id":"g4","name":"dothost",
			"customClaims":[{"key":"accessHosts","value":".example.com"}],
			"members":[{"id":"u2"}]
		},
		{
			"id":"g5","name":"nohost",
			"customClaims":[],
			"members":[{"id":"u1"}]
		}
	]`), &groups); err != nil {
		t.Fatal(err)
	}

	dir := pocketid.NewUserDirectory(users, groups)
	hostMap := buildUserHostMap(groups, dir)

	// alice: web1, web2 (from webdevs), db1 (from dbadmins) — sorted
	alice := hostMap["alice"]
	if len(alice) != 3 {
		t.Fatalf("alice: expected 3 hosts, got %v", alice)
	}
	if alice[0] != "db1" || alice[1] != "web1" || alice[2] != "web2" {
		t.Errorf("alice: unexpected hosts %v", alice)
	}

	// bob: db1 only (ALL and .example.com are rejected)
	bob := hostMap["bob"]
	if len(bob) != 1 || bob[0] != "db1" {
		t.Errorf("bob: expected [db1], got %v", bob)
	}
}

func TestBuildUserHostMap_Deduplicate(t *testing.T) {
	var users []pocketid.PocketIDAdminUser
	_ = json.Unmarshal([]byte(`[{"id":"u1","username":"alice"}]`), &users)

	// Two groups both grant alice access to the same host.
	var groups []pocketid.PocketIDAdminGroup
	_ = json.Unmarshal([]byte(`[
		{"id":"g1","name":"grpa","customClaims":[{"key":"accessHosts","value":"web1"}],"members":[{"id":"u1"}]},
		{"id":"g2","name":"grpb","customClaims":[{"key":"accessHosts","value":"web1"}],"members":[{"id":"u1"}]}
	]`), &groups)

	dir := pocketid.NewUserDirectory(users, groups)
	hostMap := buildUserHostMap(groups, dir)
	alice := hostMap["alice"]
	if len(alice) != 1 || alice[0] != "web1" {
		t.Errorf("expected deduplicated [web1], got %v", alice)
	}
}

// ── validatedSudoHostOrUser ──────────────────────────────────────────────────

func TestValidatedSudoHostOrUser(t *testing.T) {
	// Empty claim → default
	claims := map[string]string{}
	if got := validatedSudoHostOrUser(claims, "sudoHosts", "ALL"); len(got) != 1 || got[0] != "ALL" {
		t.Errorf("expected [ALL], got %v", got)
	}

	// Valid values pass through
	claims["sudoHosts"] = "server1,server2"
	if got := validatedSudoHostOrUser(claims, "sudoHosts", "ALL"); len(got) != 2 {
		t.Errorf("expected 2 hosts, got %v", got)
	}

	// All invalid → nil (fail-closed)
	claims["sudoHosts"] = "bad host,with space"
	if got := validatedSudoHostOrUser(claims, "sudoHosts", "ALL"); got != nil {
		t.Errorf("expected nil for all-invalid hosts, got %v", got)
	}
}

// ── hasSudoClaims ────────────────────────────────────────────────────────────

func TestHasSudoClaims(t *testing.T) {
	if hasSudoClaims(map[string]string{}) {
		t.Error("expected false for empty claims")
	}
	if !hasSudoClaims(map[string]string{"sudoCommands": "/usr/bin/apt"}) {
		t.Error("expected true when sudoCommands is set")
	}
	if !hasSudoClaims(map[string]string{"sudoHosts": "web1"}) {
		t.Error("expected true when sudoHosts is set")
	}
}

// ── isValidGroupName edge cases ───────────────────────────────────────────────

func TestIsValidGroupName_InvalidUTF8(t *testing.T) {
	// Invalid UTF-8 byte sequence must be rejected.
	if isValidGroupName("\xff\xfe") {
		t.Error("expected false for invalid UTF-8")
	}
}

// ── normalizeSudoOption ───────────────────────────────────────────────────────

func TestNormalizeSudoOption(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"NOPASSWD", "NOPASSWD"},
		{"NO PASSWD", "NOPASSWD"},
		{`"NOPASSWD"`, "NOPASSWD"},
		{"'LOG_INPUT'", "LOG_INPUT"},
		{"LOG\tINPUT", "LOGINPUT"},
	}
	for _, tc := range tests {
		if got := normalizeSudoOption(tc.input); got != tc.want {
			t.Errorf("normalizeSudoOption(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── ldapSubstringMatch ────────────────────────────────────────────────────────

func TestLdapSubstringMatch(t *testing.T) {
	tests := []struct {
		value   string
		pattern string
		want    bool
	}{
		{"alice", "alice", true},          // no wildcard — exact match
		{"alice", "bob", false},           // no wildcard — no match
		{"alice smith", "*alice*", true},  // contains
		{"alice smith", "*bob*", false},   // contains — no match
		{"alice", "alice*", true},         // prefix match
		{"alice", "bob*", false},          // prefix — no match
		{"alice", "*alice", true},         // suffix match
		{"alice", "*bob", false},          // suffix — no match
		{"abc", "*b*", true},              // middle wildcard
		{"abc", "*x*", false},             // middle wildcard — no match
		{"alice", "a*e", true},            // both anchor
		{"alice", "a*z", false},           // both anchor — no match
	}
	for _, tc := range tests {
		if got := ldapSubstringMatchRaw(tc.value, tc.pattern); got != tc.want {
			t.Errorf("ldapSubstringMatchRaw(%q, %q) = %v, want %v", tc.value, tc.pattern, got, tc.want)
		}
	}
}

// ── RFC 4515 escape sequences ─────────────────────────────────────────────────

func TestRFC4515FilterValues(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		attrs  map[string][]string
		want   bool
	}{
		{
			name:   "escaped asterisk is equality not wildcard",
			filter: "(uid=alice\\2a)",
			attrs:  map[string][]string{"uid": {"alice*"}},
			want:   true, // \2a unescapes to literal *, equality match succeeds
		},
		{
			name:   "escaped asterisk does not match as wildcard",
			filter: "(uid=alice\\2a)",
			attrs:  map[string][]string{"uid": {"alicebob"}},
			want:   false, // literal 'alice*' != 'alicebob'
		},
		{
			name:   "unescaped asterisk is wildcard",
			filter: "(uid=alice*)",
			attrs:  map[string][]string{"uid": {"alicebob"}},
			want:   true, // alice* wildcard matches alicebob
		},
		{
			name:   "escaped paren in value",
			filter: "(cn=test\\28group\\29)",
			attrs:  map[string][]string{"cn": {"test(group)"}},
			want:   true, // \28 = (, \29 = )
		},
		{
			name:   "escaped backslash in value",
			filter: "(cn=path\\5cfile)",
			attrs:  map[string][]string{"cn": {"path\\file"}},
			want:   true, // \5c = backslash
		},
		{
			name:   "escaped star in substring pattern",
			filter: "(uid=al\\2a*)",
			attrs:  map[string][]string{"uid": {"al*bob"}},
			want:   true, // initial='al*', matches values starting with literal 'al*'
		},
		{
			name:   "case insensitive equality match",
			filter: "(uid=Alice)",
			attrs:  map[string][]string{"uid": {"alice"}},
			want:   true,
		},
		{
			name:   "null byte escape sequence",
			filter: "(cn=foo\\00bar)",
			attrs:  map[string][]string{"cn": {"foo\x00bar"}},
			want:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesFilter(tc.filter, "", tc.attrs)
			if got != tc.want {
				t.Errorf("matchesFilter(%q) = %v, want %v", tc.filter, got, tc.want)
			}
		})
	}
}

// ── evalFilterStr edge cases ──────────────────────────────────────────────────

func TestEvalFilterStr_BareAttr(t *testing.T) {
	// bare attr=value (no parens)
	attrs := map[string][]string{"uid": {"alice"}}
	ok, rest := evalFilterStr("uid=alice", attrs, 0)
	if !ok || rest != "" {
		t.Errorf("bare attr=value: got ok=%v rest=%q", ok, rest)
	}
}

func TestEvalFilterStr_Empty(t *testing.T) {
	ok, rest := evalFilterStr("", map[string][]string{}, 0)
	if !ok || rest != "" {
		t.Errorf("empty: got ok=%v rest=%q", ok, rest)
	}
}

func TestEvalAnd_NoParens(t *testing.T) {
	// evalAnd with content that doesn't start with ( — should return true immediately
	result := evalAnd("uid=alice", map[string][]string{"uid": {"alice"}}, 0)
	if !result {
		t.Error("evalAnd with no-paren content should return true")
	}
}

func TestEvalOr_NoParens(t *testing.T) {
	// evalOr with content that doesn't start with ( — should return false (no match found)
	result := evalOr("uid=alice", map[string][]string{"uid": {"alice"}}, 0)
	if result {
		t.Error("evalOr with no-paren content should return false (no term evaluated)")
	}
}

func TestEvalSimple_NoEquals(t *testing.T) {
	// expression without '=' is unparseable — fail closed
	if evalSimple("noequalssign", map[string][]string{}) {
		t.Error("expected false for unparseable expression (fail closed)")
	}
}

// ── firstDC ───────────────────────────────────────────────────────────────────

func TestFirstDC(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"dc=example,dc=com", "example"},
		// SplitN(baseDN, ",", 2) gives ["ou=people", "dc=example,dc=com"] — the
		// second element starts with "dc=" so the full remainder is returned.
		{"ou=people,dc=example,dc=com", "example,dc=com"},
		{"dc=corp", "corp"},
		{"nodchere", "nodchere"}, // no dc= → return as-is
	}
	for _, tc := range tests {
		if got := firstDC(tc.input); got != tc.want {
			t.Errorf("firstDC(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── buildMemberUids / buildMemberDNs ─────────────────────────────────────────

func TestBuildMemberUids(t *testing.T) {
	var users []pocketid.PocketIDAdminUser
	_ = json.Unmarshal([]byte(`[{"id":"u1","username":"alice"},{"id":"u2","username":"bob"}]`), &users)
	dir := pocketid.NewUserDirectory(users, nil)

	members := []struct{ ID string `json:"id"` }{{"u1"}, {"u2"}, {"u99"}}
	got := buildMemberUids(members, dir)
	if len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Errorf("unexpected uids: %v", got)
	}
}

func TestBuildMemberDNs(t *testing.T) {
	var users []pocketid.PocketIDAdminUser
	_ = json.Unmarshal([]byte(`[{"id":"u1","username":"alice"}]`), &users)
	dir := pocketid.NewUserDirectory(users, nil)

	members := []struct{ ID string `json:"id"` }{{"u1"}}
	got := buildMemberDNs(members, dir, "ou=people,dc=example,dc=com")
	if len(got) != 1 || got[0] != "uid=alice,ou=people,dc=example,dc=com" {
		t.Errorf("unexpected dns: %v", got)
	}
}

func TestBuildMemberDNs_DNEscaping(t *testing.T) {
	// Username with RFC 4514 special characters must be escaped in the DN.
	var users []pocketid.PocketIDAdminUser
	_ = json.Unmarshal([]byte(`[{"id":"u1","username":"alice,admin"}]`), &users)
	dir := pocketid.NewUserDirectory(users, nil)

	members := []struct{ ID string `json:"id"` }{{"u1"}}
	got := buildMemberDNs(members, dir, "ou=people,dc=example,dc=com")
	if len(got) != 1 {
		t.Fatalf("expected 1 DN, got %v", got)
	}
	// The comma in the username must be escaped as \,
	if got[0] != `uid=alice\,admin,ou=people,dc=example,dc=com` {
		t.Errorf("DN not escaped: %q", got[0])
	}
}

// ── NewLDAPServer / Refresh ───────────────────────────────────────────────────

func TestNewLDAPServer(t *testing.T) {
	cfg := &config.ServerConfig{
		LDAPBaseDN:          "dc=example,dc=com",
		LDAPListenAddr:      "127.0.0.1:0",
		LDAPRefreshInterval: 0,
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewLDAPServer(cfg, um, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestRefresh(t *testing.T) {
	cfg := &config.ServerConfig{
		LDAPBaseDN:          "dc=example,dc=com",
		LDAPListenAddr:      "127.0.0.1:0",
		LDAPRefreshInterval: 0,
		LDAPUIDMapFile:      t.TempDir() + "/uidmap.json",
	}
	um, err := uidmap.NewUIDMap(cfg.LDAPUIDMapFile, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewLDAPServer(cfg, um, nil)
	if err != nil {
		t.Fatal(err)
	}

	var users []pocketid.PocketIDAdminUser
	_ = json.Unmarshal([]byte(`[{"id":"u1","username":"alice"}]`), &users)
	var groups []pocketid.PocketIDAdminGroup
	_ = json.Unmarshal([]byte(`[{"id":"g1","name":"sysadmins","customClaims":[],"members":[{"id":"u1"}]}]`), &groups)
	dir := pocketid.NewUserDirectory(users, groups)

	srv.Refresh(dir, "", nil)

	srv.mu.RLock()
	got := srv.dir
	srv.mu.RUnlock()
	if got == nil {
		t.Fatal("dir should be set after Refresh")
	}
	if len(got.Users) != 1 || got.Users[0].Username != "alice" {
		t.Errorf("unexpected dir: %+v", got)
	}
}

func TestNewLDAPServer_BridgeMode(t *testing.T) {
	cfg := &config.ServerConfig{
		LDAPBaseDN:     "dc=example,dc=com",
		LDAPListenAddr: "127.0.0.1:0",
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	store, err := sudorules.NewStore(t.TempDir() + "/sudorules.json")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewLDAPServer(cfg, um, store)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if srv.sudoRules == nil {
		t.Error("expected sudoRules to be set in bridge mode")
	}
}

// ── parseProvisionBindDN ──────────────────────────────────────────────────────

func TestParseProvisionBindDN(t *testing.T) {
	baseDN := "dc=example,dc=com"
	cfg := &config.ServerConfig{
		LDAPBaseDN:     baseDN,
		LDAPListenAddr: "127.0.0.1:0",
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewLDAPServer(cfg, um, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		dn       string
		wantHost string
		wantOK   bool
	}{
		{
			name:     "valid DN with correct base_dn",
			dn:       "uid=web1.example.com,ou=identree-hosts,dc=example,dc=com",
			wantHost: "web1.example.com",
			wantOK:   true,
		},
		{
			name:   "missing uid= prefix",
			dn:     "cn=web1.example.com,ou=identree-hosts,dc=example,dc=com",
			wantOK: false,
		},
		{
			name:   "empty hostname",
			dn:     "uid=,ou=identree-hosts,dc=example,dc=com",
			wantOK: false,
		},
		{
			name:   "wrong ou name",
			dn:     "uid=web1.example.com,ou=hosts,dc=example,dc=com",
			wantOK: false,
		},
		{
			name:     "case-insensitive suffix matching",
			dn:       "uid=web1.example.com,OU=IDENTREE-HOSTS,DC=EXAMPLE,DC=COM",
			wantHost: "web1.example.com",
			wantOK:   true,
		},
		{
			name:   "DN shorter than suffix",
			dn:     "uid=x",
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotHost, gotOK := srv.parseProvisionBindDN(tc.dn)
			if gotOK != tc.wantOK {
				t.Errorf("parseProvisionBindDN(%q) ok = %v, want %v", tc.dn, gotOK, tc.wantOK)
			}
			if gotOK && gotHost != tc.wantHost {
				t.Errorf("parseProvisionBindDN(%q) hostname = %q, want %q", tc.dn, gotHost, tc.wantHost)
			}
		})
	}
}
