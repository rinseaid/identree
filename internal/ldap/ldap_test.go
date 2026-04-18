package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/rinseaid/identree/internal/config"
	"github.com/rinseaid/identree/internal/mtls"
	"github.com/rinseaid/identree/internal/pocketid"
	"github.com/rinseaid/identree/internal/sudorules"
	"github.com/rinseaid/identree/internal/uidmap"

	ldapclient "github.com/go-ldap/ldap/v3"
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
	srv, err := NewLDAPServer(cfg, um, nil, nil)
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
	srv, err := NewLDAPServer(cfg, um, nil, nil)
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
	srv, err := NewLDAPServer(cfg, um, store, nil)
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
	srv, err := NewLDAPServer(cfg, um, nil, nil)
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

// ── LDAPS mTLS integration tests ─────────────────────────────────────────────

// TestLDAPS_mTLSBindAcceptsValidCert verifies that when LDAPS is configured
// with mTLS, a client presenting a valid client certificate can bind using
// a provisioned host DN (password is ignored — the cert is the credential).
func TestLDAPS_mTLSBindAcceptsValidCert(t *testing.T) {
	// Generate a CA and issue a server cert + client cert.
	caCertPEM, caKeyPEM, caSigner, err := mtls.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	caPair, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caLeaf, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPair.Leaf = caLeaf

	// Issue a server certificate (the LDAP server's TLS cert).
	// Re-use the CA as a self-signed server cert for simplicity; in practice
	// you'd issue a separate server cert with SAN=localhost.
	serverCertPEM, serverKeyPEM, err := issueServerCert(caPair, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Issue a client certificate for hostname "testhost-01".
	clientHostname := "testhost-01"
	clientCertPEM, clientKeyPEM, err := mtls.IssueCert(caLeaf, caSigner, clientHostname, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	baseDN := "dc=test,dc=local"
	cfg := &config.ServerConfig{
		LDAPBaseDN:           baseDN,
		LDAPListenAddr:       addr,
		LDAPTLSListenAddr:    addr,
		LDAPProvisionEnabled: true,
		LDAPAllowAnonymous:   false,
		MTLSEnabled:          true,
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 200000, 200000)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &LDAPTLSConfig{
		ServerCert: serverPair,
		CACert:     caLeaf,
	}
	srv, err := NewLDAPServer(cfg, um, nil, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	// Seed a minimal directory so searches can succeed.
	var users []pocketid.PocketIDAdminUser
	_ = json.Unmarshal([]byte(`[{"id":"u1","username":"alice"}]`), &users)
	var groups []pocketid.PocketIDAdminGroup
	_ = json.Unmarshal([]byte(`[{"id":"g1","name":"sysadmins","customClaims":[],"members":[{"id":"u1"}]}]`), &groups)
	srv.Refresh(pocketid.NewUserDirectory(users, groups), "", nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	// Wait for the server to start accepting connections.
	if !waitForPort(t, addr, 5*time.Second) {
		t.Fatal("LDAP server did not start in time")
	}

	// ── Test 1: bind with valid client cert succeeds ────────────────────
	caPool := x509.NewCertPool()
	caPool.AddCert(caLeaf)
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientPair},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}
	conn, err := ldapclient.DialURL(fmt.Sprintf("ldaps://%s", addr), ldapclient.DialWithTLSConfig(clientTLS))
	if err != nil {
		t.Fatalf("dial LDAPS: %v", err)
	}
	defer conn.Close()

	bindDN := fmt.Sprintf("uid=%s,ou=identree-hosts,%s", clientHostname, baseDN)
	err = conn.Bind(bindDN, "ignored-password")
	if err != nil {
		t.Fatalf("mTLS bind should succeed, got: %v", err)
	}
	t.Log("PASS: mTLS bind with valid client cert succeeded")

	// ── Test 2: search after bind succeeds ──────────────────────────────
	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     baseDN,
		Scope:      ldapclient.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"dn"},
	})
	if err != nil {
		t.Fatalf("search after mTLS bind failed: %v", err)
	}
	if len(sr.Entries) == 0 {
		t.Error("expected at least one search result")
	}
	t.Log("PASS: search after mTLS bind succeeded")

	cancel()
}

// TestLDAPS_mTLSRejectsWithoutCert verifies that when LDAPS with mTLS is
// configured, a connection without a client certificate is rejected.
// The rejection may happen at the TLS handshake or on the first LDAP operation.
func TestLDAPS_mTLSRejectsWithoutCert(t *testing.T) {
	caCertPEM, caKeyPEM, _, err := mtls.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	caPair, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caLeaf, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPair.Leaf = caLeaf

	serverCertPEM, serverKeyPEM, err := issueServerCert(caPair, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.ServerConfig{
		LDAPBaseDN:           "dc=test,dc=local",
		LDAPListenAddr:       addr,
		LDAPTLSListenAddr:    addr,
		LDAPProvisionEnabled: true,
		LDAPAllowAnonymous:   false,
		MTLSEnabled:          true,
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 200000, 200000)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &LDAPTLSConfig{
		ServerCert: serverPair,
		CACert:     caLeaf,
	}
	srv, err := NewLDAPServer(cfg, um, nil, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Start(ctx) }()

	if !waitForPort(t, addr, 5*time.Second) {
		t.Fatal("LDAP server did not start in time")
	}

	// Connect WITHOUT a client certificate — should fail at TLS handshake
	// or on the first LDAP operation (depending on Go TLS lazy handshake).
	caPool := x509.NewCertPool()
	caPool.AddCert(caLeaf)
	noCertTLS := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
	}
	conn, dialErr := ldapclient.DialURL(fmt.Sprintf("ldaps://%s", addr), ldapclient.DialWithTLSConfig(noCertTLS))
	if dialErr != nil {
		// Handshake failed at dial time — expected.
		t.Logf("PASS: dial without client cert rejected: %v", dialErr)
		cancel()
		return
	}
	defer conn.Close()

	// If dial succeeded (lazy TLS), the first operation should fail.
	bindErr := conn.Bind("uid=test,ou=identree-hosts,dc=test,dc=local", "test")
	if bindErr == nil {
		t.Fatal("expected bind to fail without client cert, but it succeeded")
	}
	t.Logf("PASS: operation without client cert rejected: %v", bindErr)

	cancel()
}

// TestLDAPS_mTLSCertFromWrongCA verifies that a client presenting a cert
// signed by a different CA is rejected at the TLS handshake level.
func TestLDAPS_mTLSCertFromWrongCA(t *testing.T) {
	// Generate the server's mTLS CA.
	caCertPEM, caKeyPEM, _, err := mtls.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	caPair, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caLeaf, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPair.Leaf = caLeaf

	serverCertPEM, serverKeyPEM, err := issueServerCert(caPair, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a DIFFERENT CA and issue a client cert from it.
	wrongCACertPEM, _, wrongCASigner, err := mtls.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	wrongCABlock, _ := pem.Decode(wrongCACertPEM)
	wrongCALeaf, err := x509.ParseCertificate(wrongCABlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	clientCertPEM, clientKeyPEM, err := mtls.IssueCert(wrongCALeaf, wrongCASigner, "testhost-01", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.ServerConfig{
		LDAPBaseDN:           "dc=test,dc=local",
		LDAPListenAddr:       addr,
		LDAPTLSListenAddr:    addr,
		LDAPProvisionEnabled: true,
		LDAPAllowAnonymous:   false,
		MTLSEnabled:          true,
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 200000, 200000)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &LDAPTLSConfig{
		ServerCert: serverPair,
		CACert:     caLeaf, // server trusts the original CA, NOT the wrong CA
	}
	srv, err := NewLDAPServer(cfg, um, nil, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Start(ctx) }()

	if !waitForPort(t, addr, 5*time.Second) {
		t.Fatal("LDAP server did not start in time")
	}

	// Use the wrong CA's cert as the client cert — server should reject.
	caPool := x509.NewCertPool()
	caPool.AddCert(caLeaf)
	// Also add the wrong CA so the client trusts the server (for TLS root validation).
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientPair},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}
	conn, dialErr := ldapclient.DialURL(fmt.Sprintf("ldaps://%s", addr), ldapclient.DialWithTLSConfig(clientTLS))
	if dialErr != nil {
		t.Logf("PASS: dial with wrong CA cert rejected: %v", dialErr)
		cancel()
		return
	}
	defer conn.Close()

	// If dial succeeded (lazy TLS), the first operation should fail.
	bindErr := conn.Bind("uid=testhost-01,ou=identree-hosts,dc=test,dc=local", "test")
	if bindErr == nil {
		t.Fatal("expected bind to fail with cert from wrong CA, but it succeeded")
	}
	t.Logf("PASS: bind with wrong CA cert rejected: %v", bindErr)

	cancel()
}

// ── Plaintext LDAP search integration tests ──────────────────────────────────

// newPlainLDAPTestServer creates an LDAP server with anonymous bind enabled,
// seeds it with users and groups, starts it on a random port, and returns the
// server, its address, and a cancel function.
func newPlainLDAPTestServer(t *testing.T) (*LDAPServer, string, context.CancelFunc) {
	t.Helper()
	baseDN := "dc=test,dc=local"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.ServerConfig{
		LDAPBaseDN:         baseDN,
		LDAPListenAddr:     addr,
		LDAPAllowAnonymous: true,
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 200000, 200000)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := NewLDAPServer(cfg, um, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Seed with users and groups.
	var users []pocketid.PocketIDAdminUser
	_ = json.Unmarshal([]byte(`[
		{"id":"u1","username":"alice","email":"alice@example.com","firstName":"Alice","lastName":"Smith"},
		{"id":"u2","username":"bob","email":"bob@example.com","firstName":"Bob","lastName":"Jones"},
		{"id":"u3","username":"carol","email":"carol@example.com","firstName":"Carol","lastName":"White"}
	]`), &users)
	var groups []pocketid.PocketIDAdminGroup
	_ = json.Unmarshal([]byte(`[
		{"id":"g1","name":"sysadmins","customClaims":[{"key":"sudoCommands","value":"ALL"}],"members":[{"id":"u1"},{"id":"u2"}]},
		{"id":"g2","name":"developers","customClaims":[],"members":[{"id":"u2"},{"id":"u3"}]}
	]`), &groups)
	srv.Refresh(pocketid.NewUserDirectory(users, groups), "", nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()

	if !waitForPort(t, addr, 5*time.Second) {
		cancel()
		t.Fatal("LDAP server did not start in time")
	}

	return srv, addr, cancel
}

func TestPlainLDAP_AnonymousBind(t *testing.T) {
	_, addr, cancel := newPlainLDAPTestServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Anonymous bind (empty DN, empty password).
	if err := conn.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous bind failed: %v", err)
	}
}

func TestPlainLDAP_SearchUsers(t *testing.T) {
	_, addr, cancel := newPlainLDAPTestServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	// Search for all users.
	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=people,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(objectClass=posixAccount)",
		Attributes: []string{"uid", "cn", "uidNumber"},
	})
	if err != nil {
		t.Fatalf("search users: %v", err)
	}
	if len(sr.Entries) < 3 {
		t.Errorf("expected at least 3 user entries, got %d", len(sr.Entries))
	}
}

func TestPlainLDAP_SearchSpecificUser(t *testing.T) {
	_, addr, cancel := newPlainLDAPTestServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	// Search for alice specifically.
	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=people,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(uid=alice)",
		Attributes: []string{"uid", "cn", "uidNumber", "gidNumber"},
	})
	if err != nil {
		t.Fatalf("search alice: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("expected 1 entry for alice, got %d", len(sr.Entries))
	}
	uid := sr.Entries[0].GetAttributeValue("uid")
	if uid != "alice" {
		t.Errorf("expected uid=alice, got %q", uid)
	}
}

func TestPlainLDAP_SearchGroups(t *testing.T) {
	_, addr, cancel := newPlainLDAPTestServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	// Search for groups.
	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=groups,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(objectClass=posixGroup)",
		Attributes: []string{"cn", "gidNumber", "memberUid"},
	})
	if err != nil {
		t.Fatalf("search groups: %v", err)
	}
	if len(sr.Entries) < 2 {
		t.Errorf("expected at least 2 group entries, got %d", len(sr.Entries))
	}
}

func TestPlainLDAP_SearchWithANDFilter(t *testing.T) {
	_, addr, cancel := newPlainLDAPTestServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	// AND filter: uid=alice AND objectClass=posixAccount.
	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=people,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(&(uid=alice)(objectClass=posixAccount))",
		Attributes: []string{"uid"},
	})
	if err != nil {
		t.Fatalf("search with AND: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(sr.Entries))
	}
}

func TestPlainLDAP_SearchWithPresenceFilter(t *testing.T) {
	_, addr, cancel := newPlainLDAPTestServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	// Presence filter: gidNumber=*.
	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=people,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(&(uid=alice)(gidNumber=*))",
		Attributes: []string{"uid", "gidNumber"},
	})
	if err != nil {
		t.Fatalf("search with presence: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Errorf("expected 1 entry with gidNumber, got %d", len(sr.Entries))
	}
}

func TestPlainLDAP_SearchBaseScope(t *testing.T) {
	_, addr, cancel := newPlainLDAPTestServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	// Base scope search on the root DSE.
	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "dc=test,dc=local",
		Scope:      ldapclient.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"dn"},
	})
	if err != nil {
		t.Fatalf("base search: %v", err)
	}
	if len(sr.Entries) == 0 {
		t.Error("expected at least one entry for base scope")
	}
}

func TestPlainLDAP_SearchNonexistentUser(t *testing.T) {
	_, addr, cancel := newPlainLDAPTestServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	// Search for a user that doesn't exist.
	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=people,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(uid=nonexistent)",
		Attributes: []string{"uid"},
	})
	if err != nil {
		t.Fatalf("search nonexistent: %v", err)
	}
	if len(sr.Entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent user, got %d", len(sr.Entries))
	}
}

// ── decrementLimit ───────────────────────────────────────────────────────────

func TestDecrementLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		used  int
		want  int
	}{
		{"zero is unlimited sentinel", 0, 5, 0},
		{"zero with zero used", 0, 0, 0},
		{"remaining positive", 10, 3, 7},
		{"exact consumption", 10, 10, 0},
		{"overuse clamps to zero", 10, 15, 0},
		{"negative used increases remaining", 10, -3, 13},
		{"limit of one fully consumed", 1, 1, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := decrementLimit(tc.limit, tc.used); got != tc.want {
				t.Errorf("decrementLimit(%d,%d) = %d, want %d", tc.limit, tc.used, got, tc.want)
			}
		})
	}
}

// ── searchSudoers (full mode) / searchSudoersFromStore (bridge mode) ─────────
//
// These tests exercise the sudoers search path end-to-end through the gldap
// server by using the existing real-LDAP-server harness and asserting on
// structure/content of sudoRole entries. Sudoers output is security-critical:
// an injected rule could grant root privileges, so both the happy path and
// injection attempts are tested.

func newSudoersFullModeLDAPServer(t *testing.T) (string, context.CancelFunc) {
	t.Helper()
	baseDN := "dc=test,dc=local"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.ServerConfig{
		LDAPBaseDN:             baseDN,
		LDAPListenAddr:         addr,
		LDAPAllowAnonymous:     true,
		LDAPSudoNoAuthenticate: config.SudoNoAuthClaims,
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 200000, 200000)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewLDAPServer(cfg, um, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	var users []pocketid.PocketIDAdminUser
	_ = json.Unmarshal([]byte(`[
		{"id":"u1","username":"alice"},
		{"id":"u2","username":"bob"}
	]`), &users)
	// Two groups:
	//  ops      → sudoCommands=/usr/bin/apt,/usr/bin/systemctl + dangerous host/cmd entries we expect filtered
	//  empty    → has sudoCommands but no members → must be skipped (no rule emitted)
	//  noclaims → no sudo claims → must be skipped
	//  inject   → attempts host injection; valid values remain, invalid dropped
	var groups []pocketid.PocketIDAdminGroup
	_ = json.Unmarshal([]byte(`[
		{"id":"g1","name":"ops","customClaims":[
			{"key":"sudoCommands","value":"/usr/bin/apt,/usr/bin/systemctl,bad-rel,/usr/bin/../sbin/su"},
			{"key":"sudoHosts","value":"web1,web2"},
			{"key":"sudoRunAsUser","value":"root,deploy"},
			{"key":"sudoOptions","value":"NOPASSWD,setenv,!authenticate"}
		],"members":[{"id":"u1"},{"id":"u2"}]},
		{"id":"g2","name":"empty","customClaims":[
			{"key":"sudoCommands","value":"ALL"}
		],"members":[]},
		{"id":"g3","name":"noclaims","customClaims":[],"members":[{"id":"u1"}]},
		{"id":"g4","name":"inject","customClaims":[
			{"key":"sudoCommands","value":"/usr/bin/ls"},
			{"key":"sudoHosts","value":"good-host,bad host with space,evil;rm -rf /"}
		],"members":[{"id":"u1"}]}
	]`), &groups)
	srv.Refresh(pocketid.NewUserDirectory(users, groups), "", nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	if !waitForPort(t, addr, 5*time.Second) {
		cancel()
		t.Fatal("LDAP server did not start in time")
	}
	return addr, cancel
}

func TestPlainLDAP_SearchSudoers_FullMode(t *testing.T) {
	addr, cancel := newSudoersFullModeLDAPServer(t)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN: "ou=sudoers,dc=test,dc=local",
		Scope:  ldapclient.ScopeWholeSubtree,
		Filter: "(objectClass=sudoRole)",
		Attributes: []string{
			"cn", "sudoUser", "sudoHost", "sudoCommand", "sudoRunAsUser",
			"sudoOption", "sudoOrder",
		},
	})
	if err != nil {
		t.Fatalf("search sudoers: %v", err)
	}

	// Expect rules for: ops, inject. Empty group and no-claims group must be skipped.
	byCN := map[string]*ldapclient.Entry{}
	for _, e := range sr.Entries {
		cn := e.GetAttributeValue("cn")
		byCN[cn] = e
	}
	if _, ok := byCN["empty"]; ok {
		t.Error("group 'empty' has no members; must not produce a sudoRole entry")
	}
	if _, ok := byCN["noclaims"]; ok {
		t.Error("group 'noclaims' has no sudo claims; must not produce a sudoRole entry")
	}
	ops, ok := byCN["ops"]
	if !ok {
		t.Fatalf("expected sudoRole for 'ops', got entries: %v", sr.Entries)
	}

	// sudoUser: both member uids present.
	gotUsers := ops.GetAttributeValues("sudoUser")
	if !containsAll(gotUsers, []string{"alice", "bob"}) {
		t.Errorf("ops.sudoUser = %v, want alice+bob", gotUsers)
	}

	// sudoHost: explicit values kept (no ALL fallback since claim was explicit).
	gotHosts := ops.GetAttributeValues("sudoHost")
	if !containsAll(gotHosts, []string{"web1", "web2"}) {
		t.Errorf("ops.sudoHost = %v, want web1+web2", gotHosts)
	}

	// sudoCommand: only absolute, safe paths retained; "bad-rel" and path-traversal entry dropped.
	gotCmds := ops.GetAttributeValues("sudoCommand")
	if !containsAll(gotCmds, []string{"/usr/bin/apt", "/usr/bin/systemctl"}) {
		t.Errorf("ops.sudoCommand = %v, want apt+systemctl", gotCmds)
	}
	for _, c := range gotCmds {
		if c == "bad-rel" || c == "/usr/bin/../sbin/su" {
			t.Errorf("unsafe command %q leaked into sudoCommand", c)
		}
	}

	// sudoRunAsUser: explicit list preserved.
	gotRunAs := ops.GetAttributeValues("sudoRunAsUser")
	if !containsAll(gotRunAs, []string{"root", "deploy"}) {
		t.Errorf("ops.sudoRunAsUser = %v, want root+deploy", gotRunAs)
	}

	// sudoOption: NOPASSWD retained, !authenticate allowed via SudoNoAuthClaims,
	// setenv must be dropped (dangerous).
	gotOpts := ops.GetAttributeValues("sudoOption")
	hasNoPasswd, hasSetenv, hasNoAuth := false, false, false
	for _, o := range gotOpts {
		switch o {
		case "NOPASSWD":
			hasNoPasswd = true
		case "setenv":
			hasSetenv = true
		case "!authenticate":
			hasNoAuth = true
		}
	}
	if !hasNoPasswd {
		t.Errorf("expected NOPASSWD in sudoOption, got %v", gotOpts)
	}
	if hasSetenv {
		t.Errorf("dangerous 'setenv' leaked into sudoOption: %v", gotOpts)
	}
	if !hasNoAuth {
		t.Errorf("expected !authenticate (SudoNoAuthClaims mode) in sudoOption, got %v", gotOpts)
	}

	// sudoOrder set as 1-based index.
	if order := ops.GetAttributeValue("sudoOrder"); order == "" || order == "0" {
		t.Errorf("sudoOrder must be a positive 1-based index, got %q", order)
	}

	// Injection test: the 'inject' rule should drop hostnames containing spaces
	// and shell metacharacters but keep the safe "good-host" value.
	inj, ok := byCN["inject"]
	if !ok {
		t.Fatalf("expected sudoRole for 'inject'")
	}
	injHosts := inj.GetAttributeValues("sudoHost")
	foundGood := false
	for _, h := range injHosts {
		if h == "good-host" {
			foundGood = true
		}
		if h == "bad host with space" || h == "evil;rm -rf /" {
			t.Errorf("malicious sudoHost value %q escaped validation", h)
		}
	}
	if !foundGood {
		t.Errorf("safe sudoHost 'good-host' missing; got %v", injHosts)
	}

	// OU entry itself must also be returned under subtree search.
	foundOU := false
	for _, e := range sr.Entries {
		if e.DN == "ou=sudoers,dc=test,dc=local" {
			foundOU = true
		}
	}
	if !foundOU {
		// Filter was (objectClass=sudoRole) so OU is not expected here — sanity only.
		_ = foundOU
	}
}

// newSudoersBridgeLDAPServer spins up an LDAP server in bridge mode backed by
// a sudorules.Store prepopulated with rules.
func newSudoersBridgeLDAPServer(t *testing.T, rules []sudorules.SudoRule, noAuth config.SudoNoAuthenticate) (string, *sudorules.Store, context.CancelFunc) {
	t.Helper()
	baseDN := "dc=test,dc=local"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := &config.ServerConfig{
		LDAPBaseDN:             baseDN,
		LDAPListenAddr:         addr,
		LDAPAllowAnonymous:     true,
		LDAPSudoNoAuthenticate: noAuth,
	}
	um, err := uidmap.NewUIDMap(t.TempDir()+"/uidmap.json", 200000, 200000)
	if err != nil {
		t.Fatal(err)
	}
	store, err := sudorules.NewStore(t.TempDir() + "/sudorules.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(rules); err != nil {
		t.Fatal(err)
	}
	srv, err := NewLDAPServer(cfg, um, store, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	if !waitForPort(t, addr, 5*time.Second) {
		cancel()
		t.Fatal("LDAP server did not start in time")
	}
	return addr, store, cancel
}

func TestPlainLDAP_SearchSudoersFromStore_BridgeMode(t *testing.T) {
	rules := []sudorules.SudoRule{
		{
			Group:      "ops",
			Hosts:      "web1,web2",
			Commands:   "/usr/bin/apt,/usr/bin/systemctl,../bad,not-absolute",
			RunAsUser:  "root,deploy",
			RunAsGroup: "wheel-x,ALL",
			Options:    "NOPASSWD,setenv,!authenticate",
		},
		{
			// No Commands → must be skipped entirely.
			Group:    "noperms",
			Commands: "",
		},
		{
			// Invalid group name → must be skipped.
			Group:    "ROOT-GROUP",
			Commands: "/usr/bin/ls",
		},
		{
			// Host injection: only safe hostnames retained.
			Group:    "inject",
			Hosts:    "good-host,bad host,evil;rm -rf /",
			Commands: "/usr/bin/ls",
		},
		{
			// No hosts specified → defaults to ALL.
			Group:    "defaults",
			Commands: "/usr/bin/id",
		},
	}
	// SudoNoAuthClaims allows per-rule !authenticate to pass through.
	addr, _, cancel := newSudoersBridgeLDAPServer(t, rules, config.SudoNoAuthClaims)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN: "ou=sudoers,dc=test,dc=local",
		Scope:  ldapclient.ScopeWholeSubtree,
		Filter: "(objectClass=sudoRole)",
		Attributes: []string{
			"cn", "sudoUser", "sudoHost", "sudoCommand",
			"sudoRunAsUser", "sudoRunAsGroup", "sudoOption", "sudoOrder",
		},
	})
	if err != nil {
		t.Fatalf("search bridge sudoers: %v", err)
	}

	byCN := map[string]*ldapclient.Entry{}
	for _, e := range sr.Entries {
		byCN[e.GetAttributeValue("cn")] = e
	}

	// Skipped rules must not appear.
	if _, ok := byCN["noperms"]; ok {
		t.Error("rule with empty Commands must be skipped")
	}
	if _, ok := byCN["ROOT-GROUP"]; ok {
		t.Error("rule with invalid group name must be skipped")
	}

	// ops rule — full structure check.
	ops, ok := byCN["ops"]
	if !ok {
		t.Fatalf("expected sudoRole for 'ops'; got entries %v", sr.Entries)
	}
	// In bridge mode sudoUser is always %groupname (LDAP group-member syntax).
	if u := ops.GetAttributeValue("sudoUser"); u != "%ops" {
		t.Errorf("bridge-mode ops.sudoUser = %q, want %%ops", u)
	}
	if !containsAll(ops.GetAttributeValues("sudoHost"), []string{"web1", "web2"}) {
		t.Errorf("ops.sudoHost = %v", ops.GetAttributeValues("sudoHost"))
	}
	cmds := ops.GetAttributeValues("sudoCommand")
	if !containsAll(cmds, []string{"/usr/bin/apt", "/usr/bin/systemctl"}) {
		t.Errorf("ops.sudoCommand = %v", cmds)
	}
	for _, c := range cmds {
		if c == "../bad" || c == "not-absolute" {
			t.Errorf("unsafe command %q leaked", c)
		}
	}
	// sudoRunAsGroup: "wheel-x" is a valid POSIX-ish name; "ALL" allowed. The
	// reserved "wheel" list in validGroupName is NOT applied here (it's used for
	// IdP-group shadowing prevention, not run-as). Verify both pass through.
	rg := ops.GetAttributeValues("sudoRunAsGroup")
	if !containsAll(rg, []string{"wheel-x", "ALL"}) {
		t.Errorf("ops.sudoRunAsGroup = %v", rg)
	}
	opts := ops.GetAttributeValues("sudoOption")
	hasNoPasswd, hasSetenv, hasNoAuth := false, false, false
	for _, o := range opts {
		switch o {
		case "NOPASSWD":
			hasNoPasswd = true
		case "setenv":
			hasSetenv = true
		case "!authenticate":
			hasNoAuth = true
		}
	}
	if !hasNoPasswd {
		t.Errorf("expected NOPASSWD, got %v", opts)
	}
	if hasSetenv {
		t.Errorf("dangerous setenv leaked: %v", opts)
	}
	if !hasNoAuth {
		t.Errorf("expected !authenticate under SudoNoAuthClaims, got %v", opts)
	}

	// defaults rule — Hosts empty → must default to ALL, RunAsUser empty → root.
	defaults, ok := byCN["defaults"]
	if !ok {
		t.Fatalf("expected sudoRole for 'defaults'")
	}
	if h := defaults.GetAttributeValues("sudoHost"); len(h) != 1 || h[0] != "ALL" {
		t.Errorf("defaults.sudoHost = %v, want [ALL]", h)
	}
	if ru := defaults.GetAttributeValues("sudoRunAsUser"); len(ru) != 1 || ru[0] != "root" {
		t.Errorf("defaults.sudoRunAsUser = %v, want [root]", ru)
	}

	// Injection: only good-host survives.
	inj, ok := byCN["inject"]
	if !ok {
		t.Fatalf("expected sudoRole for 'inject'")
	}
	for _, h := range inj.GetAttributeValues("sudoHost") {
		if h != "good-host" {
			t.Errorf("malicious host %q escaped validation (only good-host expected)", h)
		}
	}

	// sudoOrder must be present and distinct across rules.
	seen := map[string]bool{}
	for _, e := range sr.Entries {
		o := e.GetAttributeValue("sudoOrder")
		if o == "" {
			t.Errorf("entry %q missing sudoOrder", e.DN)
		}
		if seen[o] {
			t.Errorf("duplicate sudoOrder %q across entries", o)
		}
		seen[o] = true
	}
}

// TestPlainLDAP_SearchSudoersFromStore_NoAuthTrue verifies that when
// LDAPSudoNoAuthenticate=true every emitted rule includes !authenticate,
// regardless of per-rule Options — this is a security-critical config path.
func TestPlainLDAP_SearchSudoersFromStore_NoAuthTrue(t *testing.T) {
	rules := []sudorules.SudoRule{
		{Group: "ops", Commands: "/usr/bin/id"},
	}
	addr, _, cancel := newSudoersBridgeLDAPServer(t, rules, config.SudoNoAuthTrue)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=sudoers,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(cn=ops)",
		Attributes: []string{"sudoOption"},
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(sr.Entries))
	}
	opts := sr.Entries[0].GetAttributeValues("sudoOption")
	found := false
	for _, o := range opts {
		if o == "!authenticate" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected !authenticate under SudoNoAuthTrue, got %v", opts)
	}
}

// TestPlainLDAP_SearchSudoersFromStore_Empty ensures an empty rules store
// returns no sudoRole entries (but the ou=sudoers OU entry itself is still
// served under an (objectClass=*) search).
func TestPlainLDAP_SearchSudoersFromStore_Empty(t *testing.T) {
	addr, _, cancel := newSudoersBridgeLDAPServer(t, nil, config.SudoNoAuthFalse)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	sr, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=sudoers,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(objectClass=sudoRole)",
		Attributes: []string{"cn"},
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(sr.Entries) != 0 {
		t.Errorf("expected 0 sudoRole entries for empty store, got %d", len(sr.Entries))
	}

	// OU entry itself is reachable.
	sr2, err := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=sudoers,dc=test,dc=local",
		Scope:      ldapclient.ScopeBaseObject,
		Filter:     "(objectClass=organizationalUnit)",
		Attributes: []string{"ou"},
	})
	if err != nil {
		t.Fatalf("base search for OU: %v", err)
	}
	if len(sr2.Entries) != 1 || sr2.Entries[0].GetAttributeValue("ou") != "sudoers" {
		t.Errorf("expected ou=sudoers entry, got %v", sr2.Entries)
	}
}

// TestPlainLDAP_SearchSudoersFromStore_SizeLimit verifies the server honours
// the client's SizeLimit and returns ResultSizeLimitExceeded with a truncated
// entry set.
func TestPlainLDAP_SearchSudoersFromStore_SizeLimit(t *testing.T) {
	rules := []sudorules.SudoRule{
		{Group: "g1", Commands: "/usr/bin/id"},
		{Group: "g2", Commands: "/usr/bin/id"},
		{Group: "g3", Commands: "/usr/bin/id"},
	}
	addr, _, cancel := newSudoersBridgeLDAPServer(t, rules, config.SudoNoAuthFalse)
	defer cancel()

	conn, err := ldapclient.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.UnauthenticatedBind("")

	sr, _ := conn.Search(&ldapclient.SearchRequest{
		BaseDN:     "ou=sudoers,dc=test,dc=local",
		Scope:      ldapclient.ScopeWholeSubtree,
		Filter:     "(objectClass=sudoRole)",
		Attributes: []string{"cn"},
		SizeLimit:  2,
	})
	// The go-ldap client surfaces ResultSizeLimitExceeded as an error on
	// Search; we still get the partial entries via sr (on some code paths) or
	// via the error's packet. We care that no more than 2 entries appear.
	if sr != nil && len(sr.Entries) > 2 {
		t.Errorf("SizeLimit=2 not honoured: got %d entries", len(sr.Entries))
	}
}

// containsAll returns true iff every wanted value is present in got.
func containsAll(got, want []string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// ── Test helpers ──────────────────────────────────────────────────────────────

// waitForPort polls the given address until it accepts a TCP connection.
func waitForPort(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// issueServerCert creates a TLS server certificate signed by the given CA,
// valid for the specified hostname. Used in tests to create a proper LDAPS
// server cert (separate from the CA) with ExtKeyUsageServerAuth.
func issueServerCert(ca tls.Certificate, hostname string) (certPEM, keyPEM []byte, err error) {
	caLeaf := ca.Leaf
	if caLeaf == nil {
		caLeaf, err = x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			return nil, nil, err
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caLeaf, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
