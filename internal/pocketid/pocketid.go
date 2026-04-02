package pocketid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rinseaid/identree/internal/sanitize"
)

var sshKeyClaimRe = regexp.MustCompile(`^sshPublicKey\d*$`)

// validAdminIDPattern matches UUID-like identifiers.
// Prevents path traversal in per-group URL construction.
var validAdminIDPattern = regexp.MustCompile(`^[a-fA-F0-9-]{1,128}$`)

// maxPagesPerFetch caps the number of pagination pages fetched in a single
// PocketID API sync to prevent resource exhaustion if the API returns a
// pathologically large TotalPages value.
const maxPagesPerFetch = 500 // 500 pages × 100 items = 50,000 entries max

// PocketIDClient fetches user and group data from the Pocket ID REST API.
type PocketIDClient struct {
	baseURL string
	apiKey  string
	client  *http.Client

	mu          sync.RWMutex
	cachedData  *pocketIDData
	cacheExpiry time.Time
	cacheTTL    time.Duration
	fetchMu     sync.Mutex // separate from cache mu; serializes fetches

	adminUsersMu    sync.Mutex
	cachedAdminUsers    []PocketIDAdminUser
	cachedAdminUsersExp time.Time
}

type pocketIDData struct {
	Groups []pocketIDGroup
	// Keyed by username for fast lookup
	UserGroups map[string][]GroupInfo
}

type pocketIDGroup struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	CustomClaims []pocketIDClaim `json:"customClaims"`
	Users        []pocketIDUser  `json:"users"`
}

type pocketIDClaim struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Claim is an exported key-value custom claim pair.
type Claim = pocketIDClaim

type pocketIDUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// GroupInfo is the per-user view of a group's permissions
type GroupInfo struct {
	Name         string
	SudoCommands string // from sudoCommands claim
	SudoHosts    string // from sudoHosts claim
	SudoRunAs    string // from sudoRunAsUser claim
	AccessHosts  string // from accessHosts claim
}

func NewPocketIDClient(baseURL, apiKey string) *PocketIDClient {
	if baseURL == "" || apiKey == "" {
		return nil
	}
	return &PocketIDClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		cacheTTL: 5 * time.Minute,
	}
}

// GetGroups returns all PocketID groups with their members and custom claims.
// Results are served from the shared 5-minute cache.
func (c *PocketIDClient) GetGroups() ([]pocketIDGroup, error) {
	if c == nil {
		return nil, nil
	}
	c.mu.RLock()
	if c.cachedData != nil && time.Now().Before(c.cacheExpiry) {
		data := c.cachedData.Groups
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	c.mu.RLock()
	if c.cachedData != nil && time.Now().Before(c.cacheExpiry) {
		data := c.cachedData.Groups
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	data, err := c.fetchGroupData()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cachedData = data
	c.cacheExpiry = time.Now().Add(c.cacheTTL)
	c.mu.Unlock()
	return data.Groups, nil
}

func (c *PocketIDClient) GetUserPermissions() (map[string][]GroupInfo, error) {
	if c == nil {
		return nil, nil
	}

	// Check cache
	c.mu.RLock()
	if c.cachedData != nil && time.Now().Before(c.cacheExpiry) {
		data := c.cachedData.UserGroups
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	// Serialize concurrent fetches to prevent cache stampede.
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	// Re-check cache under fetch lock (another goroutine may have just refreshed).
	c.mu.RLock()
	if c.cachedData != nil && time.Now().Before(c.cacheExpiry) {
		data := c.cachedData.UserGroups
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	// Fetch fresh data
	data, err := c.fetchGroupData()
	if err != nil {
		return nil, err
	}

	// Cache it
	c.mu.Lock()
	c.cachedData = data
	c.cacheExpiry = time.Now().Add(c.cacheTTL)
	c.mu.Unlock()

	return data.UserGroups, nil
}

func (c *PocketIDClient) fetchGroupData() (*pocketIDData, error) {
	// Step 1: List all groups
	var allGroups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	page := 1
	for {
		url := fmt.Sprintf("%s/api/user-groups?pagination[page]=%d&pagination[limit]=100", c.baseURL, page)
		resp, err := c.apiGet(url)
		if err != nil {
			return nil, fmt.Errorf("listing groups: %w", err)
		}

		var result struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
			Pagination struct {
				TotalPages int `json:"totalPages"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(resp, &result); err != nil {
			// Try as plain array (some Pocket ID versions that don't paginate).
			// Only attempt this fallback on the first page; if pagination was
			// already in progress a parse failure is a real error.
			if page != 1 {
				return nil, fmt.Errorf("parsing groups page %d: %w", page, err)
			}
			if err2 := json.Unmarshal(resp, &allGroups); err2 != nil {
				return nil, fmt.Errorf("parsing groups: %w", err2)
			}
			break
		}
		allGroups = append(allGroups, result.Data...)
		if page >= result.Pagination.TotalPages || result.Pagination.TotalPages == 0 || page >= maxPagesPerFetch {
			break
		}
		page++
	}

	// Step 2: Fetch each group's details (members + custom claims)
	userGroups := make(map[string][]GroupInfo)
	var groups []pocketIDGroup
	var failed []string

	for _, g := range allGroups {
		if !validAdminIDPattern.MatchString(g.ID) {
			slog.Warn("pocketid: skipping group with invalid ID", "group", sanitize.ForTerminal(g.Name), "id", g.ID)
			failed = append(failed, g.Name)
			continue
		}
		url := fmt.Sprintf("%s/api/user-groups/%s", c.baseURL, g.ID)
		resp, err := c.apiGet(url)
		if err != nil {
			slog.Warn("pocketid: fetching group details failed", "group", sanitize.ForTerminal(g.Name), "err", err)
			failed = append(failed, g.Name)
			continue
		}

		var group pocketIDGroup
		if err := json.Unmarshal(resp, &group); err != nil {
			slog.Warn("pocketid: parsing group details failed", "group", sanitize.ForTerminal(g.Name), "err", err)
			failed = append(failed, g.Name)
			continue
		}

		// Parse custom claims into permissions; strip null bytes to prevent LDAP injection.
		claims := make(map[string]string)
		for _, cl := range group.CustomClaims {
			claims[cl.Key] = strings.ReplaceAll(cl.Value, "\x00", "")
		}

		info := GroupInfo{
			Name:         group.Name,
			SudoCommands: claims["sudoCommands"],
			SudoHosts:    claims["sudoHosts"],
			SudoRunAs:    claims["sudoRunAsUser"],
			AccessHosts:  claims["accessHosts"],
		}

		// Map to each member
		for _, user := range group.Users {
			userGroups[user.Username] = append(userGroups[user.Username], info)
		}

		groups = append(groups, group)
	}

	if len(failed) > 0 {
		return &pocketIDData{Groups: groups, UserGroups: userGroups},
			fmt.Errorf("pocketid: %d group(s) failed to fetch: %v", len(failed), failed)
	}
	return &pocketIDData{Groups: groups, UserGroups: userGroups}, nil
}

// SSHUser is a PocketID user who has at least one sshPublicKey* custom claim.
type SSHUser struct {
	Username string
	Email    string
	SSHKeys  []string // raw public key strings from sshPublicKey* claims
}

// UsersWithSSHKeys returns all PocketID users who have at least one non-empty
// sshPublicKey* custom claim (sshPublicKey, sshPublicKey1 … sshPublicKey99).
// Results are NOT cached — the deploy modal always needs fresh data.
func (c *PocketIDClient) UsersWithSSHKeys() ([]SSHUser, error) {
	if c == nil {
		return nil, nil
	}

	var out []SSHUser
	page := 1
	for {
		url := fmt.Sprintf("%s/api/users?pagination[page]=%d&pagination[limit]=100", c.baseURL, page)
		resp, err := c.apiGet(url)
		if err != nil {
			return nil, fmt.Errorf("listing users: %w", err)
		}

		var result struct {
			Data []struct {
				Username     string          `json:"username"`
				Email        string          `json:"email"`
				CustomClaims []pocketIDClaim `json:"customClaims"`
			} `json:"data"`
			Pagination struct {
				TotalPages int `json:"totalPages"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(resp, &result); err != nil {
			return nil, fmt.Errorf("parsing users: %w", err)
		}

		for _, u := range result.Data {
			var keys []string
			for _, cl := range u.CustomClaims {
				if sshKeyClaimRe.MatchString(cl.Key) && cl.Value != "" {
					keys = append(keys, cl.Value)
				}
			}
			if len(keys) > 0 {
				out = append(out, SSHUser{Username: u.Username, Email: u.Email, SSHKeys: keys})
			}
		}

		if page >= result.Pagination.TotalPages || result.Pagination.TotalPages == 0 || page >= maxPagesPerFetch {
			break
		}
		page++
	}
	return out, nil
}

func (c *PocketIDClient) apiGet(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, sanitize.ForTerminal(string(body)))
	}

	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
}

// ── Admin API (used by LDAP server) ──────────────────────────────────────────
// These methods use the PocketID admin API (/api/admin/*) with the API key
// to fetch comprehensive user/group data for LDAP directory serving.

// PocketIDAdminUser is a user from the admin API (richer than the regular API).
type PocketIDAdminUser struct {
	ID           string  `json:"id"`
	Username     string  `json:"username"`
	Email        string  `json:"email"`
	FirstName    string  `json:"firstName"`
	LastName     string  `json:"lastName"`
	IsAdmin      bool    `json:"isAdmin"`
	CustomClaims []Claim `json:"customClaims"`
	Disabled     bool    `json:"disabled"`
}

// PocketIDAdminGroup is a group from the admin API.
type PocketIDAdminGroup struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	FriendlyName string  `json:"friendlyName"`
	CustomClaims []Claim `json:"customClaims"`
	Members      []struct {
		ID string `json:"id"`
	} `json:"members"`
}

// ClaimsMap returns a key→value map of the group's custom claims.
// Null bytes are stripped from all keys and values to prevent truncation
// attacks in downstream C-based consumers (sudo, NSS, PAM).
func (g *PocketIDAdminGroup) ClaimsMap() map[string]string {
	m := make(map[string]string, len(g.CustomClaims))
	for _, c := range g.CustomClaims {
		m[stripNullBytes(c.Key)] = stripNullBytes(c.Value)
	}
	return m
}

// stripNullBytes removes all null bytes from a string.
func stripNullBytes(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// AllAdminUsers fetches all users via the admin API (auto-paginated).
func (c *PocketIDClient) AllAdminUsers() ([]PocketIDAdminUser, error) {
	if c == nil {
		return nil, nil
	}
	var all []PocketIDAdminUser
	page := 1
	for {
		url := fmt.Sprintf("%s/api/users?pagination[page]=%d&pagination[limit]=100", c.baseURL, page)
		body, err := c.apiGet(url)
		if err != nil {
			return nil, fmt.Errorf("admin users page %d: %w", page, err)
		}
		var result struct {
			Data       []PocketIDAdminUser `json:"data"`
			Pagination struct{ TotalPages int `json:"totalPages"` } `json:"pagination"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("admin users parse: %w", err)
		}
		all = append(all, result.Data...)
		if page >= result.Pagination.TotalPages || result.Pagination.TotalPages == 0 || page >= maxPagesPerFetch {
			break
		}
		page++
	}
	return all, nil
}

// AllAdminGroups fetches all groups via a two-phase approach:
//   - Phase 1: paginate /api/user-groups to collect group IDs and metadata.
//   - Phase 2: fetch each group via /api/user-groups/<id> to get members and custom claims.
//
// The list endpoint returns UserGroupMinimalDto; the detail endpoint returns UserGroupDto with members.
func (c *PocketIDClient) AllAdminGroups() ([]PocketIDAdminGroup, error) {
	if c == nil {
		return nil, nil
	}

	// Phase 1: collect group metadata from the paginated list.
	var phase1 []PocketIDAdminGroup
	page := 1
	for {
		url := fmt.Sprintf("%s/api/user-groups?pagination[page]=%d&pagination[limit]=100", c.baseURL, page)
		body, err := c.apiGet(url)
		if err != nil {
			return nil, fmt.Errorf("admin groups page %d: %w", page, err)
		}
		var result struct {
			Data       []PocketIDAdminGroup `json:"data"`
			Pagination struct{ TotalPages int `json:"totalPages"` } `json:"pagination"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("admin groups parse: %w", err)
		}
		phase1 = append(phase1, result.Data...)
		if page >= result.Pagination.TotalPages || result.Pagination.TotalPages == 0 || page >= maxPagesPerFetch {
			break
		}
		page++
	}

	// Phase 2: fetch each group individually for members and custom claims.
	// Track groups that fail (e.g., transient errors) and return an error if any do,
	// so callers can skip the LDAP refresh rather than accepting partial data.
	var all []PocketIDAdminGroup
	var failed []string
	for _, meta := range phase1 {
		if !validAdminIDPattern.MatchString(meta.ID) {
			slog.Warn("pocketid: skipping group with invalid ID format", "name", sanitize.ForTerminal(meta.Name), "id", meta.ID)
			continue
		}
		groupURL := fmt.Sprintf("%s/api/user-groups/%s", c.baseURL, meta.ID)
		body, err := c.apiGet(groupURL)
		if err != nil {
			slog.Warn("pocketid: failed to fetch group", "name", sanitize.ForTerminal(meta.Name), "err", err)
			failed = append(failed, meta.Name)
			continue
		}
		var g pocketIDGroup
		if err := json.Unmarshal(body, &g); err != nil {
			slog.Warn("pocketid: failed to parse group", "name", sanitize.ForTerminal(meta.Name), "err", err)
			failed = append(failed, meta.Name)
			continue
		}
		var members []struct {
			ID string `json:"id"`
		}
		for _, u := range g.Users {
			members = append(members, struct {
				ID string `json:"id"`
			}{ID: u.ID})
		}
		all = append(all, PocketIDAdminGroup{
			ID:           meta.ID,
			Name:         meta.Name,
			FriendlyName: meta.FriendlyName,
			CustomClaims: g.CustomClaims,
			Members:      members,
		})
	}
	if len(failed) > 0 {
		return all, fmt.Errorf("pocketid: %d group(s) failed to fetch: %v", len(failed), failed)
	}
	return all, nil
}

// UserDirectory is a queryable snapshot of all PocketID users and groups,
// built from the admin API for use by the LDAP server.
type UserDirectory struct {
	Users  []PocketIDAdminUser
	Groups []PocketIDAdminGroup
	// Index maps
	ByUserID   map[string]*PocketIDAdminUser
	ByGroupID  map[string]*PocketIDAdminGroup
	ByUsername map[string]*PocketIDAdminUser
}

// NewUserDirectory builds a queryable directory from raw admin API results.
func NewUserDirectory(users []PocketIDAdminUser, groups []PocketIDAdminGroup) *UserDirectory {
	d := &UserDirectory{
		Users:      users,
		Groups:     groups,
		ByUserID:   make(map[string]*PocketIDAdminUser, len(users)),
		ByGroupID:  make(map[string]*PocketIDAdminGroup, len(groups)),
		ByUsername: make(map[string]*PocketIDAdminUser, len(users)),
	}
	for i := range users {
		u := &d.Users[i]
		d.ByUserID[u.ID] = u
		d.ByUsername[u.Username] = u
	}
	for i := range groups {
		g := &d.Groups[i]
		d.ByGroupID[g.ID] = g
	}
	return d
}

// FetchDirectory fetches users and groups from PocketID and returns
// a queryable UserDirectory snapshot. Returns an error if either API call fails.
func (c *PocketIDClient) FetchDirectory() (*UserDirectory, error) {
	users, err := c.AllAdminUsers()
	if err != nil {
		return nil, fmt.Errorf("pocketid: fetch users: %w", err)
	}
	groups, err := c.AllAdminGroups()
	if err != nil {
		return nil, fmt.Errorf("pocketid: fetch groups: %w", err)
	}
	return NewUserDirectory(users, groups), nil
}

// ── Claims write API ─────────────────────────────────────────────────────────

// CachedAdminUsers returns all admin users, served from a 5-minute cache.
func (c *PocketIDClient) CachedAdminUsers() ([]PocketIDAdminUser, error) {
	if c == nil {
		return nil, nil
	}
	c.adminUsersMu.Lock()
	defer c.adminUsersMu.Unlock()
	if c.cachedAdminUsers != nil && time.Now().Before(c.cachedAdminUsersExp) {
		return c.cachedAdminUsers, nil
	}
	users, err := c.AllAdminUsers()
	if err != nil {
		return nil, err
	}
	c.cachedAdminUsers = users
	c.cachedAdminUsersExp = time.Now().Add(c.cacheTTL)
	return users, nil
}

// GetUserIDs returns a username→PocketID-ID map built from cached group member data.
// Only users who are members of at least one group are included.
func (c *PocketIDClient) GetUserIDs() (map[string]string, error) {
	if c == nil {
		return nil, nil
	}
	groups, err := c.GetGroups()
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	for _, g := range groups {
		for _, u := range g.Users {
			if u.Username != "" && u.ID != "" {
				m[u.Username] = u.ID
			}
		}
	}
	return m, nil
}

// GetAdminUserByID fetches a single user by ID from the Pocket ID admin API.
func (c *PocketIDClient) GetAdminUserByID(userID string) (*PocketIDAdminUser, error) {
	if c == nil {
		return nil, fmt.Errorf("pocketid client not configured")
	}
	if !validAdminIDPattern.MatchString(userID) {
		return nil, fmt.Errorf("invalid user ID format")
	}
	url := fmt.Sprintf("%s/api/users/%s", c.baseURL, userID)
	body, err := c.apiGet(url)
	if err != nil {
		return nil, err
	}
	var u PocketIDAdminUser
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("parse user: %w", err)
	}
	return &u, nil
}

// GetAdminGroupByID fetches a single group by ID from the Pocket ID admin API.
func (c *PocketIDClient) GetAdminGroupByID(groupID string) (*PocketIDAdminGroup, error) {
	if c == nil {
		return nil, fmt.Errorf("pocketid client not configured")
	}
	if !validAdminIDPattern.MatchString(groupID) {
		return nil, fmt.Errorf("invalid group ID format")
	}
	url := fmt.Sprintf("%s/api/user-groups/%s", c.baseURL, groupID)
	body, err := c.apiGet(url)
	if err != nil {
		return nil, err
	}
	var raw struct {
		ID           string  `json:"id"`
		Name         string  `json:"name"`
		FriendlyName string  `json:"friendlyName"`
		CustomClaims []Claim `json:"customClaims"`
		Users        []struct {
			ID string `json:"id"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse group: %w", err)
	}
	return &PocketIDAdminGroup{
		ID:           raw.ID,
		Name:         raw.Name,
		FriendlyName: raw.FriendlyName,
		CustomClaims: raw.CustomClaims,
		Members:      raw.Users,
	}, nil
}

// apiPut sends a PUT request with a JSON body to the Pocket ID API.
func (c *PocketIDClient) apiPut(urlStr string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPut, urlStr, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, sanitize.ForTerminal(string(body)))
	}
	// Drain the body so the connection can be reused.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return nil
}

// PutUserClaims replaces all custom claims for a user via PUT /api/custom-claims/user/{id}.
func (c *PocketIDClient) PutUserClaims(userID string, claims []Claim) error {
	if c == nil {
		return fmt.Errorf("pocketid client not configured")
	}
	if !validAdminIDPattern.MatchString(userID) {
		return fmt.Errorf("invalid user ID format")
	}
	url := fmt.Sprintf("%s/api/custom-claims/user/%s", c.baseURL, userID)
	return c.apiPut(url, claims)
}

// PutGroupClaims replaces all custom claims for a group via PUT /api/custom-claims/user-group/{id}.
func (c *PocketIDClient) PutGroupClaims(groupID string, claims []Claim) error {
	if c == nil {
		return fmt.Errorf("pocketid client not configured")
	}
	if !validAdminIDPattern.MatchString(groupID) {
		return fmt.Errorf("invalid group ID format")
	}
	url := fmt.Sprintf("%s/api/custom-claims/user-group/%s", c.baseURL, groupID)
	return c.apiPut(url, claims)
}

// InvalidateCache clears all cached data so the next request fetches fresh data.
func (c *PocketIDClient) InvalidateCache() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.cachedData = nil
	c.mu.Unlock()
	c.adminUsersMu.Lock()
	c.cachedAdminUsers = nil
	c.adminUsersMu.Unlock()
}
