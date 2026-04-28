package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	challpkg "github.com/rinseaid/identree/internal/challenge"
	"github.com/rinseaid/identree/internal/notify"
	"github.com/rinseaid/identree/internal/randutil"
)

// deployTimeout is the maximum time a single deploy operation may run.
const deployTimeout = 3 * time.Minute

// deployMaxOutput caps the number of bytes stored per job to prevent OOM.
const deployMaxOutput = 1 << 20 // 1 MB

// deployMaxConcurrent limits simultaneous SSH deploy operations.
const deployMaxConcurrent = 3

// deployIPCooldown is the minimum interval between deploys from the same IP.
const deployIPCooldown = 15 * time.Second

// deployRequestMaxBody caps the deploy request body (private keys can be large).
const deployRequestMaxBody = 65536 // 64 KB

// deploySSEKeepalive is the interval between SSE keepalive comments on streaming endpoints.
const deploySSEKeepalive = 30 * time.Second

// deploySemaphore limits concurrent deploy operations server-wide.
var deploySemaphore = make(chan struct{}, deployMaxConcurrent)

// deployJobTTL is how long completed jobs are retained in memory before cleanup.
const deployJobTTL = time.Hour

// deployJob tracks a running or completed remote-install job.
type deployJob struct {
	id        string
	host      string
	sshUser   string
	initiator string // admin username who started this job
	createdAt time.Time

	mu      sync.Mutex
	cond    *sync.Cond // broadcast when new output arrives or job finishes
	buf     bytes.Buffer
	done    bool
	failed  bool
	readers int32 // active SSE stream readers; checked by TTL cleanup
}

func newDeployJob(id, host, sshUser, initiator string) *deployJob {
	j := &deployJob{
		id:        id,
		host:      host,
		sshUser:   sshUser,
		initiator: initiator,
		createdAt: time.Now(),
	}
	j.cond = sync.NewCond(&j.mu)
	return j
}

// appendOutput appends p to the job's buffer and wakes SSE listeners.
// Silently truncates once deployMaxOutput is reached.
func (j *deployJob) appendOutput(p []byte) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		return
	}
	avail := deployMaxOutput - j.buf.Len()
	if avail > 0 {
		if len(p) > avail {
			p = p[:avail]
		}
		j.buf.Write(p)
	}
	j.cond.Broadcast()
}

func (j *deployJob) appendLine(s string) {
	j.appendOutput([]byte(s + "\n"))
}

// finish marks the job done and wakes listeners one last time.
func (j *deployJob) finish(failed bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		return
	}
	j.done = true
	j.failed = failed
	j.cond.Broadcast()
}

// snapshot returns a copy of current output and status.
func (j *deployJob) snapshot() (data []byte, done, failed bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	snap := make([]byte, j.buf.Len())
	copy(snap, j.buf.Bytes())
	return snap, j.done, j.failed
}

// deployJobCleanupRetry is how long TTL cleanup waits before re-checking
// when active readers are present.
const deployJobCleanupRetry = 30 * time.Second

// deployJobCleanup waits for the TTL to expire, then deletes the job from the
// server's map. If readers are still streaming, it defers deletion until they
// finish (re-checking periodically).
func (s *Server) deployJobCleanup(job *deployJob, jobID string) {
	select {
	case <-time.After(deployJobTTL):
	case <-s.stopCh:
		return
	}
	// Wait until no readers are actively streaming this job.
	job.mu.Lock()
	for job.readers > 0 {
		// Use a timer to periodically re-check, in case no broadcast arrives.
		wakeTimer := time.AfterFunc(deployJobCleanupRetry, func() {
			job.cond.Broadcast()
		})
		job.cond.Wait()
		wakeTimer.Stop()
	}
	job.mu.Unlock()

	s.deployMu.Lock()
	delete(s.deployJobs, jobID)
	s.deployMu.Unlock()
}

// --- IP rate limiter ---

type deployRateLimiter struct {
	mu      sync.Mutex
	lastSeen map[string]time.Time
}

func newDeployRateLimiter() *deployRateLimiter {
	return &deployRateLimiter{lastSeen: make(map[string]time.Time)}
}

// allow returns true if the given IP is allowed to start a deploy now,
// and records the attempt. Expired entries are pruned opportunistically.
func (r *deployRateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if last, ok := r.lastSeen[ip]; ok && now.Sub(last) < deployIPCooldown {
		return false
	}
	// Prune stale entries to prevent unbounded map growth.
	for k, t := range r.lastSeen {
		if now.Sub(t) > deployIPCooldown*4 {
			delete(r.lastSeen, k)
		}
	}
	r.lastSeen[ip] = now
	return true
}

// --- Handlers ---

// handleDeployPubkey parses a private key and returns its type and SHA256 fingerprint.
// POST /api/deploy/pubkey — admin-only; used by the browser to validate a key before deploying.
func (s *Server) handleDeployPubkey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.verifyJSONAdminAuth(w, r) == "" {
		return
	}
	var req struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, deployRequestMaxBody)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	signer, err := gossh.ParsePrivateKey([]byte(req.PrivateKey))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid key: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"type":        signer.PublicKey().Type(),
		"fingerprint": gossh.FingerprintSHA256(signer.PublicKey()),
	}); err != nil {
		slog.Error("encoding JSON response", "err", err)
	}
}

// handleDeployUsers returns PocketID users with at least one sshPublicKey* claim.
// GET /api/deploy/users — admin-only
func (s *Server) handleDeployUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.getSessionUser(r) == "" || s.getSessionRole(r) != "admin" {
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.pocketIDClient == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	users, err := s.pocketIDClient.UsersWithSSHKeys()
	if err != nil {
		slog.Error("deploy/users fetch failed", "err", err)
		apiError(w, http.StatusInternalServerError, "failed to fetch users")
		return
	}
	type userEntry struct {
		Username string   `json:"username"`
		Email    string   `json:"email"`
		SSHKeys  []string `json:"ssh_keys"`
	}
	out := make([]userEntry, 0, len(users))
	for _, u := range users {
		out = append(out, userEntry{Username: u.Username, Email: u.Email, SSHKeys: u.SSHKeys})
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil { slog.Error("encoding JSON response", "err", err) }
}

// handleDeploy starts an SSH remote-install job.
// POST /api/deploy — admin-only.
func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Admin session + CSRF check
	if s.verifyJSONAdminAuth(w, r) == "" {
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		apiError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}

	// Per-IP rate limit
	callerIP := clientIP(r)
	if !s.deployRL.allow(callerIP) {
		apiError(w, http.StatusTooManyRequests, "too many requests — wait before retrying")
		return
	}

	body := io.LimitReader(r.Body, deployRequestMaxBody)
	var req struct {
		Hostname     string `json:"hostname"`
		Port         int    `json:"port"`
		SSHUser      string `json:"ssh_user"`
		PrivateKey   string `json:"private_key"`
		PocketIDUser string `json:"pocketid_user"` // informational only
	}
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate required fields
	if req.Hostname == "" {
		apiError(w, http.StatusBadRequest, "hostname required")
		return
	}
	if !validHostname.MatchString(req.Hostname) {
		apiError(w, http.StatusBadRequest, "invalid hostname")
		return
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}
	if !validUsername.MatchString(req.SSHUser) {
		apiError(w, http.StatusBadRequest, "invalid ssh_user")
		return
	}
	if req.Port == 0 {
		req.Port = 22
	} else if req.Port < 1 || req.Port > 65535 {
		apiError(w, http.StatusBadRequest, "invalid port")
		return
	}
	if req.PrivateKey == "" {
		apiError(w, http.StatusBadRequest, "private_key required")
		return
	}

	// Parse the private key eagerly to fail fast (key never stored)
	signer, err := gossh.ParsePrivateKey([]byte(req.PrivateKey))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid private key: "+err.Error())
		return
	}

	// Acquire semaphore (non-blocking)
	select {
	case deploySemaphore <- struct{}{}:
	default:
		apiError(w, http.StatusServiceUnavailable, "server busy — too many concurrent deploys")
		return
	}

	jobID, err := randutil.Hex(16)
	if err != nil {
		<-deploySemaphore
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}

	adminUser := s.getSessionUser(r)
	slog.Info("DEPLOY starting", "admin", adminUser, "host", req.Hostname, "port", req.Port, "ssh_user", req.SSHUser, "client_ip", clientIP(r), "job", jobID)

	job := newDeployJob(jobID, req.Hostname, req.SSHUser, adminUser)
	s.deployMu.Lock()
	s.deployJobs[jobID] = job
	s.deployMu.Unlock()

	// Render the install script server-side so the remote host needs no curl.
	installScript, err := s.renderInstallScript()
	if err != nil {
		<-deploySemaphore
		apiError(w, http.StatusInternalServerError, "failed to render install script")
		return
	}

	// Use sudo only when not connecting as root; many systems (e.g. Proxmox) don't have sudo.
	sudoPrefix := ""
	if req.SSHUser != "root" {
		sudoPrefix = "sudo "
	}
	// The static installer takes the server URL as $1. Pass it via bash -s.
	remoteCmd := fmt.Sprintf("%sbash -s %s", sudoPrefix, shellQuote(s.installServerURL()))
	// Inject SHARED_SECRET and IDENTREE_SHARED_SECRET via stdin (the install
	// script) so they do not appear in the remote process list (ps aux).
	secretExport := fmt.Sprintf("export SHARED_SECRET=%s\nexport IDENTREE_SHARED_SECRET=%s\n",
		shellQuote(s.cfg.SharedSecret), shellQuote(s.cfg.SharedSecret))
	installScript = append([]byte(secretExport), installScript...)

	go func() {
		defer func() { <-deploySemaphore }()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("deploy goroutine panic", "job", jobID, "panic", r)
			}
		}()
		s.runDeployJob(job, req.Hostname, req.Port, req.SSHUser, signer, remoteCmd, installScript)
		// zero the signer (best-effort, GC will handle the rest)
		signer = nil
		// Schedule job cleanup after TTL to prevent unbounded map growth.
		go func() {
			s.deployJobCleanup(job, jobID)
		}()
	}()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"id": jobID}); err != nil {
		slog.Error("encoding JSON response", "err", err)
	}
}

// handleDeployStream streams deploy job output as SSE.
// GET /api/deploy/stream/{id} — admin-only; only the initiating admin may stream a job.
func (s *Server) handleDeployStream(w http.ResponseWriter, r *http.Request) {
	currentUser := s.getSessionUser(r)
	if currentUser == "" || s.getSessionRole(r) != "admin" {
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Extract job ID from path: /api/deploy/stream/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/deploy/stream/")
	jobID := strings.TrimSpace(path)
	if jobID == "" || !isHex(jobID) {
		apiError(w, http.StatusBadRequest, "invalid job id")
		return
	}

	s.deployMu.Lock()
	job, ok := s.deployJobs[jobID]
	s.deployMu.Unlock()
	if !ok {
		apiError(w, http.StatusNotFound, "job not found")
		return
	}

	// Only the admin who initiated the job may stream its output.
	if job.initiator != currentUser {
		apiError(w, http.StatusForbidden, "forbidden")
		return
	}

	// Track this reader so TTL cleanup defers deletion while we are streaming.
	job.mu.Lock()
	job.readers++
	job.mu.Unlock()
	defer func() {
		job.mu.Lock()
		job.readers--
		job.cond.Broadcast() // wake TTL cleanup if it is waiting for readers to drain
		job.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, canFlush := w.(http.Flusher)

	// Clear the server-level WriteTimeout for this streaming connection so
	// long-running deploys are not killed at 60s. Mirrors handleSSEEvents.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	// Bridge context cancellation to the Cond so Wait() unblocks when the
	// client disconnects. The goroutine exits when the context is done or
	// when this handler returns (whichever comes first).
	ctx := r.Context()
	go func() {
		<-ctx.Done()
		job.cond.Broadcast()
	}()

	sent := 0 // bytes already sent
	lastActivity := time.Now()
	for {
		data, done, failed := job.snapshot()

		// Send any new bytes
		if len(data) > sent {
			newData := data[sent:]
			// Emit line by line as SSE events for clean display.
			// Strip \r to prevent SSE field injection from CR-containing SSH output.
			lines := strings.Split(string(newData), "\n")
			for i, line := range lines {
				if i == len(lines)-1 && line == "" {
					break // trailing newline
				}
				fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(line, "\r", ""))
			}
			sent = len(data)
			if canFlush {
				flusher.Flush()
			}
			lastActivity = time.Now()
		}

		if done {
			status := "done"
			if failed {
				status = "failed"
			}
			fmt.Fprintf(w, "event: status\ndata: %s\n\n", status)
			if canFlush {
				flusher.Flush()
			}
			return
		}

		if ctx.Err() != nil {
			return
		}

		// Wait for new output, keepalive timeout, or client disconnect.
		// sync.Cond does not support select, so we use a timed wait via
		// a background timer that broadcasts after the keepalive interval.
		wakeTimer := time.AfterFunc(deploySSEKeepalive, func() {
			job.cond.Broadcast()
		})
		job.mu.Lock()
		// Re-check under lock: only wait if no new data and not done.
		if job.buf.Len() == sent && !job.done && ctx.Err() == nil {
			job.cond.Wait()
		}
		job.mu.Unlock()
		wakeTimer.Stop()

		// Send keepalive comment if enough time has passed without new data.
		if time.Since(lastActivity) >= deploySSEKeepalive {
			fmt.Fprintf(w, ": keepalive\n\n")
			if canFlush {
				flusher.Flush()
			}
			lastActivity = time.Now()
		}
	}
}

// handleRemoveHost removes a host from identree's store without SSH cleanup.
// POST /api/hosts/remove-host
func (s *Server) handleRemoveHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.verifyJSONAdminAuth(w, r) == "" {
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		apiError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var req struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		io.Copy(io.Discard, r.Body) //nolint:errcheck // best-effort drain for keep-alive
		apiError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Hostname == "" || !validHostname.MatchString(req.Hostname) {
		apiError(w, http.StatusBadRequest, "invalid hostname")
		return
	}

	adminUser := s.getSessionUser(r) // already validated by verifyJSONAdminAuth above
	s.store.RemoveHost(req.Hostname)
	_ = s.hostRegistry.RemoveHost(req.Hostname) // ignore "not registered" error
	s.store.LogAction(adminUser, challpkg.ActionRemovedHost, req.Hostname, "", "")
	slog.Info("HOST_REMOVED", "admin", adminUser, "host", req.Hostname, "client_ip", clientIP(r))

	s.dispatchNotification(notify.WebhookData{
		Event:      "host_removed",
		Username:   adminUser,
		Hostname:   req.Hostname,
		Actor:      adminUser,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		RemoteAddr: clientIP(r),
	})

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		slog.Error("encoding JSON response", "err", err)
	}
}

// handleRemoveDeploy SSHes into a host, runs the uninstall script, then removes it from the store.
// POST /api/deploy/remove
func (s *Server) handleRemoveDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.verifyJSONAdminAuth(w, r) == "" {
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		apiError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}

	// Per-IP rate limit
	callerIP := clientIP(r)
	if !s.deployRL.allow(callerIP) {
		apiError(w, http.StatusTooManyRequests, "too many requests — wait before retrying")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize*64)
	var req struct {
		Hostname       string `json:"hostname"`
		Port           int    `json:"port"`
		SSHUser        string `json:"ssh_user"`
		PrivateKey     string `json:"private_key"`
		UnconfigurePAM bool   `json:"unconfigure_pam"`
		RemoveFiles    bool   `json:"remove_files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		io.Copy(io.Discard, r.Body) //nolint:errcheck // best-effort drain for keep-alive
		apiError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Hostname == "" || !validHostname.MatchString(req.Hostname) {
		apiError(w, http.StatusBadRequest, "hostname required")
		return
	}
	if req.Port == 0 {
		req.Port = 22
	} else if req.Port < 1 || req.Port > 65535 {
		apiError(w, http.StatusBadRequest, "invalid port")
		return
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}
	if !validUsername.MatchString(req.SSHUser) {
		apiError(w, http.StatusBadRequest, "invalid ssh_user")
		return
	}
	if req.PrivateKey == "" {
		apiError(w, http.StatusBadRequest, "private_key required")
		return
	}

	signer, err := gossh.ParsePrivateKey([]byte(req.PrivateKey))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid private key: "+err.Error())
		return
	}

	uninstallScript, err := s.renderUninstallScript(req.UnconfigurePAM, req.RemoveFiles)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}

	adminUser := s.getSessionUser(r)
	if adminUser == "" {
		apiError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	jobID, err := randutil.Hex(8)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}

	job := newDeployJob(jobID, req.Hostname, req.SSHUser, adminUser)

	s.deployMu.Lock()
	s.deployJobs[jobID] = job
	s.deployMu.Unlock()

	sudoPrefix := ""
	if req.SSHUser != "root" {
		sudoPrefix = "sudo "
	}
	remoteCmd := fmt.Sprintf("%sbash", sudoPrefix)

	// Acquire semaphore (non-blocking) before starting the goroutine so we
	// can return a synchronous error to the caller, matching the install flow.
	select {
	case deploySemaphore <- struct{}{}:
	default:
		apiError(w, http.StatusServiceUnavailable, "server busy — too many concurrent deploys")
		return
	}

	go func() {
		defer func() { <-deploySemaphore }()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("deploy goroutine panic", "job", jobID, "panic", r)
			}
		}()
		s.runDeployJob(job, req.Hostname, req.Port, req.SSHUser, signer, remoteCmd, uninstallScript)
		_, _, jobFailed := job.snapshot()
		if !jobFailed {
			s.store.RemoveHost(req.Hostname)
			_ = s.hostRegistry.RemoveHost(req.Hostname) // ignore "not registered" error
			s.store.LogAction(adminUser, challpkg.ActionRemovedHost, req.Hostname, "", "")
		}
		// Schedule job cleanup after TTL to prevent unbounded map growth.
		go func() {
			s.deployJobCleanup(job, jobID)
		}()
	}()

	slog.Info("REMOVE starting", "admin", adminUser, "host", req.Hostname, "port", req.Port, "ssh_user", req.SSHUser, "job", jobID)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"id": jobID}); err != nil {
		slog.Error("encoding JSON response", "err", err)
	}
}

// runDeployJob connects via SSH, pipes installScript to stdin of cmd, and streams output to job.
func (s *Server) runDeployJob(job *deployJob, hostname string, port int, sshUser string, signer gossh.Signer, cmd string, installScript []byte) {
	addr := fmt.Sprintf("%s:%d", hostname, port)
	job.appendLine(fmt.Sprintf("Connecting to %s as %s …", addr, sshUser))

	cfg := &gossh.ClientConfig{
		User:            sshUser,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint — deploying to new hosts; no known_hosts
		Timeout:         15 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		job.appendLine("ERROR: " + err.Error())
		job.finish(true)
		return
	}
	defer client.Close()
	job.appendLine("Connected. Running install script …")

	sess, err := client.NewSession()
	if err != nil {
		job.appendLine("ERROR: failed to open session: " + err.Error())
		job.finish(true)
		return
	}
	defer sess.Close()

	// Pipe the install script to bash's stdin on the remote host.
	sess.Stdin = bytes.NewReader(installScript)

	// Stream stdout and stderr back to the job buffer via a pipe
	pr, pw := io.Pipe()
	defer pr.Close()
	sess.Stdout = pw
	sess.Stderr = pw

	if err := sess.Start(cmd); err != nil {
		pw.Close()
		job.appendLine("ERROR: " + err.Error())
		job.finish(true)
		return
	}

	// Read pipe and push to job (bounded by deployTimeout)
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				job.appendOutput(buf[:n])
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	// Enforce overall timeout
	timer := time.NewTimer(deployTimeout)
	defer timer.Stop()

	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()

	select {
	case waitErr := <-waitDone:
		pw.Close()
		<-done
		if waitErr != nil {
			job.appendLine("ERROR: " + waitErr.Error())
			job.finish(true)
		} else {
			job.appendLine("Install completed successfully.")
			job.finish(false)
			// Extract the hostname the install script reported, falling back to
			// the address the admin entered if the line isn't present.
			logHost := hostname
			job.mu.Lock()
			for _, line := range strings.Split(job.buf.String(), "\n") {
				if h := strings.TrimPrefix(line, "IDENTREE_HOSTNAME="); h != line {
					h = strings.TrimSpace(h)
					if h != "" && validHostname.MatchString(h) {
						logHost = h
					}
					break
				}
			}
			job.mu.Unlock()
			s.store.LogAction(job.initiator, challpkg.ActionDeployed, logHost, "", "")
			s.dispatchNotification(notify.WebhookData{
				Event:      "deployed",
				Username:   job.initiator,
				Hostname:   logHost,
				Actor:      job.initiator,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
			})
		}
	case <-timer.C:
		sess.Signal(gossh.SIGKILL)
		pw.Close()
		job.appendLine("ERROR: timed out after " + deployTimeout.String())
		job.finish(true)
	}
}

// shellQuote wraps s in single quotes safe for POSIX shell, escaping any
// single quotes within the value.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// privateIP reports whether ip is a loopback or RFC1918 address (i.e. from a
// reverse proxy rather than a real client).
func privateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP extracts the real client IP from the request.
// When RemoteAddr is a private/loopback address (i.e. behind a reverse proxy),
// the rightmost entry in X-Forwarded-For is used as the real client IP.
// The rightmost entry is appended by the outermost trusted proxy and cannot be
// spoofed by the client (unlike the leftmost, which the client controls).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if privateIP(net.ParseIP(host)) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For may be "client, proxy1, proxy2".
			// Take the rightmost entry: it was appended by the last trusted proxy
			// and cannot be forged by the client (the leftmost can be).
			parts := strings.Split(xff, ",")
			if candidate := strings.TrimSpace(parts[len(parts)-1]); candidate != "" {
				return candidate
			}
		}
	}
	return host
}

// cidrContains reports whether ip falls within any of the given CIDRs.

