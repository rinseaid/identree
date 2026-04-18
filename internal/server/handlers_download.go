package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// systemd unit file contents — served at /download/systemd/<unit>.
var systemdUnits = map[string]string{
	"identree-rotate.service": `[Unit]
Description=identree break-glass password rotation
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/identree rotate-breakglass
`,
	"identree-rotate.timer": `[Unit]
Description=identree weekly break-glass rotation
Requires=identree-rotate.service

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
`,
	"identree-heartbeat.service": `[Unit]
Description=identree agent heartbeat (managed-host liveness ping)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/identree heartbeat
SuccessExitStatus=0 1
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
`,
	"identree-heartbeat.timer": `[Unit]
Description=identree agent heartbeat — every 60 seconds
Requires=identree-heartbeat.service

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
RandomizedDelaySec=10s
AccuracySec=5s

[Install]
WantedBy=timers.target
`,
}

// handleDownloadVersion serves the running server's version string.
// GET /download/version
func (s *Server) handleDownloadVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, version)
}

// handleDownloadBinary serves the identree binary for the requested architecture.
// GET /download/identree-linux-amd64
// GET /download/identree-linux-arm64
//
// Binaries are resolved relative to the running executable's directory:
// e.g. if the server runs from /usr/local/bin/identree, it looks for
// /usr/local/bin/identree-linux-amd64 and /usr/local/bin/identree-linux-arm64.
func (s *Server) handleDownloadBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/download/")
	if name != "identree-linux-amd64" && name != "identree-linux-arm64" {
		http.NotFound(w, r)
		return
	}

	binPath, err := binaryPath(name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	f, err := os.Open(binPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, fmt.Sprintf("%s is not available on this server", name), http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// handleDownloadSystemd serves embedded systemd unit files.
// GET /download/systemd/identree-rotate.service
// GET /download/systemd/identree-rotate.timer
func (s *Server) handleDownloadSystemd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	unit := strings.TrimPrefix(r.URL.Path, "/download/systemd/")
	content, ok := systemdUnits[unit]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, content)
}

// handleDownloadBinaryChecksum serves the SHA-256 hex digest of the named binary.
// GET /download/identree-linux-amd64.sha256
// GET /download/identree-linux-arm64.sha256
func (s *Server) handleDownloadBinaryChecksum(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Strip ".sha256" suffix to get the binary name.
	name := strings.TrimPrefix(r.URL.Path, "/download/")
	name = strings.TrimSuffix(name, ".sha256")
	if name != "identree-linux-amd64" && name != "identree-linux-arm64" {
		http.NotFound(w, r)
		return
	}

	binPath, err := binaryPath(name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	f, err := os.Open(binPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, fmt.Sprintf("%s is not available on this server", name), http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), name)
}

// handleAvatarProxy fetches a user avatar image server-side and streams it to
// the browser. Routing through the proxy eliminates the DNS-rebinding TOCTOU
// that exists when the browser fetches the avatar URL independently after we
// validate the hostname in the server.
// GET /api/avatar?url=<encoded-avatar-url>
func (s *Server) handleAvatarProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		http.NotFound(w, r)
		return
	}

	if !strings.HasPrefix(rawURL, "https://") && !strings.HasPrefix(rawURL, "http://") {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}

	// Use a custom dialer that blocks private/loopback addresses to prevent SSRF.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// Resolve the hostname and check all returned addresses.
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip != nil && isPrivateIP(ip) {
					return nil, fmt.Errorf("avatar proxy: host %q resolves to private address %s", host, ipStr)
				}
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ips[0], port))
		},
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) // #nosec G704 -- URL validated above (scheme check + isPrivateIP)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("User-Agent", "identree-avatar-proxy/1.0")

	resp, err := client.Do(req) // #nosec G704 -- URL validated above
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "image/") {
		http.Error(w, "not an image", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=300")
	io.Copy(w, io.LimitReader(resp.Body, 1<<20)) //nolint:errcheck // best-effort stream
}

// binaryPath resolves the path to a named binary (e.g. "identree-linux-amd64")
// by looking in the same directory as the running executable.
func binaryPath(name string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	// Resolve symlinks so filepath.Dir gives the real directory.
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), name), nil
}
