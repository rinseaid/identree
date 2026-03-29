package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
