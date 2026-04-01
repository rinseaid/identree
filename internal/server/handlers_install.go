package server

import (
	"fmt"
	"net/http"
	"strings"
	"text/template"
)

// installScriptTmpl is a shell script template served at GET /install.sh.
// It pre-configures IDENTREE_SERVER_URL from the server's ExternalURL so
// users can pipe the script directly: curl -fsSL {{.ServerURL}}/install.sh | sudo bash
//
// The shared secret is intentionally NOT embedded in the publicly-served script.
// Pass it at install time via the SHARED_SECRET env var for automated deployments:
//   SHARED_SECRET=xxx curl -fsSL {{.ServerURL}}/install.sh | sudo bash
const installScriptTmpl = `#!/bin/bash
set -euo pipefail

# identree installer — pre-configured for {{.ServerURL}}
# Usage: curl -fsSL {{.ServerURL}}/install.sh | sudo bash
# Automated: SHARED_SECRET=xxx curl -fsSL {{.ServerURL}}/install.sh | sudo bash

SERVER_URL={{.ServerURL}}
MACHINE_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
echo "IDENTREE_HOSTNAME=$MACHINE_HOSTNAME"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/identree"
CONFIG_FILE="/etc/identree/client.conf"

# ── Download helper (curl → wget fallback) ───────────────────────────────────

_dl() {
    # Usage: _dl <url>              → stdout
    #        _dl <url> <dest-file>  → file
    local url="$1" dest="${2:-}"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$dest" ]; then curl -fsSL -o "$dest" "$url"
        else curl -fsSL "$url"; fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$dest" ]; then wget -qO "$dest" "$url"
        else wget -qO- "$url"; fi
    elif command -v python3 >/dev/null 2>&1; then
        if [ -n "$dest" ]; then
            python3 -c "
import urllib.request, sys
try:
    urllib.request.urlretrieve(sys.argv[1], sys.argv[2])
except Exception as e:
    sys.stderr.write('Error: ' + str(e) + '\n'); sys.exit(1)
" -- "$url" "$dest"
        else
            python3 -c "
import urllib.request, sys
try:
    sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1]).read())
except Exception as e:
    sys.stderr.write('Error: ' + str(e) + '\n'); sys.exit(1)
" -- "$url"
        fi
    elif command -v python >/dev/null 2>&1; then
        if [ -n "$dest" ]; then
            python -c "
import urllib2, sys
try:
    open(sys.argv[2],'wb').write(urllib2.urlopen(sys.argv[1]).read())
except Exception as e:
    sys.stderr.write('Error: ' + str(e) + '\n'); sys.exit(1)
" -- "$url" "$dest"
        else
            python -c "
import urllib2, sys
try:
    sys.stdout.write(urllib2.urlopen(sys.argv[1]).read())
except Exception as e:
    sys.stderr.write('Error: ' + str(e) + '\n'); sys.exit(1)
" -- "$url"
        fi
    else
        echo "Error: no download tool found (tried curl, wget, python3, python) — install one and retry" >&2
        exit 1
    fi
}

# ── Preflight ───────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root (try: curl ... | sudo bash)" >&2
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    echo "Error: identree only supports Linux" >&2
    exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SUFFIX="linux-amd64" ;;
    aarch64) SUFFIX="linux-arm64" ;;
    *)
        echo "Error: unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

# ── Binary ──────────────────────────────────────────────────────────────────

echo "Fetching version from $SERVER_URL..."
VERSION=$(_dl "$SERVER_URL/download/version" 2>&1) || {
    echo "Error: could not reach identree server at $SERVER_URL" >&2
    echo "$VERSION" >&2
    exit 1
}
VERSION=$(echo "$VERSION" | tr -d '[:space:]')
if [ -z "$VERSION" ]; then
    echo "Error: server returned empty version" >&2
    exit 1
fi
echo "Server version: $VERSION"

CURRENT="none"
if [ -f "$INSTALL_DIR/identree" ]; then
    CURRENT=$("$INSTALL_DIR/identree" --version 2>/dev/null | awk '{print $1}' || echo "unknown")
fi

if [ "$CURRENT" = "$VERSION" ] && [ "$VERSION" != "dev" ]; then
    echo "Binary already at $VERSION — skipping download."
else
    BIN_URL="$SERVER_URL/download/identree-$SUFFIX"
    TMP_BIN=$(mktemp /tmp/identree-XXXXXX)
    trap 'rm -f "$TMP_BIN"' EXIT

    echo "Downloading identree $VERSION ($SUFFIX)..."
    _dl "$BIN_URL" "$TMP_BIN"

    install -m 755 "$TMP_BIN" "$INSTALL_DIR/identree"
    echo "Installed identree $VERSION"
fi

# ── Config file ─────────────────────────────────────────────────────────────

mkdir -p "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

if [ -f "$CONFIG_FILE" ]; then
    conf_url=$(grep -E '^IDENTREE_SERVER_URL=' "$CONFIG_FILE" | cut -d= -f2- || true)
    conf_secret=$(grep -E '^IDENTREE_SHARED_SECRET=' "$CONFIG_FILE" | cut -d= -f2- || true)
    echo "Config file exists: $CONFIG_FILE"
    if [ -z "$conf_url" ]; then
        echo "  WARNING: IDENTREE_SERVER_URL missing"
    else
        echo "  IDENTREE_SERVER_URL=$conf_url"
    fi
    if [ -z "$conf_secret" ]; then
        echo "  WARNING: IDENTREE_SHARED_SECRET missing"
    else
        echo "  IDENTREE_SHARED_SECRET=${conf_secret:0:4}****"
    fi
    # Overwrite if SHARED_SECRET provided and config differs
    NEW_SECRET="${SHARED_SECRET:-}"
    if [ -n "$NEW_SECRET" ] && { [ "$conf_url" != "$SERVER_URL" ] || [ "$conf_secret" != "$NEW_SECRET" ]; }; then
        printf 'IDENTREE_SERVER_URL=%s\nIDENTREE_SHARED_SECRET=%s\n' \
            "$SERVER_URL" "$NEW_SECRET" > "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
        echo "  Updated $CONFIG_FILE with current values."
    else
        echo "  Config is up to date."
    fi
    CONFIG_WRITTEN=1
else
    SECRET="${SHARED_SECRET:-}"
    if [ -z "$SECRET" ]; then
        if [ -t 0 ]; then
            # Interactive: prompt securely
            read -rsp "Enter IDENTREE_SHARED_SECRET: " SECRET
            echo
        else
            echo ""
            echo "NOTE: SHARED_SECRET not set and stdin is not a terminal."
            echo "Create $CONFIG_FILE manually after this script completes:"
            echo ""
            echo "  cat > $CONFIG_FILE <<'EOF'"
            echo "  IDENTREE_SERVER_URL=$SERVER_URL"
            echo "  IDENTREE_SHARED_SECRET=<your-shared-secret>"
            echo "  EOF"
            echo "  chmod 600 $CONFIG_FILE"
        fi
    fi
    if [ -n "$SECRET" ]; then
        printf 'IDENTREE_SERVER_URL=%s\nIDENTREE_SHARED_SECRET=%s\n' \
            "$SERVER_URL" "$SECRET" > "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
        echo "Created $CONFIG_FILE"
        CONFIG_WRITTEN=1
    else
        CONFIG_WRITTEN=0
    fi
fi

# ── Systemd rotation timer ───────────────────────────────────────────────────

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    for UNIT in identree-rotate.service identree-rotate.timer; do
        _dl "$SERVER_URL/download/systemd/$UNIT" "$SYSTEMD_DIR/$UNIT"
    done
    systemctl daemon-reload
    systemctl enable --now identree-rotate.timer
    echo "Enabled weekly break-glass rotation timer"
elif command -v crontab >/dev/null 2>&1 || [ -d /etc/cron.d ]; then
    CRON_FILE="/etc/cron.d/identree-rotate"
    if [ -f "$CRON_FILE" ]; then
        echo "Cron job already configured: $CRON_FILE"
    else
        printf '# identree weekly break-glass rotation\n0 3 * * 0 root /usr/local/bin/identree rotate-breakglass\n' > "$CRON_FILE"
        chmod 644 "$CRON_FILE"
        echo "Installed weekly rotation cron job: $CRON_FILE"
    fi
else
    echo "Warning: neither systemd nor cron found — run weekly manually:"
    echo "  sudo /usr/local/bin/identree rotate-breakglass"
fi

# ── PAM configuration ────────────────────────────────────────────────────────

PAM_LINE='auth    required    pam_exec.so    stdout /usr/local/bin/identree'

for PAM_FILE in /etc/pam.d/sudo /etc/pam.d/sudo-i; do
    [ -f "$PAM_FILE" ] || continue
    if grep -q "identree" "$PAM_FILE" 2>/dev/null; then
        echo "PAM already configured: $PAM_FILE"
        continue
    fi
    cp "$PAM_FILE" "${PAM_FILE}.bak"
    # Insert before the first auth or @include line
    awk -v line="$PAM_LINE" '
        !done && /^(auth[[:space:]]|@include)/ { print line; done=1 }
        { print }
    ' "${PAM_FILE}.bak" > "$PAM_FILE"
    echo "Updated $PAM_FILE (original saved as ${PAM_FILE}.bak)"
done

# ── Initial break-glass password ─────────────────────────────────────────────

if [ ! -f /etc/identree-breakglass ]; then
    if [ "${CONFIG_WRITTEN:-0}" = "1" ]; then
        echo ""
        echo "Generating initial break-glass password..."
        if "$INSTALL_DIR/identree" rotate-breakglass; then
            echo "Break-glass password configured."
        else
            echo "WARNING: break-glass setup failed — run manually:"
            echo "  sudo identree rotate-breakglass"
        fi
    else
        echo ""
        echo "Skipping break-glass setup (no config file yet)."
        echo "Run after creating $CONFIG_FILE:"
        echo "  sudo identree rotate-breakglass"
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "Done! identree $VERSION installed."
if [ "${CONFIG_WRITTEN:-0}" != "1" ]; then
    echo "Remember to create $CONFIG_FILE and run: sudo identree rotate-breakglass"
fi
`

// uninstallScriptTmpl is the shell script run on the remote host to remove identree.
const uninstallScriptTmpl = `#!/bin/bash
set -euo pipefail

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/identree"
SYSTEMD_DIR="/etc/systemd/system"
UNCONFIGURE_PAM="{{.UnconfigurePAM}}"
REMOVE_FILES="{{.RemoveFiles}}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root" >&2
    exit 1
fi

# ── PAM ──────────────────────────────────────────────────────────────────────
if [ "$UNCONFIGURE_PAM" = "true" ]; then
    for PAM_FILE in /etc/pam.d/sudo /etc/pam.d/sudo-i; do
        [ -f "$PAM_FILE" ] || continue
        if grep -q "identree" "$PAM_FILE" 2>/dev/null; then
            cp "$PAM_FILE" "${PAM_FILE}.bak"
            grep -v "identree" "${PAM_FILE}.bak" > "$PAM_FILE"
            echo "Removed identree from $PAM_FILE"
        else
            echo "identree not configured in $PAM_FILE"
        fi
    done
fi

# ── Systemd / cron ────────────────────────────────────────────────────────────
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now identree-rotate.timer 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/identree-rotate.service" "$SYSTEMD_DIR/identree-rotate.timer"
    systemctl daemon-reload 2>/dev/null || true
    echo "Disabled and removed systemd units"
elif [ -f /etc/cron.d/identree-rotate ]; then
    rm -f /etc/cron.d/identree-rotate
    echo "Removed cron job"
fi

# ── Binary and config ─────────────────────────────────────────────────────────
if [ "$REMOVE_FILES" = "true" ]; then
    rm -f "$INSTALL_DIR/identree" "$INSTALL_DIR/identree-linux-amd64" "$INSTALL_DIR/identree-linux-arm64"
    rm -f /etc/identree-breakglass
    rm -rf "$CONFIG_DIR"
    echo "Removed identree binary and config"
fi

echo ""
echo "identree removed from this host."
`

// renderUninstallScript returns the rendered uninstall script.
func (s *Server) renderUninstallScript(unconfigurePAM, removeFiles bool) ([]byte, error) {
	tmpl, err := template.New("uninstall").Parse(uninstallScriptTmpl)
	if err != nil {
		return nil, err
	}
	data := struct {
		UnconfigurePAM string
		RemoveFiles    string
	}{
		UnconfigurePAM: fmt.Sprintf("%v", unconfigurePAM),
		RemoveFiles:    fmt.Sprintf("%v", removeFiles),
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// installServerURL returns the URL the install script should use to reach this
// server from client hosts. Uses IDENTREE_INSTALL_URL if set, otherwise
// falls back to ExternalURL.
func (s *Server) installServerURL() string {
	if s.cfg.InstallURL != "" {
		return strings.TrimRight(s.cfg.InstallURL, "/")
	}
	return s.baseURL
}

// renderInstallScript returns the rendered install script as bytes.
// Used by the deploy handler to pipe the script directly over SSH.
func (s *Server) renderInstallScript() ([]byte, error) {
	tmpl, err := template.New("install").Parse(installScriptTmpl)
	if err != nil {
		return nil, err
	}
	data := struct{ ServerURL string }{ServerURL: shellQuote(s.installServerURL())}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// handleUninstallScript serves the rendered uninstall script.
// GET /api/deploy/uninstall-script?pam=true&files=true
func (s *Server) handleUninstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pam := r.URL.Query().Get("pam") != "false"
	files := r.URL.Query().Get("files") != "false"
	script, err := s.renderUninstallScript(pam, files)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(script)
}

// handleInstallScript serves a pre-configured shell installer script.
// GET /install.sh
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tmpl, err := template.New("install").Parse(installScriptTmpl)
	if err != nil {
		// Template is a compile-time constant; any parse error is a programmer bug.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := struct {
		ServerURL string
	}{
		ServerURL: shellQuote(s.installServerURL()),
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=install.sh")
	// Prevent browsers from caching a stale version of the script.
	w.Header().Set("Cache-Control", "no-store")

	if err := tmpl.Execute(w, data); err != nil {
		// Can't write headers at this point; just log.
		fmt.Printf("ERROR: install script template: %v\n", err)
	}
}
