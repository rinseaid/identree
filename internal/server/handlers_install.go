package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/rinseaid/identree/internal/signing"
)

// staticInstallScript is the default installer served at GET /install.sh.
// It contains NO deployment-specific values — those are fetched at runtime
// from the /install-config.json endpoint. This means the script is identical
// across deployments and can be signed once at build time or at server startup.
//
// Usage:
//
//	curl -sf https://identree.example.com/install.sh | sudo IDENTREE_SHARED_SECRET=xxx bash -s https://identree.example.com
//	# or download-then-verify:
//	curl -sf https://identree.example.com/install.sh -o /tmp/install.sh
//	curl -sf https://identree.example.com/install.sh.sig -o /tmp/install.sh.sig
//	identree verify-install --key install.pub --script /tmp/install.sh --sig /tmp/install.sh.sig
//	sudo IDENTREE_SHARED_SECRET=xxx bash /tmp/install.sh https://identree.example.com
const staticInstallScript = `#!/bin/bash
set -euo pipefail

# identree static installer
# Usage: IDENTREE_SHARED_SECRET=xxx bash install.sh <identree-server-url>
# With SSSD: IDENTREE_SHARED_SECRET=xxx SETUP_SSSD=1 bash install.sh <identree-server-url>

CONFIG_URL="${1:-}"
if [ -z "$CONFIG_URL" ]; then
    echo "Usage: install.sh <identree-server-url>" >&2
    echo "  e.g. IDENTREE_SHARED_SECRET=xxx bash install.sh https://identree.example.com" >&2
    exit 1
fi
# Strip trailing slash for consistency.
CONFIG_URL="${CONFIG_URL%/}"

MACHINE_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
echo "IDENTREE_HOSTNAME=$MACHINE_HOSTNAME"
SETUP_SSSD="${SETUP_SSSD:-0}"
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

# _dl_secret downloads a URL with the shared secret in the X-Shared-Secret header.
_dl_secret() {
    local url="$1" dest="${2:-}" secret="${IDENTREE_SHARED_SECRET:-${SHARED_SECRET:-}}"
    if [ -z "$secret" ]; then
        echo "Error: IDENTREE_SHARED_SECRET (or SHARED_SECRET) must be set" >&2
        exit 1
    fi
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$dest" ]; then curl -fsSL -H "X-Shared-Secret: $secret" -o "$dest" "$url"
        else curl -fsSL -H "X-Shared-Secret: $secret" "$url"; fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$dest" ]; then wget -qO "$dest" --header="X-Shared-Secret: $secret" "$url"
        else wget -qO- --header="X-Shared-Secret: $secret" "$url"; fi
    else
        echo "Error: curl or wget required for authenticated downloads" >&2
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

# ── Fetch deployment config ────────────────────────────────────────────────

echo "Fetching deployment config from $CONFIG_URL..."
INSTALL_CONFIG=$(_dl_secret "$CONFIG_URL/install-config.json") || {
    echo "Error: could not fetch install config from $CONFIG_URL/install-config.json" >&2
    echo "Ensure IDENTREE_SHARED_SECRET is set correctly." >&2
    exit 1
}

# Parse config values using lightweight JSON extraction.
# Prefer jq if available, otherwise use python3/python, otherwise use grep/sed.
_json_val() {
    local key="$1" json="$2"
    if command -v jq >/dev/null 2>&1; then
        echo "$json" | jq -r ".$key // empty"
    elif command -v python3 >/dev/null 2>&1; then
        echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$key',''))"
    elif command -v python >/dev/null 2>&1; then
        echo "$json" | python -c "import json,sys; d=json.load(sys.stdin); print d.get('$key','')"
    else
        # Fallback: naive grep — works for simple flat JSON with string values.
        echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed 's/.*":\s*"//;s/"$//'
    fi
}

SERVER_URL=$(_json_val server_url "$INSTALL_CONFIG")
INSTALL_URL=$(_json_val install_url "$INSTALL_CONFIG")

# Use install_url for downloads if set, otherwise fall back to server_url.
DL_URL="${INSTALL_URL:-$SERVER_URL}"

if [ -z "$SERVER_URL" ]; then
    echo "Error: install config missing server_url" >&2
    exit 1
fi

echo "  server_url=$SERVER_URL"
echo "  install_url=${INSTALL_URL:-<same as server_url>}"

# ── Binary ──────────────────────────────────────────────────────────────────

echo "Fetching version from $DL_URL..."
VERSION=$(_dl "$DL_URL/download/version" 2>&1) || {
    echo "Error: could not reach identree server at $DL_URL" >&2
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
    BIN_URL="$DL_URL/download/identree-$SUFFIX"
    TMP_BIN=$(mktemp /tmp/identree-XXXXXX)
    trap 'rm -f "$TMP_BIN"' EXIT

    echo "Downloading identree $VERSION ($SUFFIX)..."
    _dl "$BIN_URL" "$TMP_BIN"

    # Verify SHA-256 checksum before installing.
    SUM_URL="$DL_URL/download/identree-$SUFFIX.sha256"
    TMP_SUM=$(mktemp /tmp/identree-sum-XXXXXX)
    trap 'rm -f "$TMP_BIN" "$TMP_SUM"' EXIT
    _dl "$SUM_URL" "$TMP_SUM"
    EXPECTED_HASH=$(awk '{print $1}' "$TMP_SUM")
    ACTUAL_HASH=$(sha256sum "$TMP_BIN" 2>/dev/null | awk '{print $1}' \
        || shasum -a 256 "$TMP_BIN" 2>/dev/null | awk '{print $1}')
    if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
        echo "ERROR: SHA-256 checksum mismatch — aborting installation." >&2
        echo "  expected: $EXPECTED_HASH" >&2
        echo "  got:      $ACTUAL_HASH" >&2
        exit 1
    fi

    install -m 755 "$TMP_BIN" "$INSTALL_DIR/identree"
    echo "Installed identree $VERSION"
fi

# ── Config file ─────────────────────────────────────────────────────────────

mkdir -p "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# Resolve the shared secret from env.
SECRET="${IDENTREE_SHARED_SECRET:-${SHARED_SECRET:-}}"

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
    # Overwrite if SECRET provided and config differs
    if [ -n "$SECRET" ] && { [ "$conf_url" != "$SERVER_URL" ] || [ "$conf_secret" != "$SECRET" ]; }; then
        printf 'IDENTREE_SERVER_URL=%s\nIDENTREE_SHARED_SECRET=%s\n' \
            "$SERVER_URL" "$SECRET" > "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
        echo "  Updated $CONFIG_FILE with current values."
    else
        echo "  Config is up to date."
    fi
    CONFIG_WRITTEN=1
else
    if [ -z "$SECRET" ]; then
        if [ -t 0 ]; then
            # Interactive: prompt securely
            read -rsp "Enter IDENTREE_SHARED_SECRET: " SECRET
            echo
        else
            echo ""
            echo "NOTE: IDENTREE_SHARED_SECRET not set and stdin is not a terminal."
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
    for UNIT in identree-rotate.service identree-rotate.timer identree-heartbeat.service identree-heartbeat.timer; do
        _dl "$DL_URL/download/systemd/$UNIT" "$SYSTEMD_DIR/$UNIT"
    done
    systemctl daemon-reload
    systemctl enable --now identree-rotate.timer
    systemctl enable --now identree-heartbeat.timer
    echo "Enabled weekly break-glass rotation timer + 5-minute heartbeat timer"
elif command -v crontab >/dev/null 2>&1 || [ -d /etc/cron.d ]; then
    CRON_FILE="/etc/cron.d/identree-rotate"
    if [ -f "$CRON_FILE" ]; then
        echo "Cron job already configured: $CRON_FILE"
    else
        printf '# identree weekly break-glass rotation\n0 3 * * 0 root /usr/local/bin/identree rotate-breakglass\n# identree heartbeat (every 5 minutes)\n*/5 * * * * root /usr/local/bin/identree heartbeat >/dev/null 2>&1\n' > "$CRON_FILE"
        chmod 644 "$CRON_FILE"
        echo "Installed rotation + heartbeat cron jobs: $CRON_FILE"
    fi
else
    echo "Warning: neither systemd nor cron found — run manually:"
    echo "  sudo /usr/local/bin/identree rotate-breakglass   # weekly"
    echo "  sudo /usr/local/bin/identree heartbeat           # every 5 minutes"
fi

# ── Auditd monitoring rules (if auditd is present) ───────────────────────────

if command -v augenrules >/dev/null 2>&1; then
    cat > /etc/audit/rules.d/identree.rules << 'AUDIT_RULES'
## identree security monitoring rules
## Install to /etc/audit/rules.d/identree.rules

# Break-glass hash file read — detects password brute-force attempts
-w /etc/identree/breakglass.hash -p r -k identree-breakglass

# Break-glass report file — detects tampering/deletion of phone-home records
-w /var/run/identree-breakglass-used -p wa -k identree-breakglass-report

# identree client config — detects credential theft or config tampering
-w /etc/identree/ -p wa -k identree-config

# PAM sudo config — detects attempts to bypass identree's PAM module
-w /etc/pam.d/sudo -p wa -k identree-pam-config

# SSSD config — detects LDAP redirect attacks
-w /etc/sssd/sssd.conf -p wa -k identree-sssd-config

# mTLS client private key — detects key exfiltration
-w /etc/identree/client.key -p r -k identree-mtls-key
AUDIT_RULES
    augenrules --load 2>/dev/null || true
    echo "auditd rules installed"
fi

# ── Setup (PAM + optional SSSD) ──────────────────────────────────────────────

SETUP_FLAGS=""
if [ "${SETUP_SSSD:-0}" = "1" ]; then
    SETUP_FLAGS="--sssd"
fi

echo "Running identree setup..."
"$INSTALL_DIR/identree" setup $SETUP_FLAGS

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

# ── Auditd rules ──────────────────────────────────────────────────────────────
if [ -f /etc/audit/rules.d/identree.rules ]; then
    rm -f /etc/audit/rules.d/identree.rules
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load 2>/dev/null || true
    fi
    echo "Removed auditd rules"
fi

# ── Systemd / cron ────────────────────────────────────────────────────────────
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now identree-rotate.timer 2>/dev/null || true
    systemctl disable --now identree-heartbeat.timer 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/identree-rotate.service" "$SYSTEMD_DIR/identree-rotate.timer"
    rm -f "$SYSTEMD_DIR/identree-heartbeat.service" "$SYSTEMD_DIR/identree-heartbeat.timer"
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

// customInstallScriptPath and customInstallSigPath are the on-disk locations
// for operator-uploaded custom install scripts and their signatures.
const customInstallScriptPath = "/config/custom-install.sh"
const customInstallSigPath = "/config/custom-install.sh.sig"

// customInstallMu protects reads/writes to the custom install script files.
// This is a package-level mutex since the paths are fixed.
var customInstallMu sync.RWMutex

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

// installScript returns the install script bytes to serve. If a verified
// custom script exists on disk, it is returned; otherwise the default
// staticInstallScript is returned.
func (s *Server) installScript() []byte {
	customInstallMu.RLock()
	defer customInstallMu.RUnlock()

	scriptData, err := os.ReadFile(customInstallScriptPath) // #nosec G703 -- server-controlled config path
	if err != nil {
		return []byte(staticInstallScript)
	}
	sigData, err := os.ReadFile(customInstallSigPath) // #nosec G703 -- server-controlled config path
	if err != nil {
		return []byte(staticInstallScript)
	}

	// Verify the custom script signature before serving it.
	if s.installVerifyKey == nil {
		return []byte(staticInstallScript)
	}
	sig := strings.TrimSpace(string(sigData))
	if !signing.VerifyScript(s.installVerifyKey, scriptData, sig) {
		slog.Warn("custom install script signature verification failed, serving default")
		return []byte(staticInstallScript)
	}

	return scriptData
}

// renderInstallScript returns the install script as bytes.
// Used by the deploy handler to pipe the script directly over SSH.
func (s *Server) renderInstallScript() ([]byte, error) {
	return s.installScript(), nil
}

// installConfigJSON returns the deployment-specific JSON config.
type installConfigJSON struct {
	ServerURL  string `json:"server_url"`
	InstallURL string `json:"install_url,omitempty"`
	LDAPBaseDN string `json:"ldap_base_dn,omitempty"`
}

// handleInstallConfig serves the per-deployment configuration as JSON.
// GET /install-config.json
// Authenticated via X-Shared-Secret header.
func (s *Server) handleInstallConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.verifySharedSecret(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cfg := installConfigJSON{
		ServerURL:  s.baseURL,
		LDAPBaseDN: s.cfg.LDAPBaseDN,
	}
	// Only include install_url if it differs from the external URL.
	if s.cfg.InstallURL != "" && s.cfg.InstallURL != s.cfg.ExternalURL {
		cfg.InstallURL = s.installServerURL()
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(cfg); err != nil {
		slog.Error("install-config.json encode error", "err", err)
	}
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

// handleInstallScript serves the static installer script.
// GET /install.sh
// If a verified custom script exists, it is served instead of the default.
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	script := s.installScript()

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=install.sh")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(script)
}

// handleInstallScriptSig serves the Ed25519 signature of the install script.
// GET /install.sh.sig
func (s *Server) handleInstallScriptSig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.installSigningKey == nil {
		http.Error(w, "signing not configured", http.StatusServiceUnavailable)
		return
	}

	script := s.installScript()
	sig := signing.SignScript(s.installSigningKey, script)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, sig)
}

// handleInstallPubKey serves the Ed25519 public key used to verify the install script signature.
// GET /install.pub
func (s *Server) handleInstallPubKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.installVerifyKey == nil {
		http.Error(w, "signing not configured", http.StatusServiceUnavailable)
		return
	}

	pubPEM := signing.EncodePubKeyPEM(s.installVerifyKey)

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(pubPEM)
}

// maxCustomScriptSize is the maximum size for uploaded custom install scripts (1 MB).
const maxCustomScriptSize = 1 << 20

// handleAdminInstallScript handles custom install script management.
//
//	GET    /api/admin/install-script → returns the current custom script (or 404)
//	POST   /api/admin/install-script → upload a new custom script + signature
//	DELETE /api/admin/install-script → revert to default installer
func (s *Server) handleAdminInstallScript(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAdminInstallScriptGet(w, r)
	case http.MethodPost:
		s.handleAdminInstallScriptPost(w, r)
	case http.MethodDelete:
		s.handleAdminInstallScriptDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminInstallScriptGet(w http.ResponseWriter, r *http.Request) {
	adminUser := s.verifyJSONAdminAuth(w, r)
	if adminUser == "" {
		return
	}

	customInstallMu.RLock()
	defer customInstallMu.RUnlock()

	scriptData, err := os.ReadFile(customInstallScriptPath) // #nosec G703 -- server-controlled config path
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "no custom script configured"}) //nolint:errcheck
		return
	}
	sigData, _ := os.ReadFile(customInstallSigPath) // #nosec G703 -- server-controlled config path

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"script":    string(scriptData),
		"signature": strings.TrimSpace(string(sigData)),
	})
}

func (s *Server) handleAdminInstallScriptPost(w http.ResponseWriter, r *http.Request) {
	adminUser := s.verifyJSONAdminAuth(w, r)
	if adminUser == "" {
		return
	}

	jsonErr := func(code int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
	}

	if s.installVerifyKey == nil {
		jsonErr(http.StatusServiceUnavailable, "signing not configured")
		return
	}

	// Parse multipart form.
	if err := r.ParseMultipartForm(maxCustomScriptSize + 4096); err != nil {
		jsonErr(http.StatusBadRequest, "invalid multipart form")
		return
	}

	scriptFile, _, err := r.FormFile("script")
	if err != nil {
		jsonErr(http.StatusBadRequest, "missing script file")
		return
	}
	defer scriptFile.Close()

	scriptData, err := io.ReadAll(io.LimitReader(scriptFile, maxCustomScriptSize+1))
	if err != nil {
		jsonErr(http.StatusBadRequest, "error reading script")
		return
	}
	if len(scriptData) > maxCustomScriptSize {
		jsonErr(http.StatusBadRequest, "script exceeds maximum size")
		return
	}

	sigStr := strings.TrimSpace(r.FormValue("signature"))
	if sigStr == "" {
		jsonErr(http.StatusBadRequest, "missing signature")
		return
	}

	// Verify the signature.
	if !signing.VerifyScript(s.installVerifyKey, scriptData, sigStr) {
		jsonErr(http.StatusBadRequest, "invalid signature")
		return
	}

	// Write to disk atomically.
	customInstallMu.Lock()
	defer customInstallMu.Unlock()

	dir := filepath.Dir(customInstallScriptPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		jsonErr(http.StatusInternalServerError, "internal error")
		return
	}
	if err := os.WriteFile(customInstallScriptPath, scriptData, 0600); err != nil {
		jsonErr(http.StatusInternalServerError, "internal error")
		return
	}
	if err := os.WriteFile(customInstallSigPath, []byte(sigStr+"\n"), 0600); err != nil { // #nosec G703 -- server-controlled config path
		// Clean up the script file if sig write fails.
		os.Remove(customInstallScriptPath)
		jsonErr(http.StatusInternalServerError, "internal error")
		return
	}

	slog.Info("custom install script uploaded", "admin", adminUser, "size", len(scriptData))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

func (s *Server) handleAdminInstallScriptDelete(w http.ResponseWriter, r *http.Request) {
	adminUser := s.verifyJSONAdminAuth(w, r)
	if adminUser == "" {
		return
	}

	customInstallMu.Lock()
	defer customInstallMu.Unlock()

	os.Remove(customInstallScriptPath)
	os.Remove(customInstallSigPath)

	slog.Info("custom install script removed, reverted to default", "admin", adminUser)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}
