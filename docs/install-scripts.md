# Install Script Architecture

This document describes how identree signs, serves, and verifies install scripts, and how to use custom scripts in production.

---

## Architecture

The install system uses three components:

1. **Static installer** (`/install.sh`) -- a shell script with no embedded secrets. It accepts the server URL as an argument and fetches runtime configuration at install time.
2. **Authenticated config endpoint** (`/install-config.json`) -- returns `server_url`, `install_url`, and `ldap_base_dn`. Requires `X-Shared-Secret` header or `IDENTREE_SHARED_SECRET` environment variable.
3. **Detached Ed25519 signature** (`/install.sh.sig`) -- proves the script was signed by the holder of the private key.

### Why this design

A compromised server can serve a tampered install script. By keeping the signing key off the server (in production), the script's integrity can be verified independently. Even if the server is fully compromised, the attacker cannot produce a valid signature for a modified script.

---

## Default flow (auto-generated keypair)

On first startup, identree generates an Ed25519 keypair and stores it at:

- `IDENTREE_INSTALL_SIGNING_KEY` (default: `/config/install-signing.key`)
- `IDENTREE_INSTALL_VERIFY_KEY` (default: `/config/install-signing.pub`)

The server signs the install script at startup and serves:

| Endpoint | Contents |
|---|---|
| `GET /install.sh` | The install script (static, no secrets) |
| `GET /install.sh.sig` | Detached Ed25519 signature (base64-encoded) |
| `GET /install.pub` | Ed25519 public verification key (PEM) |

To verify and run:

```sh
curl -sf https://identree.example.com/install.sh     -o /tmp/install.sh
curl -sf https://identree.example.com/install.sh.sig -o /tmp/install.sh.sig
curl -sf https://identree.example.com/install.pub    -o /tmp/install.pub

identree verify-install \
  --key /tmp/install.pub \
  --script /tmp/install.sh \
  --sig /tmp/install.sh.sig

sudo IDENTREE_SHARED_SECRET=xxx bash /tmp/install.sh https://identree.example.com
```

The auto-generated keypair is convenient for development and small deployments. For production, bring your own key (see below).

---

## Production flow (bring your own signing key)

In production, the signing private key should never reside on the identree server. Generate a keypair offline, configure the server with only the public key, and sign scripts on a trusted workstation.

### Generate a keypair

```sh
identree sign-script --generate-key
# Creates: install-signing.key (private), install-signing.pub (public)
```

Or use OpenSSL:

```sh
openssl genpkey -algorithm Ed25519 -out install-signing.key
openssl pkey -in install-signing.key -pubout -out install-signing.pub
```

### Configure the server

Set `IDENTREE_INSTALL_SIGNING_KEY` to the private key path if you want the server to auto-sign the default script, or omit it and upload pre-signed scripts via the admin API.

Set `IDENTREE_INSTALL_VERIFY_KEY` to the public key path so the server can serve it at `/install.pub`.

### Distribute the public key out-of-band

For the highest assurance, do not fetch the public key from the server at install time. Instead, bake it into your host images, distribute it via configuration management (Ansible, Puppet, Chef), or include it in your provisioning pipeline. This eliminates the trust-on-first-use (TOFU) dependency on the server.

---

## Custom install scripts

You can replace the default install script with a custom one. This is useful for organizations that need to integrate with internal package repositories, apply custom PAM configurations, or run additional setup steps.

### Write, sign, and upload

```sh
# Write your custom script
vim my-install.sh

# Sign it with your private key
identree sign-script --key ~/identree-signing.key --script my-install.sh
# Creates my-install.sh.sig

# Upload to server (admin API)
curl -X POST https://identree.example.com/api/admin/install-script \
  -H "Authorization: Bearer $API_KEY" \
  -F "script=@my-install.sh" \
  -F "signature=$(cat my-install.sh.sig)"

# Revert to default
curl -X DELETE https://identree.example.com/api/admin/install-script \
  -H "Authorization: Bearer $API_KEY"
```

After uploading, `GET /install.sh` serves your custom script and `GET /install.sh.sig` serves its signature. Reverting removes the custom script and restores the built-in default.

### View the current custom script

```sh
curl -sf https://identree.example.com/api/admin/install-script \
  -H "Authorization: Bearer $API_KEY"
```

Returns the custom script body if one is uploaded, or 404 if the default is active.

---

## Config endpoint

The install script fetches runtime configuration from the server during execution.

```
GET /install-config.json
Header: X-Shared-Secret: <shared-secret>
```

Response:

```json
{
  "server_url": "https://identree.example.com",
  "install_url": "https://identree.example.com",
  "ldap_base_dn": "dc=example,dc=com"
}
```

The `install_url` may differ from `server_url` in split-horizon DNS environments (configured via `IDENTREE_INSTALL_URL`). The shared secret authenticates the request, preventing unauthenticated hosts from discovering the server configuration.

---

## Verification

### How hosts verify

The `identree verify-install` command checks the Ed25519 signature against the script contents:

```sh
identree verify-install \
  --key /path/to/install-verify.pub \
  --script /tmp/install.sh \
  --sig /tmp/install.sh.sig
```

Exit code 0 means the signature is valid. Any non-zero exit code means the script has been tampered with or the signature does not match the public key.

### Verification in automation

For CI/CD pipelines and automated provisioning:

```sh
#!/bin/bash
set -euo pipefail

curl -sf "$SERVER/install.sh"     -o /tmp/install.sh
curl -sf "$SERVER/install.sh.sig" -o /tmp/install.sh.sig

# Public key baked into the image at build time
if ! identree verify-install \
    --key /etc/identree/install-verify.pub \
    --script /tmp/install.sh \
    --sig /tmp/install.sh.sig; then
  echo "FATAL: install script signature verification failed" >&2
  exit 1
fi

sudo IDENTREE_SHARED_SECRET="$SECRET" bash /tmp/install.sh "$SERVER"
```

---

## Security properties

- **Signing key never on server (production flow).** The private key stays on a trusted workstation or in a hardware security module. The server only holds the public key.
- **Signature verified before execution.** The `verify-install` command checks the detached signature before the script runs. A tampered script is rejected.
- **No embedded secrets.** The install script is static and contains no credentials. The shared secret is passed as an environment variable at runtime and used only to authenticate the config fetch.
- **Config endpoint is authenticated.** `/install-config.json` requires the shared secret, preventing unauthorized hosts from discovering the server URL or LDAP base DN.
- **Tampered scripts rejected.** Any modification to the script (even a single byte) invalidates the signature. The Ed25519 scheme provides 128-bit security.

---

## CLI commands

| Command | Description |
|---|---|
| `identree sign-script --key <private-key> --script <script-path>` | Sign a custom install script. Creates `<script-path>.sig`. |
| `identree verify-install --key <pub> --script <sh> --sig <sig>` | Verify a signed script against its detached signature. |

## Configuration variables

| Variable | Default | Description |
|---|---|---|
| `IDENTREE_INSTALL_SIGNING_KEY` | `/config/install-signing.key` | Path to Ed25519 private key for install script signing (auto-generated if absent) |
| `IDENTREE_INSTALL_VERIFY_KEY` | `/config/install-signing.pub` | Path to Ed25519 public key for install script verification (auto-generated if absent) |
