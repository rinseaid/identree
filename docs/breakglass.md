# Break-glass

Every managed host running the identree PAM helper stores a **bcrypt-hashed fallback password** locally. If the identree server is unreachable, the user is prompted to enter this password instead of waiting for an approval that will never come.

The break-glass password is:
- Auto-generated on first install
- Auto-rotated on a configurable schedule (default 90 days)
- Never stored in plaintext — only the bcrypt hash lives on the host
- Optionally escrowed to a secret manager so you can retrieve it when needed

---

## Managing break-glass passwords

```sh
# On the managed host — rotate immediately
identree rotate-breakglass

# Verify the current password works
identree verify-breakglass
```

You can also trigger rotation from the admin UI: open the Hosts page and click **Rotate** on any host, or **Rotate all** to cycle all hosts at once.

---

## Rotation schedule

```sh
# Server-side: push rotation defaults to all new clients
IDENTREE_CLIENT_BREAKGLASS_ROTATION_DAYS=90   # 0 = disable auto-rotation
IDENTREE_CLIENT_BREAKGLASS_PASSWORD_TYPE=random  # random | passphrase | alphanumeric
```

To force all existing clients to rotate immediately (e.g. after a suspected compromise), set:

```sh
IDENTREE_BREAKGLASS_ROTATE_BEFORE=2025-01-15T00:00:00Z
```

Clients whose hash is older than this timestamp will rotate on their next check-in.

---

## Escrow backends

Escrow is optional. Without it, the break-glass password exists only as a hash on the managed host — you can verify it works but cannot recover the plaintext. With escrow, the server stores the plaintext in a secret manager during rotation so you can retrieve it if needed.

### Local (no external service)

The simplest option. identree encrypts the secret with AES-256-GCM and stores it in its own database.

```sh
IDENTREE_ESCROW_BACKEND=local
IDENTREE_ESCROW_ENCRYPTION_KEY=your-32-byte-hex-key   # openssl rand -hex 32
```

### 1Password Connect

```sh
IDENTREE_ESCROW_BACKEND=1password-connect
IDENTREE_ESCROW_URL=https://1password-connect.example.com
IDENTREE_ESCROW_AUTH_SECRET=your-connect-token          # or use _FILE variant
IDENTREE_ESCROW_PATH=identree-breakglass                # vault name in 1Password
IDENTREE_ESCROW_WEB_URL=https://start.1password.com    # link shown in admin UI
```

### HashiCorp Vault

```sh
IDENTREE_ESCROW_BACKEND=vault
IDENTREE_ESCROW_URL=https://vault.example.com
IDENTREE_ESCROW_AUTH_ID=identree                        # Vault role / app ID
IDENTREE_ESCROW_AUTH_SECRET=your-vault-token            # or use _FILE variant
IDENTREE_ESCROW_PATH=secret/data/identree/breakglass    # KV path prefix
IDENTREE_ESCROW_WEB_URL=https://vault.example.com/ui
```

### Bitwarden Secrets Manager

```sh
IDENTREE_ESCROW_BACKEND=bitwarden
IDENTREE_ESCROW_URL=https://api.bitwarden.com
IDENTREE_ESCROW_AUTH_ID=your-machine-account-id
IDENTREE_ESCROW_AUTH_SECRET=your-access-token           # or use _FILE variant
IDENTREE_ESCROW_PATH=identree                           # project name prefix
IDENTREE_ESCROW_WEB_URL=https://vault.bitwarden.com
```

### Infisical

```sh
IDENTREE_ESCROW_BACKEND=infisical
IDENTREE_ESCROW_URL=https://app.infisical.com
IDENTREE_ESCROW_AUTH_ID=your-machine-identity-id
IDENTREE_ESCROW_AUTH_SECRET=your-service-token          # or use _FILE variant
IDENTREE_ESCROW_PATH=identree/breakglass                # path prefix
IDENTREE_ESCROW_WEB_URL=https://app.infisical.com
```

---

## Using `_FILE` variants for secrets

Any `IDENTREE_ESCROW_AUTH_SECRET` can be read from a file instead:

```sh
IDENTREE_ESCROW_AUTH_SECRET_FILE=/run/secrets/escrow-token
```

This is useful in Docker Swarm or Kubernetes where secrets are mounted as files.

---

## Client-side configuration

The break-glass hash file location on each managed host:

```sh
# /etc/identree/client.conf
IDENTREE_BREAKGLASS_ENABLED=true              # default true
IDENTREE_BREAKGLASS_FILE=/etc/identree-breakglass
IDENTREE_BREAKGLASS_ROTATION_DAYS=90
IDENTREE_BREAKGLASS_PASSWORD_TYPE=random      # random | passphrase | alphanumeric
```

`random` generates a 32-character random string. `passphrase` generates a memorable word sequence. `alphanumeric` generates a shorter alphanumeric string suitable for typing.
