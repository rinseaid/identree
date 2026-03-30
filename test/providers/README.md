# Provider Test Environments

Isolated Docker Compose environments that validate identree in **bridge mode** against popular free/self-hostable OIDC, LDAP, and secrets management providers.

Bridge mode = no `IDENTREE_POCKETID_API_KEY`; identree handles PAM challenges only; an external provider serves LDAP and OIDC.

## Environments

| Directory | OIDC provider | LDAP for NSS | identree port | Complexity |
|-----------|--------------|--------------|---------------|------------|
| `lldap-dex/`  | [Dex](https://dexidp.io) (LDAP connector → lldap) | lldap | 8091 | Low |
| `keycloak/`   | [Keycloak](https://www.keycloak.org) (dev mode)   | lldap | 8092 | Medium |
| `kanidm/`     | [Kanidm](https://kanidm.com) (HTTP mode)          | Kanidm built-in LDAP | 8093 | Medium |

The existing PocketID environment (`test/docker-compose.yml`) tests **full mode** — separate from this directory.

## Escrow Test Environments

These environments swap the default **local** escrow backend for an external secrets manager, using lldap+Dex for OIDC (same users/groups/ports pattern as above).

| Directory | Escrow backend | Escrow port | identree port |
|-----------|---------------|------------|---------------|
| `escrow/vault/` | [HashiCorp Vault](https://www.vaultproject.io) KV v2 (dev mode) | 8200 | 8094 |

> **Vaultwarden note:** Vaultwarden implements the Bitwarden **Password Manager** API (client-side encrypted ciphers). identree's `bitwarden` escrow backend requires the **Secrets Manager** API (`/api/secrets`), which Vaultwarden does not implement. To test Bitwarden SM escrow, use an official Bitwarden self-hosted instance or the Bitwarden cloud. For a fully self-hostable SM-style backend, use [Infisical](https://infisical.com) (already supported via the `infisical` backend).

## Port Allocation

| Service | PocketID (full) | lldap+Dex | Keycloak | Kanidm | Vault escrow |
|---------|----------------|-----------|----------|--------|--------------|
| identree HTTP | 8090 | 8091 | 8092 | 8093 | 8094 |
| identree LDAP | 3389 | — | — | — | — |
| Provider OIDC | 1411 | 5556 (Dex) | 8180 (Keycloak) | 8443 | 5557 (Dex) |
| Provider LDAP | 3389 | 3891 (lldap) | 3892 (lldap) | 3636 | 3893 (lldap) |
| lldap admin UI | — | 17171 | 17172 | — | 17173 |
| Escrow service | — | — | — | — | 8200 (Vault) |

All host bindings are `127.0.0.1` only.

## Quick Start

### lldap + Dex

```bash
make test-lldap-dex        # bring up: lldap, Dex, identree, testclient
make test-lldap-dex-setup  # create users/groups in lldap + set passwords
make test-lldap-dex-validate  # automated smoke tests
# ...
make test-lldap-dex-down
```

### Keycloak + lldap

```bash
make test-keycloak         # bring up: lldap, Keycloak, identree, testclient
make test-keycloak-setup   # create realm + users in Keycloak; users in lldap
# setup.sh prints a KEYCLOAK_CLIENT_SECRET — restart identree with it:
KEYCLOAK_CLIENT_SECRET=<secret> \
  docker compose -f test/providers/keycloak/docker-compose.yml up -d identree
make test-keycloak-validate
make test-keycloak-down
```

### Kanidm

```bash
make test-kanidm           # bring up: Kanidm, identree, testclient
make test-kanidm-setup     # recover idm_admin, create OAuth2 client + users + groups
# setup.sh prints a KANIDM_CLIENT_SECRET — restart identree with it:
KANIDM_CLIENT_SECRET=<secret> \
  docker compose -f test/providers/kanidm/docker-compose.yml up -d identree
make test-kanidm-validate
make test-kanidm-down
```

### Vault Escrow

```bash
make test-vault-escrow         # bring up: lldap, Dex, Vault (dev), identree, testclient
make test-vault-escrow-setup   # create lldap users/groups + verify Vault KV v2 mount
make test-vault-escrow-validate
# Check Vault UI for break-glass secret: http://localhost:8200 (token: identree-vault-test-token)
# Secret path: secret/identree/vault-escrow-test-host
make test-vault-escrow-down
```

Vault runs in **dev mode**: auto-unsealed, in-memory storage, KV v2 mounted at `secret/`. The root token is fixed at `identree-vault-test-token`. This is not suitable for production — test environments only.

To inspect the escrowed break-glass secret directly:

```bash
curl -sf http://localhost:8200/v1/secret/data/identree/vault-escrow-test-host \
  -H "X-Vault-Token: identree-vault-test-token" | python3 -m json.tool
```

## Manual Testing (PAM challenge flow)

After setup, the PAM challenge flow requires a human to click "Approve" in the identree web UI:

```bash
# Get a shell in the testclient container
docker exec -it identree-lldap-dex-client bash

# Switch to alice (resolved via LDAP)
su - alice

# Run sudo — this triggers the identree PAM challenge
sudo whoami

# identree sends a push/web notification; open http://localhost:809x in your browser
# and approve the request. sudo completes with exit 0.
```

Break-glass (offline fallback):

```bash
# Inside testclient, view the break-glass password
docker exec identree-lldap-dex-client cat /dev/stdin  # retrieve from escrow
# Or rotate: docker exec identree-lldap-dex-client identree rotate-breakglass
```

## Test Users

All environments provision the same three test accounts:

| Username | Password | Groups | UID | GID |
|----------|----------|--------|-----|-----|
| alice | AliceTest123! | developers | 10001 | 20001 |
| bob | BobTest123! | developers | 10002 | 20001 |
| testadmin | AdminTest123! | admins (→ identree admin) | 10003 | 20002 |

> **Kanidm:** user passwords are set separately via credential reset tokens. See `setup.sh` output.

## Automated Validation (`validate.sh`)

`validate.sh` runs checks that require no human interaction:

1. identree `/healthz` returns 200
2. OIDC discovery endpoint reachable and contains `issuer` field
3. LDAP port reachable from testclient
4. `getent passwd` resolves alice, bob, testadmin
5. `getent group` resolves developers, admins
6. Group membership: alice+bob in developers, testadmin in admins
7. `/etc/pam.d/sudo` references identree
8. Break-glass hash file provisioned
9. identree `client.conf` exists
10. Static sudoers file in place (bridge mode)

The actual PAM challenge/approval flow (step 7+) requires a browser and is not automated.

## SSSD Schema Notes

lldap and Kanidm use **rfc2307bis** group schema (`groupOfUniqueNames`/`uniqueMember` or `groupOfNames`/`member` with full DN values). This differs from the default `rfc2307` used by the PocketID full-mode environment.

The `testclient/entrypoint.sh` accepts these env vars to adapt per-provider:

| Var | Default | lldap/Kanidm value |
|-----|---------|-------------------|
| `SSSD_SCHEMA` | `rfc2307` | `rfc2307bis` |
| `SSSD_USER_OBJECT_CLASS` | (schema default) | `inetOrgPerson` / `posixaccount` |
| `SSSD_GROUP_OBJECT_CLASS` | (schema default) | `groupOfUniqueNames` / `posixgroup` |
| `SSSD_GROUP_MEMBER_ATTR` | (schema default) | `uniqueMember` / `member` |
| `LDAP_BIND_DN` | (anonymous) | `uid=admin,ou=people,...` |
| `LDAP_BIND_PW` | (empty) | admin password |
| `SSSD_SUDO_PROVIDER` | `ldap` | `none` (bridge mode) |
| `STATIC_SUDO_RULES` | (empty) | semicolon-separated rules |

## GitHub Actions

`.github/workflows/provider-tests.yml` runs all three environments in parallel on push to `dev`/`main`. Each job:

1. `docker compose up --build -d`
2. Wait for health checks
3. `setup.sh`
4. Restart identree with the generated OIDC client secret
5. Wait for sssd enumeration (`sleep 15–20`)
6. `validate.sh`
7. `docker compose down` (always, even on failure)

Logs are captured on failure for debugging. The Kanidm job may need adjustment if the `kanidm` CLI in the container image changes its non-interactive auth interface between versions — see `kanidm/setup.sh` for the recovery approach.

### Running a specific provider in CI

```yaml
# workflow_dispatch input:
provider: lldap-dex   # or keycloak, kanidm, vault-escrow, all
```

Or trigger via the GitHub Actions UI → "Run workflow" → select provider.
