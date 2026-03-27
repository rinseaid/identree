# identree local test environment

Three-container stack for end-to-end testing of identree against a real PocketID instance with an Ubuntu LDAP client.

| Container | Purpose | Host ports |
|---|---|---|
| `identree-test-pocketid` | PocketID OIDC/API backend | 127.0.0.1:1411 |
| `identree-test-server` | identree (built from source) | 127.0.0.1:8090 (HTTP), 127.0.0.1:3389 (LDAP) |
| `identree-test-client` | Ubuntu 24.04 with nslcd/NSS LDAP | — |

## Prerequisites

- OrbStack running (docker context: `orbstack`)
- Go toolchain available (identree builds from source)

## First-time setup

### 1. Build and start pocketid + identree (without testclient)

```bash
cd /Users/rinseaid/Repositories/identree/test
docker --context orbstack compose up -d pocketid identree
```

Wait for both to be healthy (check with `docker --context orbstack compose ps`).

### 2. Run setup.sh to populate PocketID

```bash
./setup.sh
```

This creates three test users (`alice`, `bob`, `testadmin`), two groups (`developers`, `admins`), and an OIDC client for identree. The script prints the OIDC client ID and secret at the end.

### 3. Restart identree with OIDC credentials

```bash
OIDC_CLIENT_ID=<id from setup.sh> OIDC_CLIENT_SECRET=<secret from setup.sh> \
  docker --context orbstack compose up -d identree
```

### 4. Start the testclient

```bash
docker --context orbstack compose up -d testclient
```

## Using the testclient

Open a shell:

```bash
docker --context orbstack exec -it identree-test-client bash
```

## LDAP NSS lookups

From the testclient shell (or via `docker exec`):

```bash
# List all users via NSS (requires nslcd to be running)
getent passwd

# Look up a specific user
getent passwd alice

# List all groups
getent group

# Look up a specific group
getent group developers
```

Direct LDAP query (bypasses NSS, useful for debugging):

```bash
ldapsearch -H ldap://identree:3389 -x -b dc=test,dc=local "(objectClass=posixAccount)"
ldapsearch -H ldap://identree:3389 -x -b dc=test,dc=local "(objectClass=posixGroup)"
```

## PAM auth test

PAM authentication goes through identree's challenge/response flow. From the testclient shell:

```bash
# Attempt to switch to an LDAP user (triggers a PAM auth challenge)
su - alice
```

identree will log the challenge URL. Open it in a browser, complete the PocketID login, and the `su` will proceed.

To watch identree logs while testing:

```bash
docker --context orbstack logs -f identree-test-server
```

## Teardown

```bash
docker --context orbstack compose down -v
```

The `-v` flag removes the named volumes (`pocketid-data`, `identree-data`), giving a clean slate for the next run.
