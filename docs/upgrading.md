# Upgrading identree

This document covers backup procedures, rollback steps, config variable renames, and known breaking changes across versions.

---

## Backup procedure

Always back up state files before upgrading. identree stores all persistent state in a single directory (default `/config/`).

1. Stop the running identree server:

   ```sh
   docker compose stop identree
   # or: systemctl stop identree
   ```

2. Copy the entire data directory:

   ```sh
   cp -a /config /config.bak-$(date +%Y%m%d)
   ```

   The files that matter:

   | File | Contents |
   |---|---|
   | `sessions.json` | Active approved sessions |
   | `uid-map.json` | UID/GID assignments (full mode) |
   | `host-registry.json` | Registered host registry |
   | `sudo-rules.json` | Sudo rules (bridge mode) |

   > File names can differ if you have overridden them with `IDENTREE_*_FILE` environment variables. Back up those paths instead.

3. Start the new server:

   ```sh
   docker compose up identree -d
   docker compose logs -f identree
   ```

---

## Rollback procedure

If you need to revert to the previous version:

1. Stop the new server:

   ```sh
   docker compose stop identree
   ```

2. Restore the backup files:

   ```sh
   cp /config.bak-<date>/sessions.json       /config/sessions.json
   cp /config.bak-<date>/uid-map.json        /config/uid-map.json
   cp /config.bak-<date>/host-registry.json  /config/host-registry.json
   cp /config.bak-<date>/sudo-rules.json     /config/sudo-rules.json
   ```

3. Switch the image tag back to the previous version in `docker-compose.yml` and start it:

   ```sh
   docker compose up identree -d
   ```

---

## State file compatibility

`sessions.json` (and all other state files) are **forward-compatible**: upgrading to a new version that adds fields will read old files fine — new fields get zero/default values. Downgrading after a newer version has written files may silently drop fields it did not know about, which is harmless in most cases but means new session or host attributes recorded by the newer version will be lost.

**Recommendation:** always back up state files before upgrading, and test the new version before discarding the backup.

---

## Config variable renames

The following environment variables were renamed in recent versions. The old names are **still accepted** and log a deprecation warning at startup; they will be removed in a future release.

| Old name | New name | Notes |
|---|---|---|
| `IDENTREE_SUDO_NO_AUTHENTICATE` | `IDENTREE_LDAP_SUDO_NO_AUTHENTICATE` | Renamed for namespace consistency |
| `IDENTREE_HISTORY_PAGE_SIZE` | `IDENTREE_DEFAULT_PAGE_SIZE` | Generalised to cover all paginated views |

If you see a log line like:

```
WARN deprecated env var used, please rename  old=IDENTREE_SUDO_NO_AUTHENTICATE new=IDENTREE_LDAP_SUDO_NO_AUTHENTICATE
```

update your `docker-compose.yml` or `/etc/identree/identree.conf` to use the new name.

---

## Breaking changes

### Escrow HKDF salt change

If you have set `IDENTREE_ESCROW_HKDF_SALT` to a new value (or set it for the first time after previously relying on the legacy static salt), **all existing escrow ciphertexts are invalidated**. Break-glass passwords stored under the old key derivation cannot be decrypted with the new salt.

Before changing `IDENTREE_ESCROW_HKDF_SALT`:

1. Back up all state files (see [Backup procedure](#backup-procedure)).
2. Note all registered hosts — they will need to re-enroll their break-glass passwords.
3. After the server restarts with the new salt, trigger a break-glass rotation on each host:

   ```sh
   identree rotate-breakglass --force
   ```

   Or use **Hosts → Rotate break-glass** in the admin UI.

If you never set `IDENTREE_ESCROW_HKDF_SALT`, the legacy static salt is used and a warning is logged at startup. It is strongly recommended to set a random deployment-specific salt:

```sh
openssl rand -hex 32
```

Add the result as `IDENTREE_ESCROW_HKDF_SALT` in your config **before** your first deployment so no migration is needed later.

---

## Known limitations

The following features are on the roadmap but not yet implemented. Do not rely on them being available in the current release.

| Feature | Status |
|---|---|
| SAML 2.0 identity provider support | Not implemented |
| mTLS client certificate authentication | Not implemented |
| Per-admin notification preferences (granular routing) | Not implemented |
| Approval policies (time windows, host-specific rules, step-up auth) | Not implemented |

Check the [GitHub issues](https://github.com/rinseaid/identree/issues) for the latest status and to add your vote or comments.
