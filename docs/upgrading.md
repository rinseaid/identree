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
   | `uidmap.json` | UID/GID assignments (full mode) |
   | `hosts.json` | Registered host registry |
   | `sudorules.json` | Sudo rules (bridge mode) |
   | `notification-channels.json` | Notification channel definitions |
   | `admin-notifications.json` | Per-admin notification preferences |

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
   cp /config.bak-<date>/sessions.json                /config/sessions.json
   cp /config.bak-<date>/uidmap.json                 /config/uidmap.json
   cp /config.bak-<date>/hosts.json                  /config/hosts.json
   cp /config.bak-<date>/sudorules.json              /config/sudorules.json
   cp /config.bak-<date>/notification-channels.json  /config/notification-channels.json
   cp /config.bak-<date>/admin-notifications.json    /config/admin-notifications.json
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
| SAML 2.0 identity provider support | Implemented — configure via `IDENTREE_SAML_*` variables (see [deployment-modes.md](deployment-modes.md)) |
| mTLS client certificate authentication | Implemented — configure via `IDENTREE_MTLS_*` variables (see [operations.md](operations.md)) |
| Per-admin notification preferences (granular routing) | Implemented — configure via **Admin > Notifications** (`/admin/notifications`) |
| Approval policies (time windows, host-specific rules, step-up auth) | Implemented — configure via **Admin > Policies** (`/admin/policies`) |
| Multi-approval workflows (N-of-M quorum with partial tracking) | Implemented — set `min_approvals` in policy |
| Break-glass policy override for emergency access | Implemented — set `break_glass_bypass` in policy; uses `/api/challenges/override` |
| Per-policy notification channels | Implemented — set `notify_channels` in policy |

### New SAML and mTLS configuration variables

If upgrading from a version before SAML 2.0 and mTLS support, note the following new environment variables:

- **SAML 2.0:** `IDENTREE_SAML_IDP_METADATA_URL`, `IDENTREE_SAML_ENTITY_ID`, `IDENTREE_SAML_CERTIFICATE`, `IDENTREE_SAML_PRIVATE_KEY`. Set these to enable SAML-based authentication in bridge mode as an alternative to OIDC.
- **mTLS:** `IDENTREE_MTLS_ENABLED`, `IDENTREE_MTLS_CA_CERT`, `IDENTREE_MTLS_CLIENT_CERT`, `IDENTREE_MTLS_CLIENT_KEY`. Set these to require mutual TLS client certificate authentication for API and PAM client connections.

These variables are optional and have no effect if left unset. Existing OIDC-only deployments continue to work without changes.

Check the [GitHub issues](https://github.com/rinseaid/identree/issues) for the latest status and to add your vote or comments.
