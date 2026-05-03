# Auditd Monitoring

identree can install Linux auditd rules that monitor security-sensitive files on managed hosts. These rules create a kernel-level audit trail that is independent of identree itself -- even if the identree binary is compromised or removed, the audit log captures the event.

---

## What the rules monitor

| Rule | Key | What it detects |
|---|---|---|
| `-w /etc/identree/breakglass.hash -p r` | `identree-breakglass` | Reads of the break-glass password hash (brute-force attempts) |
| `-w /var/run/identree-breakglass-used -p wa` | `identree-breakglass-report` | Writes or attribute changes to the break-glass usage report file (tampering/deletion) |
| `-w /etc/identree/ -p wa` | `identree-config` | Writes or attribute changes in the identree config directory (credential theft, config tampering) |
| `-w /etc/pam.d/sudo -p wa` | `identree-pam-config` | Changes to the PAM sudo config (attempts to bypass identree's PAM module) |
| `-w /etc/sssd/sssd.conf -p wa` | `identree-sssd-config` | Changes to SSSD config (LDAP redirect attacks) |
| `-w /etc/identree/client.key -p r` | `identree-mtls-key` | Reads of the mTLS client private key (key exfiltration) |

---

## Installation

### Automatic (recommended)

The install script (`install.sh`) automatically installs auditd rules if `augenrules` is detected on the host. No additional flags are needed.

### Via setup command

```sh
sudo identree setup --sssd --auditd
```

The `--auditd` flag writes the rules to `/etc/audit/rules.d/identree.rules` and runs `augenrules --load` to activate them. If auditd is not installed, the flag is silently skipped with a message.

### Manual installation

Copy the rules file from `deploy/auditd/identree.rules` to the host:

```sh
sudo cp identree.rules /etc/audit/rules.d/identree.rules
sudo augenrules --load
```

Or extract the rules from the identree binary:

```sh
sudo identree setup --auditd --dry-run   # preview what would be written
sudo identree setup --auditd             # install rules only
```

---

## Verifying rules are active

```sh
# List all loaded rules filtered to identree
sudo auditctl -l | grep identree

# Expected output:
# -w /etc/identree/breakglass.hash -p r -k identree-breakglass
# -w /var/run/identree-breakglass-used -p wa -k identree-breakglass-report
# -w /etc/identree/ -p wa -k identree-config
# -w /etc/pam.d/sudo -p wa -k identree-pam-config
# -w /etc/sssd/sssd.conf -p wa -k identree-sssd-config
# -w /etc/identree/client.key -p r -k identree-mtls-key
```

---

## Searching audit logs

Use `ausearch` to query events by key:

```sh
# All identree-related events
sudo ausearch -k identree-breakglass
sudo ausearch -k identree-config
sudo ausearch -k identree-pam-config
sudo ausearch -k identree-sssd-config
sudo ausearch -k identree-mtls-key

# Events in the last hour
sudo ausearch -k identree-breakglass -ts recent

# Events from a specific date
sudo ausearch -k identree-config -ts 04/05/2026 00:00:00
```

Generate a report:

```sh
sudo aureport --file --key --summary | grep identree
```

---

## Forwarding audit logs to remote syslog

For tamper-resistance, forward audit logs off the host. A local root attacker can clear `/var/log/audit/audit.log`, but logs already forwarded to a remote collector are safe.

### Using audisp-remote (recommended)

Install the `audispd-plugins` package and configure `/etc/audisp/audisp-remote.conf`:

```
remote_server = syslog.example.com
port = 60
transport = tcp
```

Enable the plugin in `/etc/audisp/plugins.d/au-remote.conf`:

```
active = yes
direction = out
path = /sbin/audisp-remote
type = always
```

Restart auditd:

```sh
sudo systemctl restart auditd
```

### Using rsyslog

Add to `/etc/rsyslog.d/identree-audit.conf`:

```
# Forward audit logs to remote syslog
if $programname == 'audit' then @@syslog.example.com:514
```

---

## Security properties

- **Kernel-level monitoring.** auditd rules are loaded into the kernel. User-space processes cannot suppress audit events without unloading the auditd daemon (which itself generates an audit event).
- **Tamper detection.** If an attacker modifies `/etc/pam.d/sudo` to remove the identree PAM line, the `identree-pam-config` audit event fires before the write completes.
- **Independent of identree.** The audit trail works even if identree is not running, has been removed, or has been compromised. It is a defense-in-depth layer.
- **Immutable mode.** For maximum security, enable auditd's immutable mode (`-e 2` in `/etc/audit/audit.rules`). Once set, audit rules cannot be changed without a reboot -- even by root.

---

## Removing rules

The uninstall script automatically removes the rules file and reloads auditd. To remove manually:

```sh
sudo rm /etc/audit/rules.d/identree.rules
sudo augenrules --load
```
