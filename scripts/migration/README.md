# ALLINAGENT — Private Production State Migration Toolkit (`scripts/migration/`)

This toolkit implements **Phase 17 Track B**: secure, zero-corruption, zero-repo-leakage migration of private operational state from an existing host onto a production Ubuntu 24.04 LTS VPS (`/opt/allinagent` + `/var/lib/allinagent`) while keeping the **public ALLINAGENT Git repository 100% clean**.

---

## Architecture & Security Guarantees

1. **Authenticated Envelope Encryption (`AES-256-GCM` + `PBKDF2-HMAC-SHA256`):**
   - Derives a 256-bit key with `PBKDF2HMAC(SHA256, iterations=600_000)` and a 256-bit CSPRNG salt.
   - Encrypts the compressed payload with `AESGCM` (96-bit CSPRNG nonce) and binds the entire cleartext header (`version`, `kdf_iterations`, `salt`, `nonce`, `payload_sha256`) as **Authenticated Associated Data (AAD)**.
2. **Strict Out-of-Repo Enforcement (`assert_outside_git_repo`):**
   - Both `export_private_state.py` and `import_private_state.py` enforce `assert_outside_git_repo(path)` on bundles, staging directories (`$TEMP` / `/tmp`, `0700` / `0600`), and unpacked state directories (`/var/lib/allinagent/...`) so private state can never enter a Git working tree.
3. **Online WAL-Safe SQLite Backups (`sqlite3.Connection.backup`):**
   - Snapshots root `state.db`, all 11 `pc*` worker profile `state.db` files, `findings.db`, and `workflow-ledger.db` via SQLite's online backup API, checkpoints into single-file `DELETE` journal mode, and verifies `PRAGMA integrity_check == 'ok'`.
4. **100% Identity Continuity (Company UUID + 11 Agent UUIDs):**
   - Preserves Paperclip PostgreSQL logical dump (`pg_dump --no-owner --no-acl` / `paperclipai db:backup`), `master.key` (`/var/lib/allinagent/secrets/paperclip-master.key`), `organization-roster.json`, and `office-data` stores while rewriting legacy host paths inside `agents.adapter_config` to `/var/lib/allinagent/hermes/profiles/pc*`, `/var/lib/allinagent/reports`, and `/workspaces` in-place without regenerating UUIDs.
5. **Single-Poller Telegram Cutover Guard (`MIG-02`):**
   - Prevents HTTP `409 Conflict` dual-polling by creating `/var/lib/allinagent/hermes/.telegram_cutover_lock` (honored by `components/hermes/entrypoint.sh`, which still runs `hermes_exec_daemon.py` while skipping `hermes gateway run`) until the source host poller is stopped and `--cutover-telegram` (or `--clear-telegram-cutover`) is explicitly passed.

---

## Quick Operator Workflow

### 1. Pre-Flight Consistency Check on Source Host (`--dry-run`)

```bash
python scripts/migration/export_private_state.py \
  --source-root /path/to/existing/platform \
  --dry-run
```

*(On Windows hosts, `ALLINAGENT_LEGACY_ROOT` and `LOCALAPPDATA` are also honored automatically when `--source-root` / `--hermes-home` are omitted.)*

### 2. Encrypted Export on Source Host (Writes Only to `$TEMP` / `/tmp`)

```bash
export ALLINAGENT_MIGRATION_PASSPHRASE="<strong-random-passphrase-min-12-chars>"
python scripts/migration/export_private_state.py \
  --source-root /path/to/existing/platform
```

### 3. Transfer & Restore on Ubuntu 24.04 VPS (`compose.yaml` + `/var/lib/allinagent`)

1. Stop the source host's active Hermes Telegram Gateway poller service or scheduled task so two `getUpdates` pollers never run simultaneously.
2. Ensure application containers on the target VPS are stopped (`docker compose -f /opt/allinagent/compose.yaml stop hermes paperclip office-bridge hermes3d vulnclaw`, keeping `postgres` up).
3. Run `import_private_state.py` (omit `--cutover-telegram` first if restoring in standby with `.telegram_cutover_lock`, or pass `--cutover-telegram` once the source poller is stopped):

```bash
export ALLINAGENT_MIGRATION_PASSPHRASE="<strong-random-passphrase-min-12-chars>"
python3 /opt/allinagent/scripts/migration/import_private_state.py \
  --bundle /tmp/allinagent-private-state-YYYYMMDDTHHMMSSZ.aiaenc \
  --target-root /opt/allinagent \
  --target-state-root /var/lib/allinagent \
  --target-hermes-root /var/lib/allinagent/hermes \
  --target-reports-root /var/lib/allinagent/reports \
  --target-secrets-root /var/lib/allinagent/secrets \
  --target-workspaces-root /workspaces \
  --cutover-telegram
```

4. If you restored in standby mode earlier, you can toggle `.telegram_cutover_lock` independently at cutover time:

```bash
# Place target Hermes into exec-daemon-only standby (skip Telegram polling):
python3 /opt/allinagent/scripts/migration/import_private_state.py --lock-telegram-cutover

# Authorize Telegram polling once source host poller is stopped:
python3 /opt/allinagent/scripts/migration/import_private_state.py --clear-telegram-cutover
```

5. Securely delete `/tmp/*.aiaenc*` and start the production stack (`docker compose -f /opt/allinagent/compose.yaml up -d`).
