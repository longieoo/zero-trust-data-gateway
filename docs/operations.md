# Operations and recovery

The default local deployment is `abac-portfolio`. `python -m scripts.portfolio init --project abac-complete` selects a separate Compose project for a fresh checkout; subsequent commands read this identity from `.gateway/gateway.env`. An explicit `GATEWAY_COMPOSE_PROJECT` environment variable takes precedence. Its four services are isolated from other Compose projects. Gateway database and audit state live in named volumes; `.gateway/` contains the private CA, credentials, policy signing keys, trust set and release files. None of this runtime belongs in Git or public artifacts.

## Readiness and a fresh checkout

Use Python 3.12 and the locked requirements. The `.gitattributes` file keeps shell, Rego and configuration sources on LF when checked out on Windows as well as Linux; this prevents CRLF shell failures and avoids deployment fingerprints changing because of a checkout's line-ending defaults.

```bash
python -m scripts.portfolio init
python -m scripts.portfolio doctor
python -m scripts.portfolio up
python -m scripts.portfolio doctor --live
```

`doctor` checks Docker availability, the active release signatures and interpreter fingerprint, and Compose configuration. `doctor --live` additionally requests `/health` over HTTPS with the generated CA and checks OPA/database/policy/audit/session/access readiness. It does not use an insecure TLS bypass.

On POSIX hosts, initialization restricts the outer runtime directory to mode 0700 and generated private keys/credentials to 0600. The mounted `server/` subtree uses readable configuration files (0644) and searchable directories (0755) so the unprivileged Gateway UID 10001 can read it; the private CA and maintainer signing keys are outside that mount. The outer private directory still restricts access by unrelated host users. On Windows, the runtime inherits the account's filesystem ACL; protect that account and keep the directory outside shared/public folders.

## Create an encrypted backup

```bash
python -m scripts.backup_restore create
# Or choose a new name inside the protected runtime backup directory:
python -m scripts.backup_restore create --output .gateway/backups/before-change.ztbackup
```

This is a **maintenance operation**. It records whether the proxy/Gateway were running, acquires the policy activation lock, stops only those services, captures a PostgreSQL custom-format dump and Gateway state, then restarts only the services that were previously running and waits up to 90 seconds for running/healthy status before returning. Other Docker projects and the source database volume are not deleted or replaced.

The backup contains runtime configuration, certificates, signing material, registry, policy releases, the database dump and Gateway state files. It is encrypted with AES-GCM. Its authenticated ZIP manifest records SHA-256, size and file permission mode. The encryption key is `.gateway/backup.key`, generated once using exclusive creation and **excluded from the backup itself**. Keep that key in a separate protected offline backup. Losing it makes encrypted backups unreadable.

Backups can only be created under `.gateway/backups/` and never overwrite an existing archive. Keep this directory ignored by Git. Archives contain secrets even though they are encrypted; do not attach them or the key to public CI artifacts, issues or pull requests.

The consistency boundary assumes all business/session writes use this Gateway and policy activation uses the normal CLI. A host administrator bypassing these controls can invalidate the boundary. The backup is not a distributed snapshot of unrelated external systems.

## Restore to a new directory and verify the database

```bash
python -m scripts.backup_restore restore .gateway/backups/before-change.ztbackup \
  --destination .gateway/restored/check-before-change --verify-db --report evidence/recovery.json
```

On PowerShell, put this command on one line or use PowerShell's continuation syntax. The destination must not already exist. The tool authenticates the archive, rejects duplicate/traversing/symlink entries and verifies every manifest checksum before it creates the restore directory. Files are created exclusively; POSIX permission modes are preserved without setuid/setgid bits.

`--verify-db` starts a new disposable PostgreSQL container with **network disabled and no host ports**. It creates the runtime role names, restores the dump, and compares business/session-table counts and content fingerprints with the values captured during backup. It checks that all three business tables still enable and force RLS, that their restrictive tenant and permissive scope policies survived, and that the reader has SELECT without INSERT/UPDATE/DELETE or superuser/BYPASSRLS privileges. A query under the reader role without tenant/scope context must return zero rows. Session-role privileges are checked separately. Finally it removes only that uniquely named verification container and its anonymous volume. The running deployment's data and named volumes remain untouched.

The same verification opens the restored SQLite databases in read-only mode, runs integrity checks and compares every table's ordered logical rows against the backup-time count/digest. Every stored audit replay snapshot is authenticated and decrypted using the restored audit key, and its plaintext digest is compared with the backup-time digest. Only counts and verification flags are printed; decrypted snapshots and keys stay private. The access request/grant history is included in this comparison.

The restored directory contains `runtime/`, `state/`, `database.dump`, `reconciliation.json`, `state-reconciliation.json` and `RESTORE_MANIFEST.json`. This verification does not redirect a running Gateway to the restored database, change production credentials, or prove a multi-host recovery objective. Promoting a verified restore requires a planned deployment procedure, correct database role passwords, the matching application interpreter and a deliberate routing change.

## Recovery checks in CI

The workflow exercises encrypted backup and isolated restore after live deployment validation. `--report evidence/recovery.json` writes a public machine-readable receipt after successful isolated database/state verification, including its UTC timestamp, verified file count and safety checks. It contains no runtime paths, secret values or data rows. Only this receipt and the sanitized verification log go to `evidence/`; the archive, encryption key, CA and credentials remain under ignored `.gateway/`. A successful restore records actual database reconciliation rather than merely checking that a backup file exists.

No RPO/RTO or high-availability guarantee is claimed. A single host's loss still requires restoring the private runtime, encryption key, data and deployment configuration on a suitable replacement host.
