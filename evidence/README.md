# Verification evidence

The root artifacts describe the v5.1.0 local verification recorded in `verification-receipt.json`. `scripts.verify_release` executes each gate sequentially against one source/configuration fingerprint. `scripts.summarize_evidence` rejects incomplete results and recomputes benchmark percentiles from the raw CSV before generating the results document.

- `pytest.xml`: actual Python suite outcomes and duration.
- `live-validation.json`: CA-verified HTTPS/mTLS, tenant/RLS, signed releases and failure recovery.
- `governance.json`: approval, real expiry, revocation and bound pagination.
- `browser.json` / `images/`: real browser outcomes and screenshots using synthetic data.
- `recovery.json`: isolated PostgreSQL and SQLite state reconciliation, without private material.
- `benchmark.json` / `benchmark-samples.csv`: local closed-loop measurements and separate warmup.
- `dependency-audit.json`: time-specific Python dependency vulnerability lookup.
- `verification-receipt.json`: code/config hashes, per-step exit status and elapsed time. Logs referenced by the receipt stay local and are uploaded as CI artifacts; they are not part of the source package.

Browser captures use a real client certificate and ignore locally generated server-CA warnings only inside the automated browser context. Python live and benchmark requests verify the CA chain and hostname. Dependency audit does not cover container OS packages or constitute a certification. `db_queried` refers to the protected business SELECT, not all session/audit/health operations.

Earlier evidence is retained under `history/2026-10-23/`, with its original dates and limitations. It is never used as a fresh result. Runtime credentials, private keys, encrypted backups, audit/session/access databases and decrypted snapshots are excluded from public evidence. Machine names in JUnit may be normalized for publication without changing counts, test cases or measured values.
