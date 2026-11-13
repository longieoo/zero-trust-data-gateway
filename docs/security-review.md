# Security review of the portfolio hardening

Reviewed on 13 November 2026. This is a source review with regression testing of a local portfolio deployment, not an independent penetration test or a security certification. Current full-suite, deployment and browser results belong in the verification receipt; historical results are not substituted for a new run.

## Findings addressed

| Boundary | Finding | Change and regression evidence |
| --- | --- | --- |
| PDP to SQL enforcement | A correct revision label did not prove that the returned plan matched the signed view profile. Admin masking or the signed row cap could drift while tenant checks still passed. | The evaluator independently checks tenant, resource, department/all scope, the exact supported mask, full allowed column set and the signed row cap. Altered plans and malformed PDP envelopes fail with `INVALID_OPA_RESPONSE` before a protected query. See `tests/unit/test_security_hardening.py`. |
| Signed release verification | Ambiguous signature mappings, unknown signers and invalid approval quorums needed consistent rejection; non-finite JSON numbers could enter canonical encoding. | Approval quorum is strictly one or two distinct Ed25519 public keys. Signer identifiers and signature envelopes are validated, unknown/invalid signatures raise a validation error, and canonical JSON rejects NaN/Infinity. Release content reads are bounded to 8 MB. |
| Audit availability | A readable SQLite file could report ready even when the service could no longer persist an audit event. | Audit readiness now performs `quick_check` and a rollback-only write transaction. Read-only storage fails readiness; the probe leaves no synthetic audit events or retained health rows. |
| Audit input contracts | Internal audit callers could bypass HTTP page limits or serialize excessively large metadata/snapshots. | Page bounds are checked inside the store, booleans are rejected as integer limits, metadata is bounded to 64 KB and replay plaintext to 8 MB. Stored ciphertext is size checked and decoded strictly before authenticated decryption. These are per-operation bounds, not disk-retention guarantees. |
| Replay availability and integrity | A corrupt ciphertext or a validly encrypted legacy JSON value with an unexpected shape could escape replay classification. | Replay must return `UNREPLAYABLE`, with `db_queried: false`, for missing, malformed or undecryptable history. Regression cases cover absent/list/boolean/string snapshots, malformed release mappings, invalid base64, short ciphertext and failed AEAD authentication in `tests/integration/test_security_replay.py`. A corrupt record must never become a fabricated `MATCH`. |

## New access paths reviewed

The access-request workflow is an **additional gate**. A successful protected read requires normal identity/session/device checks, a valid policy release, OPA `ALLOW`, valid SQL obligations, and an unexpired approval when the resource is configured to require one. Approval never changes a tenant, bypasses a department denial, removes masking or grants an administrator unrestricted SQL.

Requests derive their identity from the verified Gateway callback. Tenant administrators can manage only requests in their tenant and cannot approve their own requests. The requester, tenant, resource, role, department and clearance are bound to a grant. Expiry and revocation are read from persistent storage on each protected request. Empty grant-required configuration preserves the existing ABAC access path; pending requests alone do not authorize a read.

Pagination uses authenticated keyset cursors. Each cursor binds the complete current subject, session ID, resource, active policy revision and requested page size; expiry and the last row ID are checked. Changing these inputs or tampering with a cursor cannot broaden access. Unknown/duplicate query parameters and invalid page sizes are rejected. Each page repeats policy and approval checks and uses tenant/department RLS and SQL masking. Without pagination, the existing signed row cap remains in effect. Pagination is not a database snapshot across multiple HTTP requests; concurrent inserts/deletes may change later pages.

Decision replay reproduces the recorded OPA decision and obligations. It does not query historical business rows, recreate a previous HTTP response, or replay today's approval/session state as historical authorization. For example, an OPA `ALLOW` may have been followed by `ACCESS_APPROVAL_REQUIRED` in the enforcement path. Response audit events record that final outcome separately.

## Focused verification

The following command was run locally against the reviewed sources:

```powershell
..\ZERO_TRUST_ABAC\source\.venv\Scripts\python.exe -m pytest tests/unit/test_security_hardening.py tests/unit/test_pagination.py tests/unit/test_access.py --confcutdir=tests/unit -q --tb=short
```

Result: **64 passed in 2.35 seconds**. These are mocked-PDP and isolated SQLite/FastAPI component checks. The run deliberately excludes the root real-OPA fixture. A subsequent integration run used the real OPA 1.4.2 executable:

```powershell
..\ZERO_TRUST_ABAC\source\.venv\Scripts\python.exe -m pytest tests/integration/test_access_enforcement.py tests/integration/test_security_replay.py tests/integration/test_pagination_api.py -q --tb=short
```

Result: **23 passed in 23.68 seconds**. This verifies the approval/revocation/expiry AND gate, an approved analyst's continued ABAC denial, malformed replay history, cursor enforcement and state-store readiness failures through the FastAPI routes. The database in these integration tests is an observable adapter, not live PostgreSQL. These focused runs do not establish Nginx mTLS, browser or Docker behavior. Each run emitted one dependency deprecation warning from the locally reused test environment. The complete suite and deployment gates must still pass before a release is claimed verified.

The evaluator participates in the interpreter fingerprint. Deployment after this change requires a freshly generated and independently approved matching release; copying an old active policy pointer is insufficient. The application release protocol remains signed JSON, not OPA's native bundle protocol.

## Residual limits

- **The PEP and host are trusted.** The Gateway chooses transaction-local PostgreSQL tenant/scope context. A compromised Gateway holding database credentials can select another context. RLS is defense in depth against accidental or unapproved queries from the intended application, not an isolation boundary against its fully compromised identity. The ingress must overwrite identity/device headers and keep its shared secret and internal route private.
- **Context is a demonstration model.** Device trust comes from certificate verification plus an enrollment registry; location comes from the ingress-observed address and configured networks. Docker NAT can affect that address. The small risk heuristic is not measured endpoint posture, continuous device telemetry or a machine-learning risk detector. Client private keys are ordinary files rather than TPM-bound keys.
- **Single-host state remains.** Audit and approval history use SQLite WAL. PostgreSQL can share sessions across Gateway instances, but distributed audit/approval coordination and multi-host failover are not demonstrated. Readiness is an observation, not a guarantee that a later write cannot fail.
- **No cross-store atomic commit is claimed.** An approval/session mutation and its response audit use different transactions. If the final audit write fails, a `503` can accompany an already-applied mutation; inspect persistent state before retrying. An audit failure after a business SELECT withholds the response, but must not be described as `db_queried: false`.
- **Audit confidentiality is not host-admin immutability.** AES-GCM authenticates snapshots and their associated metadata; an administrator with the audit key and filesystem control can replace history. Plain response metadata is not a remote append-only ledger. Automated retention, remote durable audit export and KMS rotation are not implemented; capacity and backup policy remain operator responsibilities.
- **Sampled impact is bounded evidence.** Comparing a candidate against recorded snapshots does not prove policy correctness for every future input. Demo signing keys generated on one machine demonstrate cryptographic quorum, not organizational separation of duties. Revocation is checked for new operations and does not cancel an already executing query.
