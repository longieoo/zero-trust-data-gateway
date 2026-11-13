# Gateway API v5.1

All public traffic enters through `https://127.0.0.1:28443`. PostgreSQL, OPA and the Python service have no published host port. Use the generated CA and enrolled client certificate. Login creates a ten-minute bearer token bound to the presented certificate serial and account tenant. Generated account passwords live only in `.gateway/credentials.json`; never paste tokens into committed examples.

## Routes

| Method and path | Required context | Result |
|---|---|---|
| GET `/health` | HTTPS | 200 only when OPA, signed policy, business DB, session store, audit and access store are ready; otherwise 503 |
| POST `/auth/login` | Account/password | `access_token`, `token_type`, `expires_in`, `tenant_id`, `role`; login without a certificate does not authorize protected data |
| POST `/auth/logout` | Active bearer with matching certificate context | `revoked: true`; subsequent use is rejected |
| GET `/api/v1/catalog` | Bearer, enrolled device, trusted location | Tenant-scoped resource metadata, PII columns, page cap and grant requirement; listing is not an access decision |
| GET `/api/v1/data/{resource}` | Bearer, device/location, ABAC and optional grant | Filtered/masked rows with decision, obligations, policy revision, request ID and timing |
| GET `/api/v1/policy` | Bearer, enrolled device, trusted location | Current revision, engine revision, description and signer identifiers |
| GET `/api/v1/audit` | Same verified context | Own response events, or tenant events for admin; `limit=1..100`, optional `before` sequence |
| POST `/api/v1/audit/{request_id}/replay` | Authorized audit viewer | MATCH / MISMATCH / UNREPLAYABLE; never queries business rows |
| POST `/api/v1/policies/impact` | Verified tenant admin | Body `revision` and `limit=1..50`; bounded comparison against signed candidate |
| POST `/api/v1/access-requests` | Verified identity | 201 with pending request; body below |
| GET `/api/v1/access-requests` | Verified identity | Own requests, or same-tenant requests for admin; `before` and `limit=1..100` |
| POST `/api/v1/access-requests/{id}/approve` | Same-tenant admin, different requester | APPROVED with approval/expiry timestamps |
| POST `/api/v1/access-requests/{id}/revoke` | Same-tenant admin | REVOKED, including cancellation of a pending request |

## Protected data and pagination

`resource` is exactly `customers`, `financial` or `production`. No arbitrary SQL or resource-name interpolation is accepted. Query parameters are limited to `page_size` (integer 1–100) and optional `cursor`. Duplicate or unknown parameters return 422. A cursor requires a page size and must be passed back unchanged with the same requested size.

```http
GET /api/v1/data/customers?page_size=25
Authorization: Bearer <local-token>
```

The response includes `data`, `obligations` and `pagination: {page_size, has_more, next_cursor}`. Without `page_size`, legacy capped reads remain supported and `next_cursor` is null. The effective page size cannot exceed the signed release limit. A next cursor exists only when the SQL lookahead found another permitted row.

Cursor expiry is ten minutes. User/role/tenant/clearance, session, resource, policy revision or page-size changes invalidate it. Each page rechecks session, device, policy, approval, masking and RLS. Pages are ordered by ID and are not one frozen transaction; concurrent writes can affect later pages. Restart from page one after a policy change or new login.

## Access workflow

```json
{"resource":"production","purpose":"Review production logs for the approved investigation","duration_seconds":900}
```

Purpose must be a single line of 10–500 characters. Duration is an integer 60–3600 seconds; default 900. Pending requests expire after 24 hours. Approval starts the requested duration. The store limits duplicate active/pending requests, ten pending requests per user and 50,000 total records; capacity errors do not silently erase governance history.

The demo requires grants for production. An operator can change `GATEWAY_GRANT_REQUIRED` in Compose; unknown resource values prevent startup. A valid approval is an additional AND condition, evaluated after OPA ALLOW and before the protected SELECT. Approval cannot turn a department mismatch into ALLOW. Attribute changes invalidate old grants. Expiry/revocation affects new requests, not an already executing query.

State and audit use separate SQLite transactions. A 503 after a workflow mutation can leave the mutation committed; reload the request list before deciding whether to retry. Workflow purpose is sensitive plaintext in the local access store, included only inside encrypted backups, and is not added to public audit metadata.

## Interpreting failures

| HTTP | Examples | Protected business SELECT |
|---|---|---|
| 401 | Invalid/expired token, inactive session, certificate mismatch | Not executed |
| 403 | UNTRUSTED_DEVICE, DEPARTMENT_MISMATCH, ACCESS_APPROVAL_REQUIRED | Not executed |
| 404 | Unknown resource or unavailable request in the caller tenant | Not executed |
| 409 | Duplicate active request, already processed approval | Not executed |
| 422 | Invalid input/cursor/candidate | Not executed |
| 429 | Login or pending-request limit | Not executed |
| 503 | OPA_UNAVAILABLE, INVALID_POLICY, INVALID_OPA_RESPONSE | Not executed |
| 503 | Audit or SQL enforcement failure | Inspect `db_queried`: a SELECT may already have been attempted |

`db_queried` refers to the protected business query. Authentication, audit, access-store checks and health probes can use their own database operations even when it is false. A response flag is useful application evidence, not an independent PostgreSQL server trace. Never infer a successful SELECT or data delivery from an intent-only audit event.
