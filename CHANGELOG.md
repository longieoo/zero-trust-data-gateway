# Changelog

## 5.1.0 — 13 November 2026

- Enforce exact signed SQL obligations, including admin masks and row caps.
- Add tenant-scoped access requests, independent approval, revocation and real expiry.
- Add authenticated resource catalog and session/policy-bound keyset pagination.
- Extend the browser interface with approval management and paged data reads.
- Probe writable audit/access stores and classify corrupt replay history safely.
- Add encrypted full-runtime backup and isolated PostgreSQL restore verification.
- Fix Windows/Linux line endings and make Compose project identity configurable.
- Extend regression, live governance, browser and recovery gates; publish fresh evidence.

Details, validation and limits: [upgrade report](docs/upgrade-v5-v5.1.md).

## 5.0.0

Multi-tenant RLS, signed policy releases, replay/impact analysis and shared session revocation. Original recorded evidence is retained under `evidence/history/2026-10-23/`.
