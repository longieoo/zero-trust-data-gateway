# Contributing

Use Python 3.12 and the pinned requirements. Before proposing a change, run `python -m ruff check app tests scripts`, `python -m pytest -q` with OPA available, and `node tests/ui/gateway_session.cjs`.

For changes to tenant isolation, policy evaluation or data obligations, include a regression that exercises the security boundary. Use the live validation script on a dedicated local deployment when PostgreSQL RLS, certificate handling or recovery behavior changes.

Describe the failure or user-visible behavior, the change and how it was checked. Keep synthetic fixtures deterministic and preserve the distinction between recorded evidence and new test runs.

Never attach a local runtime, private certificate keys or unredacted tokens to a pull request.
