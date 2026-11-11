# Security

This repository is a security engineering lab using synthetic data. It is not a production deployment or a compliance certification.

Do not commit `.gateway/`, private keys, generated account passwords, bearer tokens, session stores or audit databases. Generate a separate local CA and runtime for each installation. Keep the default loopback bind unless you have configured certificates, network boundaries and trusted ingress addresses for your environment.

For a suspected vulnerability, contact the maintainer through the contact options on the GitHub profile before posting exploit details in a public issue. Share a minimal reproduction with synthetic data and redacted credentials.

See `docs/portfolio-architecture.md` for the threat model and known limits.
