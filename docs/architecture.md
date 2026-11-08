# Architecture notes

The API is deliberately split into URL safety, phishing, network, threat-intelligence, and risk engines. Each engine returns structured evidence with a state (`suspicious`, `clean`, or `unavailable`) so the UI can distinguish lack of evidence from a failed check.

Production hardening should add an egress proxy, a background queue, PostgreSQL migrations, authentication/RBAC, provider-specific rate limiting and an audited admin review workflow. The current MVP already blocks restricted destinations, strips URL fragments, does not execute page JavaScript, and validates only the initial passive request.
