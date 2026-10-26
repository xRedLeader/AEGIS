# v1.5 work in progress — not ready for deployment

This feature branch is an **incomplete draft**. The first trusted HTTPS metadata helper has been committed. The session authority, operator approval signer, and adversarial tests have been developed locally but are **not all committed here** yet.

Before enabling authenticated testing, the changes must be rebased/integrated against the current v1.4.1 supervisor, reviewed to ensure credential operations do not bypass kernel-enforced network isolation, and validated on a supported Linux CI environment. Do **not** provide real secrets to this candidate or merge/release it yet.

Planned checks: operator-signed, expiring single-use grants; role/origin/route constraints; atomic session usage and replay prevention; independent revocation; race-safe in-flight cancellation; TLS verification; redacted evidence; protected secret files; and complete Linux containment tests.
