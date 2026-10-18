# Security policy

## Scope

This is a **patterns library with simulated cryptography** (HMAC stand-ins,
fake KDC/token endpoints). It demonstrates authentication *decision logic*;
it does not protect real secrets and must not be used as a security control.

## Reporting a vulnerability

If you find a real security issue (e.g. a test that passes but shouldn't,
a bypass of a documented enforcement), please report it via a private
vulnerability report on GitHub (Security tab) rather than a public issue.

## What is enforced (and tested)

- Fail-closed vault reads; plaintext never in the audit log
- Revocation is never retryable
- Delegation subset rule (agent cannot exceed delegator)
- Org/instance/service binding on tokens
- Hash-chained audit with tamper detection

See `docs/threat-model.md` for the full STRIDE analysis and known
limitations.
