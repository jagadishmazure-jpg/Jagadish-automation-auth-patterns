# ADR 003: Security inputs are required arguments, not optional defaults

## Status
Accepted (2026-10-18)

## Context

The 2026-10-18 review found nine bypasses. Most came from a secure check
being optional or missing: an mTLS server with no pinned CN accepted any
cert from a trusted CA, a tool grant with no approver worked, delegation
accepted any dict as the user, and the token endpoint issued any scope a
client asked for.

## Decision

Security-relevant inputs are required and validated at construction or at
call time:

- `MTLSServer` requires `expected_cn`; empty raises `ValueError`.
- `Delegation` requires a `user_validator`, and only signed user tokens may
  delegate.
- `grant()` requires `approved_by`, which must name someone other than the agent.
- `register()` records `allowed_scopes`, and tokens carry `iss` and `aud`.
- Authorization denials use `forbidden` or `scope_exceeded`, not
  `bad_signature`, so runbooks can tell "who are you" apart from "you may not".

## Consequences

Callers must state their trust decisions explicitly; tests and demos were
updated to do so. Forgetting a check is now a `TypeError` or `ValueError`
at startup instead of a silent bypass in production.
