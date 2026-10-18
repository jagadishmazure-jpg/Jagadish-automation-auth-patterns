# ADR 001: Simulated cryptography (HMAC) instead of real PKI

## Status
Accepted

## Context
The repo needs to demonstrate authentication *decisions* -- what to check,
in what order, what to do on failure -- without requiring certificates,
a KDC, or network access. Tests must be deterministic and run offline.

## Decision
Simulate signatures and tickets with HMAC-SHA256 (stdlib). The checklists
(issuer trust, signature validity, expiry, identity binding) are real; the
cipher suite is a stand-in.

## Consequences
- Tests run anywhere with zero setup; demos are one `python3` command.
- Nothing here protects real secrets; the threat model says so explicitly.
- Adopters must replace simulations with real TLS/Kerberos/OAuth -- the
  implementation guide maps each module to its production counterpart.
