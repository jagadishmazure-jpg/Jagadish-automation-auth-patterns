# Threat model (STRIDE)

Scope: this patterns library (simulated). Production deployments inherit
these threats and must mitigate them with real infrastructure.

| Threat | Example | Mitigation in this repo | Production note |
|---|---|---|---|
| **Spoofing** | Attacker presents a forged token/ticket | HMAC signature verification on every token; tests for tampering | Use real asymmetric signatures (RS256), not HMAC |
| **Spoofing** | Forged claims dict passed as "the user" to delegation | `Delegation` takes a user-token validator and only accepts signed user tokens | Validate the user's IdP token (iss, aud, exp) before minting any delegation |
| **Spoofing** | Any cert from a trusted CA accepted as the job agent | `MTLSServer` requires `expected_cn`; other CNs are rejected | Pin SAN/SPIFFE ID per route, not only the CA |
| **Spoofing** | Token minted for API A replayed at API B | Tokens carry `iss` and `aud`; `validate(audience=...)` rejects others | Each resource server checks its own audience |
| **Tampering** | Audit log edited to hide access | Hash-chained log; `verify()` detects edits | Ship logs to append-only storage |
| **Repudiation** | "I never called that tool" | Every grant, call, and denial is audited with principal + reason | Centralize logs in a SIEM |
| **Information disclosure** | Secret leaks via logs | Keyed HMAC fingerprints only in audit; test scans the log for plaintext | Same rule; key from a vault, rotate it; secret scanning in CI |
| **Information disclosure** | Wrong password reveals "revoked"/"locked" | API keys and SAP check the secret first | Same; uniform errors at the edge |
| **Denial of service** | Vault outage kills all jobs | Fail-closed is explicit; `vault_unreachable` is retryable with backoff | Vault HA / multi-region |
| **Elevation of privilege** | Agent exceeds its grant | Subset rule on delegation; scope+grant checks per call | Same; grants need approval workflow |
| **Elevation of privilege** | Client requests `admin:all` | Endpoint issues only registered scopes (`scope_exceeded`) | Scope policy per client at the IdP |
| **Elevation of privilege** | Agent approves its own tool grant | `grant(..., approved_by=)` must name someone other than the agent; audited | Approval workflow with separate identities |
| **Elevation of privilege** | Delegation chained to extend lifetime | Only user tokens delegate; delegation `exp` capped at the user token's | Same; token exchange policy at the IdP |
| **Elevation of privilege** | Revoked key rotated back to life | `rotate()` refuses revoked keys | Same |
| **Cross-environment replay** | Sandbox token used in prod | Org/instance/service binding on tokens | Same; enforce at the API gateway too |

## Out of scope (known limitations)

- The HMAC "crypto" is a simulation for deterministic tests, not a security
  claim. Nothing here should protect real secrets.
- No protection against a compromised host: if the agent's machine is owned,
  its tokens are owned too. Host hardening is assumed.
- Clock-skew leeway is a tolerance, not a fix; NTP is the real control.
- The fake KDC/token endpoint have no rate limiting; production endpoints
  need it (brute-force protection).
- No revocation list for agent/delegation tokens (`jti` is present but not
  checked); a leaked token lives until expiry. Keep TTLs short.
- Kerberos authenticators have no replay cache, and the fake KDC issues a
  ticket for any service name. A real KDC knows its service principals.
- The vault has no per-caller authorization; production vaults need policies
  per identity.
