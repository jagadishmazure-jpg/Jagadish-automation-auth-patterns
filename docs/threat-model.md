# Threat model (STRIDE)

Scope: this patterns library (simulated). Production deployments inherit
these threats and must mitigate them with real infrastructure.

| Threat | Example | Mitigation in this repo | Production note |
|---|---|---|---|
| **Spoofing** | Attacker presents a forged token/ticket | HMAC signature verification on every token; tests for tampering | Use real asymmetric signatures (RS256), not HMAC |
| **Tampering** | Audit log edited to hide access | Hash-chained log; `verify()` detects edits | Ship logs to append-only storage |
| **Repudiation** | "I never called that tool" | Every grant, call, and denial is audited with principal + reason | Centralize logs in a SIEM |
| **Information disclosure** | Secret leaks via logs | Fingerprints only in audit; test scans the log for plaintext | Same rule; add secret scanning in CI |
| **Denial of service** | Vault outage kills all jobs | Fail-closed is explicit; `vault_unreachable` is retryable with backoff | Vault HA / multi-region |
| **Elevation of privilege** | Agent exceeds its grant | Subset rule on delegation; scope+grant checks per call | Same; grants need approval workflow |
| **Cross-environment replay** | Sandbox token used in prod | Org/instance/service binding on tokens | Same; enforce at the API gateway too |

## Out of scope (known limitations)

- The HMAC "crypto" is a simulation for deterministic tests, not a security
  claim. Nothing here should protect real secrets.
- No protection against a compromised host: if the agent's machine is owned,
  its tokens are owned too. Host hardening is assumed.
- Clock-skew leeway is a tolerance, not a fix; NTP is the real control.
- The fake KDC/token endpoint have no rate limiting; production endpoints
  need it (brute-force protection).
