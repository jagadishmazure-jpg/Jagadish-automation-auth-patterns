# Interview points

Two-minute explanations for each pattern, with the trade-off that shows
depth.

## Vaulted service accounts
"Agents fetch credentials at run time from a central vault instead of
storing them. The two properties that matter: the audit log sees
fingerprints, never plaintext -- proven by a test that scans the log --
and reads fail closed. A vault you can't reach hands out nothing."

## API keys
"Key id in the clear, constant-time secret comparison, expiry on every
key. The interesting bit is rotation with an overlap: the old key stays
valid briefly so in-flight jobs aren't killed. Revocation and expiry are
different operations with different responses."

## OAuth client credentials
"Short-lived bearer tokens, cached client-side, refreshed *before* expiry
so jobs never see an expired token. Validation uses a clock-skew leeway:
small skew tolerated, large skew rejected as a config problem, not retried
as an auth problem."

## mTLS
"Both sides present certificates; the handshake checks issuer trust,
signature, validity window, and identity. The crypto here is simulated --
the point is the checklist, which is the same checklist production mTLS
needs."

## Kerberos
"Prove the password once to the KDC, get a TGT, exchange it for
per-service tickets. Passwords cross the wire once per TGT lifetime.
The failure taxonomy matters: expired TGT means re-authenticate, wrong
service means the ticket is being misused."

## Zero-downtime rotation
"Rotation is a process, not an event: begin (both valid), overlap
(stragglers finish), complete (old retired). The test that matters is the
one that authenticates continuously across the boundary and asserts no
request fails."

## Error taxonomy
"Every failure maps to retry, rotate, or escalate. The rule I enforce in
code: revocation is never retryable. Retrying a revoked credential is how
you get lockouts and give attackers signal."

## Agentic AI auth
"Agents get their own short-lived identity tokens, scoped delegation with
a subset rule so an agent never exceeds its delegator, and a governed tool
registry where every call checks token, scopes, and an explicit grant.
Discovery is separated from execution."

## Enterprise idioms
"Each system has an idiom: SAP is user+client, Oracle is wallet,
Salesforce is org-bound OAuth, ServiceNow is instance-bound, file shares
are Kerberos ticket plus ACL. The decision guide says which and why --
prefer the target's native idiom, and always bind the credential to its
scope."
