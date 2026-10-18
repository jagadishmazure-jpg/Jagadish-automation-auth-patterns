# Auth patterns, distilled

Seven patterns, each answering one question.

## 1. Vaulted service accounts -- "Where do secrets live?"

In exactly one place: a vault. Agents fetch at run time; the audit log sees
fingerprints, never plaintext. When the vault is unreachable, the system
fails closed (no credentials handed out) and the failure is marked retryable.

## 2. API keys -- "How do I call a REST API on a schedule?"

Key id in the clear, secret compared in constant time, expiry on every key
so a leak has a blast radius measured in hours, not years. Revocation is a
first-class operation, distinct from expiry.

## 3. OAuth 2.0 client credentials -- "How do I talk to modern APIs?"

Short-lived bearer tokens, cached, refreshed *before* expiry so jobs never
observe an expired token. Validation tolerates small clock skew (leeway) but
rejects large skew -- a host whose clock is hours off has a config problem,
not a token problem.

## 4. mTLS -- "How do services trust each other?"

Both sides present certificates. The handshake checks issuer trust,
signature integrity, validity window, and identity. Crypto is a means;
the checks are the pattern.

## 5. Kerberos tickets -- "How do Windows estates authenticate?"

Prove the password once to the KDC, get a ticket-granting ticket, exchange
it for per-service tickets. Passwords cross the wire once per TGT lifetime,
not once per connection.

## 6. Zero-downtime rotation -- "How do I change a credential safely?"

Dual-credential overlap: the new credential goes live while the old one
stays valid for a window. Stragglers finish; nothing breaks at 02:00.
Rotation is a process with a beginning, a middle, and an end -- not an event.

## 7. Error taxonomy -- "What do I do when auth fails?"

Retry, rotate, or escalate -- never guess. `vault_unreachable` retries with
backoff. `expired_credential` rotates. `revoked_credential` escalates to a
human. `clock_skew` is a config fix. The code in `errors.py` makes the
decision table executable.
