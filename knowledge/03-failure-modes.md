# Failure modes

Every failure in this repo maps to one response: **retry**, **rotate**, or
**escalate**. The table below is implemented in `authpatterns/errors.py` and
proven by tests -- including the negative paths.

| Failure | Code | Response | Why |
|---|---|---|---|
| Vault unreachable | `vault_unreachable` | Retry with backoff | Credential is fine; infrastructure hiccupped |
| Vault sealed | `vault_sealed` | Escalate | Needs a human with unseal authority |
| Credential expired | `expired_credential` | Rotate | A new credential is the only fix |
| Credential revoked | `revoked_credential` | Escalate | Someone deliberately killed it; find out why |
| Bad signature / wrong secret | `bad_signature` | Escalate | Retrying a wrong secret is a lockout risk |
| Unknown principal / key | `unknown_principal` | Escalate | Config or provisioning problem |
| Clock skew | `clock_skew` | Fix config | No credential change helps |
| Cert outside validity | `cert_expired` | Rotate | Issue a new certificate |
| Ticket expired | `ticket_expired` | Re-acquire | Get a fresh TGT / service ticket |
| Wrong service / org / instance | `wrong_service` | Escalate | Token is being used where it does not belong |

## Design rules

1. **Fail closed.** A vault that cannot be reached hands out nothing. An
   expired token authenticates nobody. There is no "allow on error" path.
2. **Never retry revocation.** Retrying a revoked credential is how accounts
   get locked and attackers get signal. The taxonomy makes revocation
   non-retryable by construction.
3. **Distinguish locked from expired from wrong.** SAP taught the industry
   this: a locked user, an expired password, and a wrong password are three
   different problems with three different fixes. Collapsing them into
   "auth failed" is how outages get misdiagnosed.
4. **Audit the rejection, not just the success.** Every denied attempt in
   this repo writes an audit entry with the reason -- the failure log is
   where intrusions first appear.
