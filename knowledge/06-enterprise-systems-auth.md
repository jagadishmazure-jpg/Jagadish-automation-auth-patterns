# Enterprise systems auth

How automation authenticates to the systems enterprises actually run.
Each system has an idiom; using the wrong one is a classic integration
failure.

## SAP (application server)

Idiom: **service user + client number.** The client (e.g. 100 = production,
200 = QA) is part of the identity -- the same username in two clients is
two different accounts. Three distinct failures: unknown user/client,
locked user, expired password. Automation must handle all three, because
basis teams lock service users aggressively and password policies expire
them on schedules the automation team does not control.

## Oracle Database

Idiom: **wallet-based auth.** Credentials live in a client-side wallet; the
job definition names a connect string, never a password. This removes the
most common leak vector in batch estates: passwords in job definitions,
scripts, and logs.

## Salesforce

Idiom: **connected app, server-to-server OAuth.** The critical property is
**org binding**: the token carries the org id, and a token minted for
sandbox is rejected by production. Without this, one leaked token crosses
every environment.

## ServiceNow

Idiom: **instance-bound auth.** Same principle as org binding, applied to
the instance URL. Credentials for the dev instance cannot authenticate
against prod, because the instance is checked on every call -- not just at
token issuance.

## Windows file shares

Idiom: **Kerberos ticket + share ACL.** Two separate checks: the ticket
proves *who* you are (validated against the KDC), the ACL decides *what*
you may touch. A valid ticket for the wrong share, or the right share
without ACL membership, is still denied. Authentication and authorization
stay separate.
