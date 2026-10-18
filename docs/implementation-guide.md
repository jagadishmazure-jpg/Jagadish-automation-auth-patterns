# Implementation guide

How to adopt these patterns in a real automation estate. This repo is a
patterns library (simulated, stdlib-only); the guide maps each pattern to
its production counterpart.

## 1. Start with the vault

Move every hardcoded credential into a real vault (HashiCorp Vault, Azure
Key Vault -- the module mirrors their semantics, not their APIs).
The rule from `vault.py` to keep: **fail-closed reads**. An automation host
that cannot reach the vault must fail the job, never fall back to a cached
or embedded secret.

## 2. Give every target a profile, not a password

Follow `enterprise.py`: one named profile per target system holding *how* to
authenticate (user+client for SAP, wallet entry for Oracle, org id for
Salesforce). Job definitions reference the profile name. When the password
changes, exactly one place is updated.

## 3. Put rotation on a calendar

Use the dual-credential pattern from `rotation.py` for every shared secret:
database passwords, API keys, service-user passwords. Set the overlap window
longer than your longest job. Rotate on schedule, not on incident.

## 4. Bind SaaS tokens to their environment

The org/instance binding in `SalesforceConnectedApp` and
`ServiceNowInstance` is the cheapest high-value control in this repo: one
comparison that makes an entire class of cross-environment mistakes
impossible. Implement it as a validation step in your token service.

## 5. Govern agent tool calls

If agents call tools, put a registry in front (`agentic.py`):
short-lived agent tokens, scope checks, explicit grants, full audit. The
grant -- not the model -- is the authorization decision.

## 6. Make the failure table operational

Turn `knowledge/03-failure-modes.md` into runbook pages: each code gets an
owner, an alert, and a first action. `vault_unreachable` pages infra;
`revoked_credential` pages security; `expired_credential` triggers the
rotation pipeline.

## What NOT to copy

The HMAC "signatures" and "tickets" here are simulations for learning and
testing. Production needs real TLS, a real KDC, and a real OAuth server.
What transfers is the *decision logic*: what to check, in what order, and
what to do when each check fails.
