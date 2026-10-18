# Agentic AI auth

Why agents need their own auth patterns, separate from service accounts.

## The difference

A service account has a fixed job: "the ETL job reads the warehouse every
night." Its permissions are static and reviewed quarterly. An AI agent
chooses its targets at run time: the same agent might read tickets, then
query orders, then call a refund tool -- depending on the conversation.
Static permissions cannot cover dynamic behaviour, so agents need:

1. **Their own identity.** An agent identity token names the agent, not a
   human and not a shared service account. When something goes wrong, the
   audit log says *which agent* did it.
2. **Short lifetimes.** Agent tokens in this repo live 10 minutes by default.
   A leaked token is useful to an attacker for minutes, not months.
3. **Scoped delegation.** When an agent acts for a user, the delegation token
   carries both identities and the agent's scopes must be a subset of the
   user's. The agent can never exceed its delegator -- this is the
   on-behalf-of rule, and the repo rejects delegations that violate it.
4. **Governed tool access.** Discovery is separated from execution: an agent
   can *see* a tool in the registry without being *allowed* to call it.
   Every call checks token validity, scope coverage, and an explicit grant.
   This is the MCP-style pattern: the model proposes, the registry disposes.

## What can go wrong (agent-specific)

- **Scope creep via delegation:** fixed by the subset rule, tested.
- **Token replay after expiry:** fixed by short TTLs, tested.
- **A compromised agent calling tools:** contained by per-agent grants --
  revoking one grant stops one agent without touching the others, tested.
- **Confused deputy:** the registry checks the *agent's* scopes, not the
  tool's -- a tool cannot launder permissions, tested via the
  insufficient-scopes case.
