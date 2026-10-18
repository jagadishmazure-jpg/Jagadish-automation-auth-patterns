"""Authentication patterns for AI agents.

Agents are non-human identities with their own lifecycle, distinct from the
service accounts above:

* **Agent identity tokens** -- short-lived, per-agent, scope-bound. An agent
  never holds a human's password; it holds a token that says what *it* may do.
* **Scoped delegation (on-behalf-of)** -- a user delegates a *subset* of their
  scopes to an agent. The agent can never exceed the delegator.
* **Governed tool access (MCP-style)** -- every tool call passes through a
  registry that checks the agent's scopes and an explicit grant *before* the
  tool executes. Discovery and execution are separated: seeing a tool in the
  registry does not mean being allowed to call it.
"""
import base64
import hashlib
import hmac
import json
import secrets
from datetime import timedelta

from .audit import AuditLog
from .errors import AuthError


def _b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class AgentIssuer:
    """Issues and validates short-lived agent identity tokens."""

    def __init__(self, clock, ttl_seconds=600, audit=None):
        self._clock = clock
        self._ttl = timedelta(seconds=ttl_seconds)
        self._key = secrets.token_bytes(32)
        self.audit = audit or AuditLog(clock)

    def _sign(self, body):
        return _b64encode(hmac.new(self._key, body.encode("ascii"),
                                   hashlib.sha256).digest())

    def issue(self, agent_id, scopes):
        now = self._clock.now()
        payload = {
            "agent_id": agent_id,
            "scopes": sorted(set(scopes)),
            "iat": int(now.timestamp()),
            "exp": int((now + self._ttl).timestamp()),
            "jti": secrets.token_hex(8),
            "kind": "agent",
        }
        body = _b64encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
        token = "%s.%s" % (body, self._sign(body))
        self.audit.record("agent.token_issued", agent_id,
                          "scopes=%s" % ",".join(payload["scopes"]))
        return token

    def validate(self, token):
        try:
            body, sig = token.split(".")
        except ValueError:
            raise AuthError(AuthError.BAD_SIGNATURE, "malformed agent token") from None
        if not hmac.compare_digest(self._sign(body), sig):
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "agent token signature invalid")
        claims = json.loads(_b64decode(body).decode("utf-8"))
        if claims.get("kind") != "agent":
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "not an agent identity token")
        if self._clock.now().timestamp() > claims["exp"]:
            self.audit.record("agent.token_rejected", claims["agent_id"],
                              "expired")
            raise AuthError(AuthError.EXPIRED_CREDENTIAL,
                            "agent token has expired")
        return claims


class Delegation:
    """On-behalf-of: a user delegates a subset of scopes to an agent.

    The delegation token carries both the delegator and the agent, and its
    scopes must be a subset of the delegator's -- an agent can never gain
    more power through delegation than the human who delegated.
    """

    def __init__(self, issuer, clock, user_validator, ttl_seconds=900):
        """``user_validator`` verifies the *user's* token and returns its
        claims (for example ``FakeTokenEndpoint.validate``). Delegation never
        trusts a claims dict supplied by the caller."""
        self._issuer = issuer
        self._clock = clock
        self._validate_user = user_validator
        self._ttl = timedelta(seconds=ttl_seconds)

    def delegate(self, user_token, agent_id, scopes):
        user_claims = self._validate_user(user_token)   # raises if forged/expired
        if user_claims.get("kind") in ("agent", "delegation") or "sub" not in user_claims:
            # An agent or delegation token is not a human delegator: allowing it
            # would let an agent re-delegate to itself and extend its lifetime.
            raise AuthError(AuthError.FORBIDDEN,
                            "only a user token can delegate")
        delegator = user_claims["sub"]
        if delegator == agent_id:
            raise AuthError(AuthError.FORBIDDEN, "cannot delegate to yourself")
        raw = user_claims.get("scopes", user_claims.get("scope", ""))
        user_scopes = set(raw.split() if isinstance(raw, str) else raw)
        wanted = set(scopes)
        if not wanted or not wanted <= user_scopes:
            raise AuthError(
                AuthError.SCOPE_EXCEEDED,
                "delegation exceeds delegator scopes: %s not in %s"
                % (sorted(wanted - user_scopes), sorted(user_scopes)))
        now = self._clock.now()
        exp = int((now + self._ttl).timestamp())
        if "exp" in user_claims:
            exp = min(exp, int(user_claims["exp"]))   # never outlive the user's token
        payload = {
            "delegator": delegator,
            "agent_id": agent_id,
            "scopes": sorted(wanted),
            "iat": int(now.timestamp()),
            "exp": exp,
            "jti": secrets.token_hex(8),
            "kind": "delegation",
        }
        body = _b64encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
        token = "%s.%s" % (body, self._issuer._sign(body))
        self._issuer.audit.record("agent.delegated", agent_id,
                                  "by=%s scopes=%s"
                                  % (payload["delegator"],
                                     ",".join(payload["scopes"])))
        return token

    def validate(self, token):
        try:
            body, sig = token.split(".")
        except ValueError:
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "malformed delegation token") from None
        if not hmac.compare_digest(self._issuer._sign(body), sig):
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "delegation signature invalid")
        claims = json.loads(_b64decode(body).decode("utf-8"))
        if claims.get("kind") != "delegation":
            raise AuthError(AuthError.BAD_SIGNATURE, "not a delegation token")
        if self._clock.now().timestamp() > claims["exp"]:
            raise AuthError(AuthError.EXPIRED_CREDENTIAL,
                            "delegation has expired")
        return claims


class GovernedToolRegistry:
    """MCP-style governed bridge between agents and tools.

    Tools are registered with the scopes they require. An agent may call a
    tool only when (a) its token is valid, (b) its scopes cover the tool's
    required scopes, and (c) an explicit grant exists for that agent+tool.
    Every decision is audited.
    """

    def __init__(self, issuer, clock, audit=None):
        self._issuer = issuer
        self._clock = clock
        self._tools = {}   # name -> {"scopes": [...], "handler": fn}
        self._grants = {}  # (agent_id, tool_name) -> approver
        self.audit = audit or AuditLog(clock)

    def register_tool(self, name, required_scopes, handler):
        if name in self._tools:
            # Re-registering would silently attach existing grants to a new
            # handler with possibly weaker scope requirements.
            raise AuthError(AuthError.FORBIDDEN, "tool %r already registered" % (name,))
        self._tools[name] = {"scopes": list(required_scopes),
                             "handler": handler}
        self.audit.record("tool.registered", name,
                          "scopes=%s" % ",".join(required_scopes))

    def grant(self, agent_id, tool_name, approved_by):
        """Grant a tool to an agent. A named human approver is required and
        may not be the agent itself (no self-approval)."""
        if tool_name not in self._tools:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown tool %r" % (tool_name,))
        approver = (approved_by or "").strip()
        if not approver or approver.lower() == str(agent_id).strip().lower():
            raise AuthError(AuthError.FORBIDDEN,
                            "grant needs a named approver other than the agent")
        self._grants[(agent_id, tool_name)] = approver
        self.audit.record("tool.granted", agent_id,
                          "%s approved_by=%s" % (tool_name, approver))

    def revoke_grant(self, agent_id, tool_name):
        self._grants.pop((agent_id, tool_name), None)
        self.audit.record("tool.grant_revoked", agent_id, tool_name)

    def call(self, agent_token, tool_name, *args, **kwargs):
        claims = self._issuer.validate(agent_token)
        agent_id = claims["agent_id"]
        tool = self._tools.get(tool_name)
        if tool is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown tool %r" % (tool_name,))
        missing = set(tool["scopes"]) - set(claims["scopes"])
        if missing:
            self.audit.record("tool.denied", agent_id,
                              "%s missing_scopes=%s"
                              % (tool_name, ",".join(sorted(missing))))
            raise AuthError(AuthError.FORBIDDEN,
                            "agent lacks scopes %s for tool %r"
                            % (sorted(missing), tool_name))
        if (agent_id, tool_name) not in self._grants:
            self.audit.record("tool.denied", agent_id,
                              "%s no_grant" % tool_name)
            raise AuthError(AuthError.FORBIDDEN,
                            "no grant for agent %r on tool %r"
                            % (agent_id, tool_name))
        self.audit.record("tool.called", agent_id, tool_name)
        return tool["handler"](*args, **kwargs)
