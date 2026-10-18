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
            raise AuthError(AuthError.BAD_SIGNATURE, "malformed agent token")
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

    def __init__(self, issuer, clock, ttl_seconds=900):
        self._issuer = issuer
        self._clock = clock
        self._ttl = timedelta(seconds=ttl_seconds)

    def delegate(self, user_claims, agent_id, scopes):
        user_scopes = set(user_claims.get("scopes", []))
        wanted = set(scopes)
        if not wanted <= user_scopes:
            raise AuthError(
                AuthError.BAD_SIGNATURE,
                "delegation exceeds delegator scopes: %s not in %s"
                % (sorted(wanted - user_scopes), sorted(user_scopes)))
        now = self._clock.now()
        payload = {
            "delegator": user_claims.get("sub", user_claims.get("agent_id")),
            "agent_id": agent_id,
            "scopes": sorted(wanted),
            "iat": int(now.timestamp()),
            "exp": int((now + self._ttl).timestamp()),
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
                            "malformed delegation token")
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
        self._grants = set()  # (agent_id, tool_name)
        self.audit = audit or AuditLog(clock)

    def register_tool(self, name, required_scopes, handler):
        self._tools[name] = {"scopes": list(required_scopes),
                             "handler": handler}
        self.audit.record("tool.registered", name,
                          "scopes=%s" % ",".join(required_scopes))

    def grant(self, agent_id, tool_name):
        if tool_name not in self._tools:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown tool %r" % (tool_name,))
        self._grants.add((agent_id, tool_name))
        self.audit.record("tool.granted", agent_id, tool_name)

    def revoke_grant(self, agent_id, tool_name):
        self._grants.discard((agent_id, tool_name))
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
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "agent lacks scopes %s for tool %r"
                            % (sorted(missing), tool_name))
        if (agent_id, tool_name) not in self._grants:
            self.audit.record("tool.denied", agent_id,
                              "%s no_grant" % tool_name)
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "no grant for agent %r on tool %r"
                            % (agent_id, tool_name))
        self.audit.record("tool.called", agent_id, tool_name)
        return tool["handler"](*args, **kwargs)
