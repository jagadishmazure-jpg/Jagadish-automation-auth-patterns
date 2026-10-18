"""Demo: agentic-AI auth -- identity token, delegation, governed tool call."""
import sys

sys.path.insert(0, ".")

from authpatterns.agentic import AgentIssuer, Delegation, GovernedToolRegistry
from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.oauth import FakeTokenEndpoint

clock = FakeClock()
issuer = AgentIssuer(clock, ttl_seconds=600)

# 1. agent identity token
agent_token = issuer.issue("planner-1", ["read:tickets"])
print("agent token valid for:", issuer.validate(agent_token)["agent_id"])

# 2. user delegates a subset of scopes to the agent, using a *signed* user token
idp = FakeTokenEndpoint(clock)
idp.register("operator-ana", "ana-secret", allowed_scopes=["read:tickets", "read:orders"])
user = idp.token("operator-ana", "ana-secret", scope="read:tickets read:orders")["access_token"]
delegation = Delegation(issuer, clock, idp.validate)
dtoken = delegation.delegate(user, "planner-1", ["read:tickets"])
print("delegation:", delegation.validate(dtoken)["delegator"], "->",
      delegation.validate(dtoken)["agent_id"])

# 3. governed tool registry: scopes + explicit grant required
registry = GovernedToolRegistry(issuer, clock)
registry.register_tool("get_ticket", ["read:tickets"],
                       lambda tid: {"id": tid, "status": "open"})
registry.register_tool("refund_order", ["write:orders"],
                       lambda oid: {"refunded": oid})

try:
    registry.grant("planner-1", "get_ticket", approved_by="planner-1")
except AuthError as e:
    print("self-approved grant blocked:", e.code)
registry.grant("planner-1", "get_ticket", approved_by="operator-ana")
print("tool call:", registry.call(agent_token, "get_ticket", "T-4242"))

try:
    registry.call(agent_token, "refund_order", "O-9")  # no scopes, no grant
except AuthError as e:
    print("refund blocked:", e.code, "-", str(e)[:60])
