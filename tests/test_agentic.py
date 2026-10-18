"""Tests: agentic-AI auth (identity tokens, delegation, governed tools)."""
import pytest

from authpatterns.agentic import AgentIssuer, Delegation, GovernedToolRegistry
from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.oauth import FakeTokenEndpoint


def make_user(clock, scopes):
    """A real, signed user token (delegation never trusts a claims dict)."""
    idp = FakeTokenEndpoint(clock)
    idp.register("jdoe", "pw", allowed_scopes=scopes)
    return idp, idp.token("jdoe", "pw", scope=" ".join(scopes))["access_token"]


def make_issuer(ttl=600):
    clock = FakeClock()
    return clock, AgentIssuer(clock, ttl_seconds=ttl)


def test_agent_token_issued_and_validated():
    clock, issuer = make_issuer()
    token = issuer.issue("agent-7", ["read:tickets"])
    claims = issuer.validate(token)
    assert claims["agent_id"] == "agent-7"
    assert claims["scopes"] == ["read:tickets"]


def test_expired_agent_token_rejected():
    clock, issuer = make_issuer(ttl=600)
    token = issuer.issue("agent-7", ["read:tickets"])
    clock.advance(minutes=11)
    with pytest.raises(AuthError) as exc:
        issuer.validate(token)
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL


def test_tampered_agent_token_rejected():
    _, issuer = make_issuer()
    token = issuer.issue("agent-7", ["read:tickets"])
    body, _ = token.split(".")
    with pytest.raises(AuthError) as exc:
        issuer.validate(body + ".forged")
    assert exc.value.code == AuthError.BAD_SIGNATURE


def test_delegation_subset_succeeds():
    clock, issuer = make_issuer()
    idp, user = make_user(clock, ["read:tickets", "read:orders"])
    delegation = Delegation(issuer, clock, idp.validate)
    token = delegation.delegate(user, "agent-7", ["read:tickets"])
    claims = delegation.validate(token)
    assert claims["delegator"] == "jdoe"
    assert claims["scopes"] == ["read:tickets"]


def test_delegation_beyond_user_scopes_rejected():
    clock, issuer = make_issuer()
    idp, user = make_user(clock, ["read:tickets"])
    delegation = Delegation(issuer, clock, idp.validate)
    with pytest.raises(AuthError):
        delegation.delegate(user, "agent-7",
                            ["read:tickets", "admin:users"])


def test_expired_delegation_rejected():
    clock, issuer = make_issuer()
    idp, user = make_user(clock, ["read:tickets"])
    delegation = Delegation(issuer, clock, idp.validate, ttl_seconds=900)
    token = delegation.delegate(user, "agent-7", ["read:tickets"])
    clock.advance(minutes=16)
    with pytest.raises(AuthError) as exc:
        delegation.validate(token)
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL


def make_registry():
    clock = FakeClock()
    issuer = AgentIssuer(clock)
    registry = GovernedToolRegistry(issuer, clock)
    registry.register_tool("get_ticket",
                           ["read:tickets"], lambda tid: {"id": tid})
    registry.register_tool("close_ticket",
                           ["write:tickets"], lambda tid: {"closed": tid})
    return clock, issuer, registry


def test_governed_call_succeeds_with_scopes_and_grant():
    _, issuer, registry = make_registry()
    token = issuer.issue("agent-7", ["read:tickets"])
    registry.grant("agent-7", "get_ticket", approved_by="r.osei")
    assert registry.call(token, "get_ticket", "T-1") == {"id": "T-1"}


def test_call_without_grant_rejected_even_with_scopes():
    _, issuer, registry = make_registry()
    token = issuer.issue("agent-7", ["read:tickets"])
    with pytest.raises(AuthError):
        registry.call(token, "get_ticket", "T-1")


def test_call_with_insufficient_scopes_rejected():
    _, issuer, registry = make_registry()
    token = issuer.issue("agent-7", ["read:tickets"])
    registry.grant("agent-7", "close_ticket", approved_by="r.osei")
    with pytest.raises(AuthError):
        registry.call(token, "close_ticket", "T-1")


def test_call_with_expired_token_rejected():
    clock, issuer, registry = make_registry()
    token = issuer.issue("agent-7", ["read:tickets"])
    registry.grant("agent-7", "get_ticket", approved_by="r.osei")
    clock.advance(hours=1)
    with pytest.raises(AuthError) as exc:
        registry.call(token, "get_ticket", "T-1")
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL


def test_revoked_grant_blocks_calls():
    _, issuer, registry = make_registry()
    token = issuer.issue("agent-7", ["read:tickets"])
    registry.grant("agent-7", "get_ticket", approved_by="r.osei")
    registry.revoke_grant("agent-7", "get_ticket")
    with pytest.raises(AuthError):
        registry.call(token, "get_ticket", "T-1")


def test_unknown_tool_rejected():
    _, issuer, registry = make_registry()
    token = issuer.issue("agent-7", ["read:tickets"])
    with pytest.raises(AuthError) as exc:
        registry.call(token, "nope", "T-1")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_grant_on_unknown_tool_rejected():
    _, _, registry = make_registry()
    with pytest.raises(AuthError):
        registry.grant("agent-7", "nope", approved_by="r.osei")
