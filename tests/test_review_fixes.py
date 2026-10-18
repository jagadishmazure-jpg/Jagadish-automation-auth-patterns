"""Regression tests for auth bypasses found in review (grokbot-portfolio, 2026-10-18).

Each test reproduces a bypass that worked on the original code.
"""
from datetime import timedelta

import pytest

from authpatterns.agentic import AgentIssuer, Delegation, GovernedToolRegistry
from authpatterns.api_key import ApiKeyStore
from authpatterns.audit import AuditLog, fingerprint
from authpatterns.clock import FakeClock
from authpatterns.enterprise import FileShareAccess, SAPServiceUser, SAPSystem
from authpatterns.errors import AuthError
from authpatterns.kerberos import KDC
from authpatterns.mtls import Certificate, CertificateAuthority, MTLSServer
from authpatterns.oauth import FakeTokenEndpoint, OAuthClient

# ---- OAuth -------------------------------------------------------------------

def test_oauth_client_cannot_mint_scopes_it_was_not_registered_for():
    clock = FakeClock()
    ep = FakeTokenEndpoint(clock)
    ep.register("reporter", "s", allowed_scopes=["read:reports"])
    with pytest.raises(AuthError) as exc:
        ep.token("reporter", "s", scope="admin:all")
    assert exc.value.code == AuthError.SCOPE_EXCEEDED
    with pytest.raises(AuthError):
        ep.token("reporter", "s", scope="read:reports admin:all")


def test_oauth_token_for_another_audience_is_rejected():
    clock = FakeClock()
    ep = FakeTokenEndpoint(clock, audiences=["api://billing", "api://reports"])
    ep.register("reporter", "s")
    token = ep.token("reporter", "s", audience="api://reports")["access_token"]
    assert ep.validate(token, audience="api://reports")["aud"] == "api://reports"
    with pytest.raises(AuthError) as exc:
        ep.validate(token, audience="api://billing")
    assert exc.value.code == AuthError.WRONG_SERVICE


def test_oauth_token_from_another_issuer_is_rejected():
    clock = FakeClock()
    ep = FakeTokenEndpoint(clock, issuer="https://idp-a.example.test")
    ep.register("c", "s")
    token = ep.token("c", "s")["access_token"]
    ep.issuer = "https://idp-b.example.test"   # same key, different trusted issuer
    with pytest.raises(AuthError) as exc:
        ep.validate(token)
    assert exc.value.code == AuthError.WRONG_SERVICE


def test_oauth_validate_enforces_required_scopes():
    clock = FakeClock()
    ep = FakeTokenEndpoint(clock)
    ep.register("c", "s", allowed_scopes=["read", "write"])
    token = ep.token("c", "s", scope="read")["access_token"]
    assert ep.validate(token, required_scopes=["read"])
    with pytest.raises(AuthError) as exc:
        ep.validate(token, required_scopes=["write"])
    assert exc.value.code == AuthError.SCOPE_EXCEEDED


def test_oauth_client_cache_never_serves_a_token_for_a_different_scope():
    clock = FakeClock()
    ep = FakeTokenEndpoint(clock)
    ep.register("c", "s", allowed_scopes=["read", "write"])
    client = OAuthClient("c", "s", ep, clock)
    read = client.get_token("read")
    write = client.get_token("write")
    assert ep.validate(write)["scope"] == "write"
    assert client.get_token("read") == read   # still cached per scope


def test_oauth_rejects_unbounded_ttl():
    clock = FakeClock()
    ep = FakeTokenEndpoint(clock)
    ep.register("c", "s")
    with pytest.raises(ValueError):
        ep.token("c", "s", ttl_seconds=10 ** 9)
    with pytest.raises(ValueError):
        ep.token("c", "s", ttl_seconds=0)


# ---- delegation ----------------------------------------------------------------

def _idp(clock, user="jdoe", scopes=("read",)):
    idp = FakeTokenEndpoint(clock)
    idp.register(user, "pw", allowed_scopes=scopes)
    return idp, idp.token(user, "pw", scope=" ".join(scopes), ttl_seconds=600)["access_token"]


def test_delegation_rejects_a_forged_claims_dict():
    clock = FakeClock()
    idp, _ = _idp(clock)
    d = Delegation(AgentIssuer(clock), clock, idp.validate)
    with pytest.raises(AuthError):
        d.delegate({"sub": "ceo", "scopes": ["admin"]}, "agent-x", ["admin"])


def test_delegation_cannot_be_chained_to_extend_its_lifetime():
    clock = FakeClock()
    issuer = AgentIssuer(clock)
    idp, user = _idp(clock)
    d = Delegation(issuer, clock, idp.validate)
    token = d.delegate(user, "agent-x", ["read"])
    # A delegation (or agent) token is not a user token: re-delegating fails.
    d2 = Delegation(issuer, clock, d.validate)
    with pytest.raises(AuthError) as exc:
        d2.delegate(token, "agent-x", ["read"])
    assert exc.value.code == AuthError.FORBIDDEN


def test_delegation_never_outlives_the_users_token():
    clock = FakeClock()
    idp, user = _idp(clock)                      # user token lives 600 s
    d = Delegation(AgentIssuer(clock), clock, idp.validate, ttl_seconds=3600)
    token = d.delegate(user, "agent-x", ["read"])
    clock.advance(seconds=601)
    with pytest.raises(AuthError) as exc:
        d.validate(token)
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL


def test_delegation_to_yourself_is_rejected():
    clock = FakeClock()
    idp, user = _idp(clock, user="agent-x")
    d = Delegation(AgentIssuer(clock), clock, idp.validate)
    with pytest.raises(AuthError) as exc:
        d.delegate(user, "agent-x", ["read"])
    assert exc.value.code == AuthError.FORBIDDEN


# ---- governed tool registry ---------------------------------------------------------

def test_tool_grant_needs_a_named_approver_who_is_not_the_agent():
    clock = FakeClock()
    issuer = AgentIssuer(clock)
    reg = GovernedToolRegistry(issuer, clock)
    reg.register_tool("delete_all", ["admin"], lambda: "deleted")
    for approver in ("", "   ", "agent-x", " AGENT-X "):
        with pytest.raises(AuthError) as exc:
            reg.grant("agent-x", "delete_all", approved_by=approver)
        assert exc.value.code == AuthError.FORBIDDEN
    with pytest.raises(TypeError):
        reg.grant("agent-x", "delete_all")       # approver is mandatory
    reg.grant("agent-x", "delete_all", approved_by="r.osei")
    assert reg.call(issuer.issue("agent-x", ["admin"]), "delete_all") == "deleted"
    assert "approved_by=r.osei" in reg.audit.entries()[-2]["detail"]


def test_tool_cannot_be_re_registered_under_existing_grants():
    clock = FakeClock()
    reg = GovernedToolRegistry(AgentIssuer(clock), clock)
    reg.register_tool("export", ["admin"], lambda: "ok")
    with pytest.raises(AuthError):
        reg.register_tool("export", [], lambda: "exfiltrated")


# ---- API keys --------------------------------------------------------------------

def test_revoked_api_key_cannot_be_rotated_into_a_working_key():
    clock = FakeClock()
    store = ApiKeyStore(clock)
    key = store.issue("ops")
    store.revoke(key.key_id)
    with pytest.raises(AuthError) as exc:
        store.rotate(key.key_id)
    assert exc.value.code == AuthError.REVOKED_CREDENTIAL


def test_rotated_api_key_keeps_its_owner():
    clock = FakeClock()
    store = ApiKeyStore(clock)
    key = store.issue("ops-team")
    assert store.rotate(key.key_id).owner == "ops-team"


def test_api_key_status_is_not_revealed_without_the_secret():
    clock = FakeClock()
    store = ApiKeyStore(clock)
    key = store.issue("ops")
    store.revoke(key.key_id)
    with pytest.raises(AuthError) as exc:
        store.authenticate(key.key_id, "wrong")
    assert exc.value.code == AuthError.BAD_SIGNATURE
    with pytest.raises(AuthError):
        store.authenticate(key.key_id, None)


# ---- mTLS ------------------------------------------------------------------------

def test_mtls_server_requires_identity_pinning():
    clock = FakeClock()
    ca = CertificateAuthority()
    with pytest.raises((TypeError, ValueError)):
        MTLSServer(clock, [ca])
    with pytest.raises(ValueError):
        MTLSServer(clock, [ca], expected_cn="")
    server = MTLSServer(clock, [ca], expected_cn={"svc-a", "svc-b"})
    other = ca.sign(Certificate("svc-evil", clock.now() - timedelta(days=1),
                                clock.now() + timedelta(days=1)))
    with pytest.raises(AuthError) as exc:
        server.handshake(other)
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


# ---- enterprise ---------------------------------------------------------------------

def test_share_operation_cannot_hit_the_service_string():
    clock = FakeClock()
    kdc = KDC(clock)
    kdc.add_principal("cifs", "pw")
    ticket = kdc.get_service_ticket(kdc.get_tgt("cifs", "pw"), "cifs/fileserver")
    fs = FileShareAccess(kdc, clock, {"finance": {"service": "cifs/fileserver",
                                                  "read": ["alice"], "write": []}})
    for op in ("service", "Read", "delete"):
        with pytest.raises(AuthError) as exc:
            fs.access(ticket, "finance", op)
        assert exc.value.code == AuthError.FORBIDDEN
    with pytest.raises(AuthError) as exc:
        fs.access(ticket, "finance", "read")     # cifs is not on the read ACL
    assert exc.value.code == AuthError.FORBIDDEN


def test_sap_lock_and_expiry_not_revealed_without_the_password():
    clock = FakeClock()
    sap = SAPSystem(clock)
    sap.add_user(SAPServiceUser("batch", "right", "100", locked=True))
    sap.add_user(SAPServiceUser("old", "right", "100",
                                password_expires_at=clock.now() - timedelta(days=1)))
    for user in ("batch", "old"):
        with pytest.raises(AuthError) as exc:
            sap.logon(user, "wrong", "100")
        assert exc.value.code == AuthError.BAD_SIGNATURE


# ---- audit -------------------------------------------------------------------------

def test_fingerprint_is_keyed_not_a_plain_hash():
    import hashlib
    weak = "Spring2026!"
    plain = hashlib.sha256(weak.encode()).hexdigest()[:16]
    fp = fingerprint(weak)
    assert plain not in fp                  # not brute-forceable from a wordlist
    assert fp == fingerprint(weak)          # still stable within a process
    log = AuditLog(FakeClock())
    log.record("secret.stored", "db", fp)
    assert weak not in str(log.entries())
