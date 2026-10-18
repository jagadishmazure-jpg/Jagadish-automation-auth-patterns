"""Demo: the auth bypasses found in the 2026-10-18 review, each now blocked."""
import sys
from datetime import timedelta

sys.path.insert(0, ".")

from authpatterns.agentic import AgentIssuer, Delegation, GovernedToolRegistry
from authpatterns.api_key import ApiKeyStore
from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.mtls import Certificate, CertificateAuthority, MTLSServer
from authpatterns.oauth import FakeTokenEndpoint, OAuthClient


def attempt(label, fn):
    try:
        fn()
        print(f"{label:<44} ALLOWED (bug)")
    except AuthError as e:
        print(f"{label:<44} blocked: {e.code}")
    except (TypeError, ValueError) as e:
        print(f"{label:<44} blocked: {type(e).__name__}")


clock = FakeClock()
idp = FakeTokenEndpoint(clock, audiences=["api://reports", "api://billing"])
idp.register("reporter", "s", allowed_scopes=["read:reports"])
attempt("client mints admin:all", lambda: idp.token("reporter", "s", scope="admin:all"))
tok = idp.token("reporter", "s", scope="read:reports", audience="api://reports")["access_token"]
attempt("reports token replayed at billing API", lambda: idp.validate(tok, audience="api://billing"))

idp.register("ops", "s", allowed_scopes=["read", "write"])
client = OAuthClient("ops", "s", idp, clock)
client.get_token("read", audience="api://reports")
write_tok = client.get_token("write", audience="api://reports")
print(f"{'cache asked for write, got scope:':<44} {idp.validate(write_tok, audience='api://reports')['scope']}")

issuer = AgentIssuer(clock)
idp.register("ana", "pw", allowed_scopes=["read"])
user = idp.token("ana", "pw", scope="read", ttl_seconds=600, audience="api://reports")["access_token"]
delegation = Delegation(issuer, clock, lambda t: idp.validate(t, audience="api://reports"))
attempt("delegation from forged {'sub': 'ceo'} dict",
        lambda: delegation.delegate({"sub": "ceo", "scopes": ["admin"]}, "agent-1", ["admin"]))
dtoken = delegation.delegate(user, "agent-1", ["read"])
attempt("re-delegate a delegation to extend it",
        lambda: Delegation(issuer, clock, delegation.validate).delegate(dtoken, "agent-1", ["read"]))

registry = GovernedToolRegistry(issuer, clock)
registry.register_tool("delete_all", ["admin"], lambda: "deleted")
attempt("agent approves its own grant", lambda: registry.grant("agent-1", "delete_all", approved_by="agent-1"))

store = ApiKeyStore(clock)
key = store.issue("ops")
store.revoke(key.key_id)
attempt("rotate a revoked API key", lambda: store.rotate(key.key_id))

ca = CertificateAuthority()
no_pin = (clock, [ca])  # deliberately omits expected_cn
attempt("mTLS server without a pinned CN", lambda: MTLSServer(*no_pin))
server = MTLSServer(clock, [ca], expected_cn="job-agent-01")
rogue = ca.sign(Certificate("rogue-host", clock.now() - timedelta(days=1), clock.now() + timedelta(days=1)))
attempt("same-CA cert with another CN", lambda: server.handshake(rogue))
