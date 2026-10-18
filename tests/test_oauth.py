"""Tests: OAuth2 client-credentials incl. caching and clock skew."""
import pytest

from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.oauth import FakeTokenEndpoint, OAuthClient


def make_pair(**client_kw):
    clock = FakeClock()
    endpoint = FakeTokenEndpoint(clock)
    endpoint.register("agent-svc", "topsecret")
    client = OAuthClient("agent-svc", "topsecret", endpoint, clock, **client_kw)
    return clock, endpoint, client


def test_token_acquired_and_validated():
    clock, endpoint, client = make_pair()
    token = client.get_token()
    claims = endpoint.validate(token)
    assert claims["sub"] == "agent-svc"


def test_cache_reused_before_margin():
    clock, endpoint, client = make_pair(refresh_margin_seconds=120)
    first = client.get_token()
    clock.advance(minutes=30)
    assert client.get_token() == first  # still cached


def test_proactive_refresh_before_expiry():
    clock, endpoint, client = make_pair(refresh_margin_seconds=120)
    first = client.get_token()          # ttl 3600
    clock.advance(minutes=59)           # 60s left < 120s margin
    second = client.get_token()
    assert second != first             # refreshed, never served expired


def test_unknown_client_rejected():
    clock = FakeClock()
    endpoint = FakeTokenEndpoint(clock)
    with pytest.raises(AuthError) as exc:
        endpoint.token("ghost", "x", ttl_seconds=60)
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_bad_client_secret_rejected():
    clock = FakeClock()
    endpoint = FakeTokenEndpoint(clock)
    endpoint.register("c", "right")
    with pytest.raises(AuthError) as exc:
        endpoint.token("c", "wrong", ttl_seconds=60)
    assert exc.value.code == AuthError.BAD_SIGNATURE


def test_expired_token_rejected():
    clock, endpoint, client = make_pair()
    token = client.get_token()
    clock.advance(hours=2)
    with pytest.raises(AuthError) as exc:
        endpoint.validate(token)
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL


def test_tampered_token_rejected():
    clock, endpoint, client = make_pair()
    token = client.get_token()
    body, sig = token.split(".")
    with pytest.raises(AuthError) as exc:
        endpoint.validate(body + ".forged")
    assert exc.value.code == AuthError.BAD_SIGNATURE


def test_clock_skew_beyond_leeway_rejected():
    clock = FakeClock()
    endpoint = FakeTokenEndpoint(clock)
    endpoint.register("c", "s")
    token = endpoint.token("c", "s", ttl_seconds=3600)["access_token"]
    clock.advance(hours=2)  # far past expiry + default 60s leeway
    with pytest.raises(AuthError) as exc:
        endpoint.validate(token, leeway_seconds=60)
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL
