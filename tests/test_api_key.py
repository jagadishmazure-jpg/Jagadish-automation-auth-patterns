"""Tests: API-key auth incl. expiry, revocation, rotation overlap."""
import pytest

from authpatterns.api_key import ApiKeyStore
from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError


def make_store():
    return ApiKeyStore(FakeClock())


def test_issue_and_authenticate():
    store = make_store()
    key = store.issue("job-runner")
    assert store.authenticate(key.key_id, key.secret) == key.key_id


def test_unknown_key_rejected():
    store = make_store()
    with pytest.raises(AuthError) as exc:
        store.authenticate("ak_nope", "whatever")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_wrong_secret_rejected():
    store = make_store()
    key = store.issue("job-runner")
    with pytest.raises(AuthError) as exc:
        store.authenticate(key.key_id, "wrong-secret")
    assert exc.value.code == AuthError.BAD_SIGNATURE


def test_expired_key_rejected():
    clock = FakeClock()
    store = ApiKeyStore(clock)
    key = store.issue("job-runner", ttl_seconds=60)
    clock.advance(minutes=2)
    with pytest.raises(AuthError) as exc:
        store.authenticate(key.key_id, key.secret)
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL


def test_revoked_key_rejected():
    store = make_store()
    key = store.issue("job-runner")
    store.revoke(key.key_id)
    with pytest.raises(AuthError) as exc:
        store.authenticate(key.key_id, key.secret)
    assert exc.value.code == AuthError.REVOKED_CREDENTIAL


def test_revoke_unknown_key_raises():
    store = make_store()
    with pytest.raises(AuthError) as exc:
        store.revoke("ak_nope")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_rotation_overlap_keeps_old_key_working_briefly():
    clock = FakeClock()
    store = ApiKeyStore(clock)
    old = store.issue("job-runner", ttl_seconds=3600)
    new = store.rotate(old.key_id, ttl_seconds=3600, overlap_seconds=300)
    # both work during the overlap
    assert store.authenticate(old.key_id, old.secret) == old.key_id
    assert store.authenticate(new.key_id, new.secret) == new.key_id
    # after the overlap the old key's grace expiry kicks in
    clock.advance(minutes=6)
    with pytest.raises(AuthError) as exc:
        store.authenticate(old.key_id, old.secret)
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL
    assert store.authenticate(new.key_id, new.secret) == new.key_id
