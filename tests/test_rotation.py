"""Tests: zero-downtime dual-credential rotation."""
import pytest

from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.rotation import DualCredentialRotation


def make_rotation(overlap_seconds=300):
    clock = FakeClock()
    rot = DualCredentialRotation(clock, overlap_seconds=overlap_seconds)
    rot.set_initial("cred-v1")
    return clock, rot


def test_initial_credential_authenticates():
    _, rot = make_rotation()
    assert rot.authenticate("cred-v1") == "primary"


def test_wrong_credential_rejected():
    _, rot = make_rotation()
    with pytest.raises(AuthError) as exc:
        rot.authenticate("nope")
    assert exc.value.code == AuthError.REVOKED_CREDENTIAL


def test_both_valid_during_overlap():
    _, rot = make_rotation()
    rot.begin_rotation("cred-v2")
    assert rot.authenticate("cred-v1") == "primary"
    assert rot.authenticate("cred-v2") == "primary"


def test_old_rejected_after_overlap_expires():
    clock, rot = make_rotation(overlap_seconds=300)
    rot.begin_rotation("cred-v2")
    clock.advance(minutes=6)
    with pytest.raises(AuthError):
        rot.authenticate("cred-v1")
    assert rot.authenticate("cred-v2") == "primary"


def test_complete_rotation_retires_old_immediately():
    _, rot = make_rotation(overlap_seconds=3600)
    rot.begin_rotation("cred-v2")
    rot.complete_rotation()
    with pytest.raises(AuthError):
        rot.authenticate("cred-v1")
    assert rot.authenticate("cred-v2") == "primary"


def test_zero_downtime_across_rotation_boundary():
    """Simulates jobs authenticating continuously while a rotation happens:
    no request in the sequence may fail."""
    clock, rot = make_rotation(overlap_seconds=300)
    results = []
    results.append(rot.authenticate("cred-v1"))   # before
    rot.begin_rotation("cred-v2")
    results.append(rot.authenticate("cred-v1"))   # straggler, still ok
    results.append(rot.authenticate("cred-v2"))   # already migrated
    clock.advance(minutes=6)                       # overlap ends
    results.append(rot.authenticate("cred-v2"))   # after
    assert results == ["primary"] * 4


def test_rotation_without_initial_credential_raises():
    clock = FakeClock()
    rot = DualCredentialRotation(clock)
    with pytest.raises(AuthError) as exc:
        rot.begin_rotation("x")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL
