"""Tests: error taxonomy and retry policy."""
import pytest

from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError, RetryPolicy, is_retryable


def test_every_code_is_a_string_constant():
    codes = [AuthError.EXPIRED_CREDENTIAL, AuthError.REVOKED_CREDENTIAL,
             AuthError.VAULT_UNREACHABLE, AuthError.VAULT_SEALED,
             AuthError.CLOCK_SKEW, AuthError.BAD_SIGNATURE,
             AuthError.UNKNOWN_PRINCIPAL, AuthError.CERT_EXPIRED,
             AuthError.TICKET_EXPIRED, AuthError.WRONG_SERVICE]
    assert len(set(codes)) == len(codes)
    assert all(isinstance(c, str) for c in codes)


def test_error_carries_code_and_message():
    err = AuthError(AuthError.EXPIRED_CREDENTIAL, "token too old")
    assert err.code == "expired_credential"
    assert "too old" in str(err)


def test_vault_unreachable_is_retryable():
    assert is_retryable(AuthError(AuthError.VAULT_UNREACHABLE, "down"))


def test_expired_revoked_and_bad_signature_are_not_retryable():
    for code in (AuthError.EXPIRED_CREDENTIAL, AuthError.REVOKED_CREDENTIAL,
                 AuthError.BAD_SIGNATURE, AuthError.CLOCK_SKEW,
                 AuthError.UNKNOWN_PRINCIPAL):
        assert not is_retryable(AuthError(code, "x"))


def test_non_auth_errors_are_not_retryable():
    assert not is_retryable(ValueError("boom"))


def test_backoff_delays_are_deterministic():
    policy = RetryPolicy(max_attempts=4, base_delay=1.0, multiplier=2.0)
    assert list(policy.delays()) == [1.0, 2.0, 4.0]
    assert list(policy.delays()) == [1.0, 2.0, 4.0]  # repeatable


def test_single_attempt_yields_no_delays():
    assert list(RetryPolicy(max_attempts=1).delays()) == []


def test_should_retry_only_within_budget_and_retryable():
    policy = RetryPolicy(max_attempts=3)
    err = AuthError(AuthError.VAULT_UNREACHABLE, "down")
    assert policy.should_retry(err, 1)
    assert policy.should_retry(err, 2)
    assert not policy.should_retry(err, 3)  # budget exhausted
    fatal = AuthError(AuthError.REVOKED_CREDENTIAL, "gone")
    assert not policy.should_retry(fatal, 1)  # never retry revocation


def test_invalid_policy_rejected():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(base_delay=0)
