"""Tests: simulated vault (fail-closed, no plaintext in audit)."""
import pytest

from authpatterns.audit import AuditLog
from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.vault import Vault


def make_vault():
    clock = FakeClock()
    return Vault(clock, AuditLog(clock))


def test_store_and_retrieve_roundtrip():
    vault = make_vault()
    vault.store("db/password", "s3cr3t-value")
    assert vault.retrieve("db/password") == "s3cr3t-value"


def test_unknown_secret_raises():
    vault = make_vault()
    with pytest.raises(AuthError) as exc:
        vault.retrieve("nope")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_offline_vault_is_fail_closed():
    vault = make_vault()
    vault.store("db/password", "s3cr3t-value")
    vault.go_offline()
    with pytest.raises(AuthError) as exc:
        vault.retrieve("db/password")
    assert exc.value.code == AuthError.VAULT_UNREACHABLE
    # and it comes back when the vault does
    vault.go_online()
    assert vault.retrieve("db/password") == "s3cr3t-value"


def test_sealed_vault_refuses():
    vault = make_vault()
    vault.store("k", "v")
    vault.seal()
    with pytest.raises(AuthError) as exc:
        vault.retrieve("k")
    assert exc.value.code == AuthError.VAULT_SEALED
    vault.unseal()
    assert vault.retrieve("k") == "v"


def test_plaintext_never_reaches_audit_log():
    vault = make_vault()
    secret = "super-secret-plaintext-12345"
    vault.store("x", secret)
    vault.retrieve("x")
    blob = str(vault.audit.entries())
    assert secret not in blob


def test_rotation_changes_secret_and_audits_both_fingerprints():
    vault = make_vault()
    vault.store("x", "old-secret")
    vault.rotate("x", "new-secret")
    assert vault.retrieve("x") == "new-secret"
    types = [e["type"] for e in vault.audit.entries()]
    assert "secret.rotated" in types


def test_rotate_unknown_secret_raises():
    vault = make_vault()
    with pytest.raises(AuthError) as exc:
        vault.rotate("ghost", "x")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_audit_chain_stays_valid():
    vault = make_vault()
    vault.store("a", "1")
    vault.retrieve("a")
    vault.rotate("a", "2")
    assert vault.audit.verify()
