"""Tests: simulated mTLS handshake."""
import pytest

from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.mtls import Certificate, CertificateAuthority, MTLSServer
from datetime import timedelta


def make_cert(clock, cn="svc-a", days=365):
    now = clock.now()
    return Certificate(cn, now - timedelta(days=1), now + timedelta(days=days))


def test_handshake_succeeds_with_trusted_cert():
    clock = FakeClock()
    ca = CertificateAuthority()
    server = MTLSServer(clock, [ca])
    session = server.handshake(ca.sign(make_cert(clock)))
    assert session["peer"] == "svc-a"


def test_untrusted_issuer_rejected():
    clock = FakeClock()
    ca = CertificateAuthority("Real CA")
    rogue = CertificateAuthority("Rogue CA")
    server = MTLSServer(clock, [ca])
    with pytest.raises(AuthError) as exc:
        server.handshake(rogue.sign(make_cert(clock)))
    assert exc.value.code == AuthError.BAD_SIGNATURE


def test_expired_cert_rejected():
    clock = FakeClock()
    ca = CertificateAuthority()
    server = MTLSServer(clock, [ca])
    cert = ca.sign(make_cert(clock, days=1))
    clock.advance(days=2)
    with pytest.raises(AuthError) as exc:
        server.handshake(cert)
    assert exc.value.code == AuthError.CERT_EXPIRED


def test_not_yet_valid_cert_rejected():
    clock = FakeClock()
    ca = CertificateAuthority()
    server = MTLSServer(clock, [ca])
    now = clock.now()
    cert = Certificate("svc-a", now + timedelta(days=1),
                       now + timedelta(days=30))
    with pytest.raises(AuthError) as exc:
        server.handshake(ca.sign(cert))
    assert exc.value.code == AuthError.CERT_EXPIRED


def test_tampered_cert_rejected():
    clock = FakeClock()
    ca = CertificateAuthority()
    server = MTLSServer(clock, [ca])
    cert = ca.sign(make_cert(clock))
    cert.common_name = "svc-evil"  # tamper after signing
    with pytest.raises(AuthError) as exc:
        server.handshake(cert)
    assert exc.value.code == AuthError.BAD_SIGNATURE


def test_unexpected_identity_rejected():
    clock = FakeClock()
    ca = CertificateAuthority()
    server = MTLSServer(clock, [ca], expected_cn="svc-a")
    with pytest.raises(AuthError) as exc:
        server.handshake(ca.sign(make_cert(clock, cn="svc-b")))
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_audit_chain_valid_after_handshakes():
    clock = FakeClock()
    ca = CertificateAuthority()
    server = MTLSServer(clock, [ca])
    server.handshake(ca.sign(make_cert(clock)))
    assert server.audit.verify()
