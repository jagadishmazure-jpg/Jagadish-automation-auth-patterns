"""Tests: simulated Kerberos (TGT -> service ticket -> authenticate)."""
import pytest

from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.kerberos import KDC, ServiceServer


def make_kdc():
    clock = FakeClock()
    kdc = KDC(clock)
    kdc.add_principal("svc-batch", "correct-horse")
    return clock, kdc


def test_full_flow_authenticates():
    clock, kdc = make_kdc()
    tgt = kdc.get_tgt("svc-batch", "correct-horse")
    ticket = kdc.get_service_ticket(tgt, "cifs/fileserver")
    result = ServiceServer("cifs/fileserver", kdc, clock).authenticate(ticket)
    assert result["client"] == "svc-batch"


def test_unknown_principal_rejected():
    _, kdc = make_kdc()
    with pytest.raises(AuthError) as exc:
        kdc.get_tgt("ghost", "x")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_wrong_password_rejected():
    _, kdc = make_kdc()
    with pytest.raises(AuthError) as exc:
        kdc.get_tgt("svc-batch", "wrong-horse")
    assert exc.value.code == AuthError.BAD_SIGNATURE


def test_expired_tgt_rejected():
    clock, kdc = make_kdc()
    tgt = kdc.get_tgt("svc-batch", "correct-horse")
    clock.advance(hours=2)  # TGT lifetime is 1h
    with pytest.raises(AuthError) as exc:
        kdc.get_service_ticket(tgt, "cifs/fileserver")
    assert exc.value.code == AuthError.TICKET_EXPIRED


def test_expired_service_ticket_rejected():
    clock, kdc = make_kdc()
    tgt = kdc.get_tgt("svc-batch", "correct-horse")
    ticket = kdc.get_service_ticket(tgt, "cifs/fileserver")
    clock.advance(hours=1)  # service ticket lifetime is 10m
    with pytest.raises(AuthError) as exc:
        ServiceServer("cifs/fileserver", kdc, clock).authenticate(ticket)
    assert exc.value.code == AuthError.TICKET_EXPIRED


def test_wrong_service_rejected():
    clock, kdc = make_kdc()
    tgt = kdc.get_tgt("svc-batch", "correct-horse")
    ticket = kdc.get_service_ticket(tgt, "cifs/fileserver")
    with pytest.raises(AuthError) as exc:
        ServiceServer("http/intranet", kdc, clock).authenticate(ticket)
    assert exc.value.code == AuthError.WRONG_SERVICE


def test_tampered_ticket_rejected():
    clock, kdc = make_kdc()
    tgt = kdc.get_tgt("svc-batch", "correct-horse")
    ticket = kdc.get_service_ticket(tgt, "cifs/fileserver")
    body, _ = ticket.split(".")
    with pytest.raises(AuthError) as exc:
        ServiceServer("cifs/fileserver", kdc, clock).authenticate(
            body + ".forged")
    assert exc.value.code == AuthError.BAD_SIGNATURE


def test_ticket_cannot_be_used_as_tgt():
    clock, kdc = make_kdc()
    tgt = kdc.get_tgt("svc-batch", "correct-horse")
    ticket = kdc.get_service_ticket(tgt, "cifs/fileserver")
    with pytest.raises(AuthError):
        kdc.get_service_ticket(ticket, "other/svc")
