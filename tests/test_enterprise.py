"""Tests: enterprise-system auth idioms (SAP, Oracle, Salesforce, ServiceNow, shares)."""
import pytest

from authpatterns.clock import FakeClock
from authpatterns.enterprise import (
    FileShareAccess, OracleWallet, SalesforceConnectedApp, SAPServiceUser,
    SAPSystem, ServiceNowInstance,
)
from authpatterns.errors import AuthError
from authpatterns.kerberos import KDC
from datetime import timedelta


# -- SAP ---------------------------------------------------------------

def make_sap():
    clock = FakeClock()
    sap = SAPSystem(clock)
    sap.add_user(SAPServiceUser("BATCH_SVC", "pw123456", client="100"))
    return clock, sap


def test_sap_logon_ok():
    _, sap = make_sap()
    session = sap.logon("BATCH_SVC", "pw123456", "100")
    assert session["user"] == "BATCH_SVC"


def test_sap_wrong_client_rejected():
    _, sap = make_sap()
    with pytest.raises(AuthError) as exc:
        sap.logon("BATCH_SVC", "pw123456", "200")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_sap_locked_user_rejected():
    clock = FakeClock()
    sap = SAPSystem(clock)
    sap.add_user(SAPServiceUser("LOCKED", "pw", client="100", locked=True))
    with pytest.raises(AuthError) as exc:
        sap.logon("LOCKED", "pw", "100")
    assert exc.value.code == AuthError.REVOKED_CREDENTIAL


def test_sap_expired_password_rejected():
    clock = FakeClock()
    sap = SAPSystem(clock)
    sap.add_user(SAPServiceUser("OLD", "pw", client="100",
                                password_expires_at=clock.now()))
    clock.advance(days=1)
    with pytest.raises(AuthError) as exc:
        sap.logon("OLD", "pw", "100")
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL


# -- Oracle wallet ------------------------------------------------------

def test_wallet_connect_ok():
    wallet = OracleWallet()
    wallet.add_entry("PROD_DB", "etl_svc", "dbpass")
    conn = wallet.connect("PROD_DB")
    assert conn["user"] == "etl_svc"


def test_wallet_unknown_connect_string_rejected():
    wallet = OracleWallet()
    with pytest.raises(AuthError) as exc:
        wallet.connect("QA_DB")
    assert exc.value.code == AuthError.UNKNOWN_PRINCIPAL


def test_wallet_wrong_password_rejected():
    wallet = OracleWallet()
    wallet.add_entry("PROD_DB", "etl_svc", "dbpass")
    with pytest.raises(AuthError) as exc:
        wallet.connect("PROD_DB", password="wrong")
    assert exc.value.code == AuthError.BAD_SIGNATURE


# -- Salesforce connected app -------------------------------------------

def make_sf():
    clock = FakeClock()
    sf = SalesforceConnectedApp(clock)
    sf.register("etl_app", "sfsecret", org_id="00Dxx0000001ABC")
    return clock, sf


def test_salesforce_token_org_bound_ok():
    _, sf = make_sf()
    token = sf.token("etl_app", "sfsecret")
    result = sf.authenticate(token, "00Dxx0000001ABC")
    assert result["org_id"] == "00Dxx0000001ABC"


def test_salesforce_token_wrong_org_rejected():
    _, sf = make_sf()
    token = sf.token("etl_app", "sfsecret")
    with pytest.raises(AuthError) as exc:
        sf.authenticate(token, "00Dxx0000009ZZZ")
    assert exc.value.code == AuthError.WRONG_SERVICE


# -- ServiceNow ----------------------------------------------------------

def make_snow():
    clock = FakeClock()
    snow = ServiceNowInstance("https://acme.service-now.com", clock)
    snow.add_user("svc_int", "snowpass")
    return clock, snow


def test_servicenow_basic_ok():
    _, snow = make_snow()
    result = snow.basic_auth("svc_int", "snowpass",
                             "https://acme.service-now.com")
    assert result["user"] == "svc_int"


def test_servicenow_wrong_instance_rejected():
    _, snow = make_snow()
    with pytest.raises(AuthError) as exc:
        snow.basic_auth("svc_int", "snowpass",
                        "https://evil.service-now.com")
    assert exc.value.code == AuthError.WRONG_SERVICE


def test_servicenow_oauth_roundtrip():
    clock, snow = make_snow()
    token = snow.issue_oauth_token("svc_int", "snowpass",
                                   "https://acme.service-now.com")
    result = snow.token_auth(token, "https://acme.service-now.com")
    assert result["user"] == "svc_int"
    clock.advance(hours=1)
    with pytest.raises(AuthError) as exc:
        snow.token_auth(token, "https://acme.service-now.com")
    assert exc.value.code == AuthError.EXPIRED_CREDENTIAL


# -- File shares ----------------------------------------------------------

def make_share():
    clock = FakeClock()
    kdc = KDC(clock)
    kdc.add_principal("svc-batch", "pw")
    acls = {
        "finance": {"service": "cifs/fileserver",
                    "read": ["svc-batch"], "write": []},
    }
    return clock, kdc, FileShareAccess(kdc, clock, acls)


def test_share_access_with_valid_ticket():
    clock, kdc, share = make_share()
    tgt = kdc.get_tgt("svc-batch", "pw")
    ticket = kdc.get_service_ticket(tgt, "cifs/fileserver")
    result = share.access(ticket, "finance", "read")
    assert result["client"] == "svc-batch"


def test_share_acl_denies_write():
    _, kdc, share = make_share()
    tgt = kdc.get_tgt("svc-batch", "pw")
    ticket = kdc.get_service_ticket(tgt, "cifs/fileserver")
    with pytest.raises(AuthError):
        share.access(ticket, "finance", "write")


def test_share_wrong_service_ticket_rejected():
    _, kdc, share = make_share()
    tgt = kdc.get_tgt("svc-batch", "pw")
    ticket = kdc.get_service_ticket(tgt, "http/intranet")
    with pytest.raises(AuthError) as exc:
        share.access(ticket, "finance", "read")
    assert exc.value.code == AuthError.WRONG_SERVICE
