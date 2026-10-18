"""Kerberos-style ticket authentication (simulated KDC).

The flow enterprise Windows environments use: the client proves its password
once to the KDC, gets a ticket-granting ticket (TGT), then exchanges the TGT
for per-service tickets without retyping the password. Passwords are verified
with PBKDF2; tickets are HMAC-signed structures carrying client, service,
issue and expiry times.
"""
import base64
import hashlib
import hmac
import json
import secrets
from datetime import timedelta

from .audit import AuditLog
from .errors import AuthError


def _b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class KDC:
    def __init__(self, clock, realm="EXAMPLE.REALM", audit=None,
                 tgt_lifetime_seconds=3600, ticket_lifetime_seconds=600):
        self._clock = clock
        self.realm = realm
        self._principals = {}
        self._kdc_key = secrets.token_bytes(32)
        self._tgt_lifetime = timedelta(seconds=tgt_lifetime_seconds)
        self._ticket_lifetime = timedelta(seconds=ticket_lifetime_seconds)
        self.audit = audit or AuditLog(clock)

    def add_principal(self, name, password):
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                  salt, 100_000)
        self._principals[name] = (salt, key)

    def _sign(self, payload):
        body = _b64encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
        sig = _b64encode(hmac.new(self._kdc_key, body.encode("ascii"),
                                  hashlib.sha256).digest())
        return "%s.%s" % (body, sig)

    def _verify(self, token):
        try:
            body, sig = token.split(".")
        except ValueError:
            raise AuthError(AuthError.BAD_SIGNATURE, "malformed ticket") from None
        expected = _b64encode(hmac.new(self._kdc_key, body.encode("ascii"),
                                       hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "ticket signature invalid")
        return json.loads(_b64decode(body).decode("utf-8"))

    def get_tgt(self, name, password):
        entry = self._principals.get(name)
        if entry is None:
            self.audit.record("kerberos.rejected", name, "unknown_principal")
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown principal %r" % (name,))
        salt, key = entry
        presented = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                        salt, 100_000)
        if not hmac.compare_digest(key, presented):
            self.audit.record("kerberos.rejected", name, "bad_password")
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "bad password for %r" % (name,))
        now = self._clock.now()
        tgt = self._sign({
            "client": name,
            "kind": "tgt",
            "iat": int(now.timestamp()),
            "exp": int((now + self._tgt_lifetime).timestamp()),
        })
        self.audit.record("kerberos.tgt_issued", name, self.realm)
        return tgt

    def get_service_ticket(self, tgt, service):
        claims = self._verify(tgt)
        if claims.get("kind") != "tgt":
            raise AuthError(AuthError.BAD_SIGNATURE, "not a TGT")
        if self._clock.now().timestamp() > claims["exp"]:
            self.audit.record("kerberos.rejected", claims["client"],
                              "tgt_expired")
            raise AuthError(AuthError.TICKET_EXPIRED, "TGT has expired")
        now = self._clock.now()
        ticket = self._sign({
            "client": claims["client"],
            "service": service,
            "kind": "service",
            "iat": int(now.timestamp()),
            "exp": int((now + self._ticket_lifetime).timestamp()),
        })
        self.audit.record("kerberos.ticket_issued", claims["client"], service)
        return ticket


class ServiceServer:
    """A service that accepts Kerberos service tickets for its own name."""

    def __init__(self, service_name, kdc, clock):
        self._service = service_name
        self._kdc = kdc
        self._clock = clock

    def authenticate(self, ticket):
        claims = self._kdc._verify(ticket)
        if claims.get("kind") != "service":
            raise AuthError(AuthError.BAD_SIGNATURE, "not a service ticket")
        if claims.get("service") != self._service:
            raise AuthError(AuthError.WRONG_SERVICE,
                            "ticket is for %r, not %r"
                            % (claims.get("service"), self._service))
        if self._clock.now().timestamp() > claims["exp"]:
            raise AuthError(AuthError.TICKET_EXPIRED,
                            "service ticket has expired")
        return {"client": claims["client"], "service": self._service}
