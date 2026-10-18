"""Mutual TLS (simulated handshake).

Service-to-service authentication where both sides present certificates.
The handshake validates: the issuer is trusted, the signature is intact, the
certificate is within its validity window, and the identity matches the
expected service. Crypto is simulated with HMAC -- the *checks* are the point,
not the cipher suite.
"""
import hashlib
import hmac
import secrets

from .audit import AuditLog
from .errors import AuthError


class Certificate:
    def __init__(self, common_name, not_before, not_after, issuer_cn=""):
        self.common_name = common_name
        self.not_before = not_before
        self.not_after = not_after
        self.issuer_cn = issuer_cn
        self.signature = None

    def _bytes(self):
        return "|".join([
            self.common_name,
            self.not_before.isoformat(),
            self.not_after.isoformat(),
            self.issuer_cn,
        ]).encode("utf-8")


class CertificateAuthority:
    """Simulated CA: signs certificates, verifies signatures."""

    def __init__(self, common_name="Example Root CA"):
        self.common_name = common_name
        self._key = secrets.token_bytes(32)

    def sign(self, cert):
        cert.issuer_cn = self.common_name
        cert.signature = hmac.new(self._key, cert._bytes(),
                                  hashlib.sha256).hexdigest()
        return cert

    def verify(self, cert):
        if cert.issuer_cn != self.common_name or cert.signature is None:
            return False
        expected = hmac.new(self._key, cert._bytes(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, cert.signature)


class MTLSServer:
    """Server side of the handshake: validates the client's certificate."""

    def __init__(self, clock, trusted_cas, expected_cn=None, audit=None):
        self._clock = clock
        self._cas = list(trusted_cas)
        self._expected_cn = expected_cn
        self.audit = audit or AuditLog(clock)

    def handshake(self, cert):
        now = self._clock.now()
        if not any(ca.verify(cert) for ca in self._cas):
            self.audit.record("mtls.rejected", cert.common_name,
                              "untrusted_issuer")
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "certificate issuer is not trusted")
        if now < cert.not_before or now > cert.not_after:
            self.audit.record("mtls.rejected", cert.common_name,
                              "cert_expired")
            raise AuthError(AuthError.CERT_EXPIRED,
                            "certificate is outside its validity window")
        if self._expected_cn and cert.common_name != self._expected_cn:
            self.audit.record("mtls.rejected", cert.common_name,
                              "cn_mismatch")
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unexpected client identity %r"
                            % (cert.common_name,))
        self.audit.record("mtls.established", cert.common_name, "ok")
        return {"peer": cert.common_name, "established_at": now.isoformat()}
