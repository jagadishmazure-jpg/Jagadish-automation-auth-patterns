"""API-key authentication with expiry and revocation.

The pattern used when an automation agent calls a target system's REST API:
a key id travels in the clear, the secret is compared in constant time, and
keys carry an expiry so a leaked key has a limited blast radius.
"""
import hmac
import secrets
from datetime import timedelta

from .audit import AuditLog
from .errors import AuthError


class ApiKey:
    def __init__(self, key_id, secret, expires_at, owner=None):
        self.key_id = key_id
        self.owner = owner
        self.secret = secret
        self.expires_at = expires_at
        self.revoked = False


class ApiKeyStore:
    def __init__(self, clock, audit=None):
        self._clock = clock
        self._keys = {}
        self.audit = audit or AuditLog(clock)

    def issue(self, owner, ttl_seconds=3600):
        key_id = "ak_" + secrets.token_hex(8)
        key = ApiKey(key_id, secrets.token_hex(32),
                     self._clock.now() + timedelta(seconds=ttl_seconds), owner)
        self._keys[key_id] = key
        self.audit.record("apikey.issued", owner, key_id)
        return key

    def authenticate(self, key_id, secret):
        key = self._keys.get(key_id)
        if key is None:
            self.audit.record("apikey.rejected", key_id, "unknown_key")
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown key id %r" % (key_id,))
        # Check the secret first: the key id travels in the clear, so status
        # (revoked/expired) must not be revealed to someone without the secret.
        if not isinstance(secret, str) or not hmac.compare_digest(
                key.secret.encode("utf-8"), secret.encode("utf-8")):
            self.audit.record("apikey.rejected", key_id, "bad_secret")
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "secret mismatch for key %r" % (key_id,))
        if key.revoked:
            self.audit.record("apikey.rejected", key_id, "revoked")
            raise AuthError(AuthError.REVOKED_CREDENTIAL,
                            "key %r has been revoked" % (key_id,))
        if self._clock.now() >= key.expires_at:
            self.audit.record("apikey.rejected", key_id, "expired")
            raise AuthError(AuthError.EXPIRED_CREDENTIAL,
                            "key %r has expired" % (key_id,))
        self.audit.record("apikey.authenticated", key_id, "ok")
        return key_id

    def revoke(self, key_id):
        key = self._keys.get(key_id)
        if key is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown key id %r" % (key_id,))
        key.revoked = True
        self.audit.record("apikey.revoked", key_id, "revoked")

    def rotate(self, key_id, ttl_seconds=3600, overlap_seconds=300):
        """Issue a replacement; the old key stays valid for ``overlap_seconds``
        so in-flight jobs are not killed mid-run (see rotation.py)."""
        old = self._keys.get(key_id)
        if old is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown key id %r" % (key_id,))
        if old.revoked:
            # Revocation is terminal: rotating would mint a working key from
            # one that was deliberately killed.
            raise AuthError(AuthError.REVOKED_CREDENTIAL,
                            "key %r is revoked and cannot be rotated" % (key_id,))
        new = self.issue(old.owner or "rotation", ttl_seconds=ttl_seconds)
        old.expires_at = min(
            old.expires_at,
            self._clock.now() + timedelta(seconds=overlap_seconds),
        )
        self.audit.record("apikey.rotated", key_id, "-> %s" % new.key_id)
        return new
