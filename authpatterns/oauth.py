"""OAuth 2.0 client-credentials flow (simulated token endpoint).

Models what an automation agent does against a modern API: exchange a client
id/secret for a short-lived bearer token, cache it, and refresh *before* it
expires so jobs never observe an expired token. Tokens are HMAC-signed and
validated with a clock-skew leeway, the way real deployments tolerate small
clock differences between hosts.
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
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


class FakeTokenEndpoint:
    """Stands in for an OAuth authorization server (no network)."""

    def __init__(self, clock):
        self._clock = clock
        self._clients = {}
        self._signing_key = secrets.token_bytes(32)

    def register(self, client_id, client_secret):
        self._clients[client_id] = client_secret

    def token(self, client_id, client_secret, scope="default", ttl_seconds=3600):
        expected = self._clients.get(client_id)
        if expected is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown client %r" % (client_id,))
        if not hmac.compare_digest(expected, client_secret):
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "bad secret for client %r" % (client_id,))
        now = self._clock.now()
        payload = {
            "sub": client_id,
            "scope": scope,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "jti": secrets.token_hex(8),
        }
        body = _b64encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
        sig = _b64encode(hmac.new(self._signing_key, body.encode("ascii"),
                                  hashlib.sha256).digest())
        return {
            "access_token": "%s.%s" % (body, sig),
            "token_type": "Bearer",
            "expires_in": ttl_seconds,
        }

    def validate(self, token, leeway_seconds=60):
        """Validate a token, tolerating ``leeway_seconds`` of clock skew."""
        try:
            body, sig = token.split(".")
        except ValueError:
            raise AuthError(AuthError.BAD_SIGNATURE, "malformed token")
        expected = _b64encode(hmac.new(self._signing_key, body.encode("ascii"),
                                       hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            raise AuthError(AuthError.BAD_SIGNATURE, "token signature invalid")
        try:
            claims = json.loads(_b64decode(body).decode("utf-8"))
        except Exception:
            raise AuthError(AuthError.BAD_SIGNATURE, "token payload unreadable")
        now_ts = self._clock.now().timestamp()
        if now_ts < claims["iat"] - leeway_seconds:
            raise AuthError(AuthError.CLOCK_SKEW,
                            "token used before it was issued: clocks disagree")
        if now_ts > claims["exp"] + leeway_seconds:
            raise AuthError(AuthError.EXPIRED_CREDENTIAL, "token has expired")
        return claims


class OAuthClient:
    """Client-credentials consumer with caching and proactive refresh."""

    def __init__(self, client_id, client_secret, endpoint, clock,
                 refresh_margin_seconds=120, audit=None):
        self._client_id = client_id
        self._client_secret = client_secret
        self._endpoint = endpoint
        self._clock = clock
        self._margin = timedelta(seconds=refresh_margin_seconds)
        self.audit = audit or AuditLog(clock)
        self._token = None
        self._expires_at = None

    def get_token(self, scope="default"):
        now = self._clock.now()
        if self._token is not None and now < self._expires_at - self._margin:
            self.audit.record("oauth.cache_hit", self._client_id, scope)
            return self._token
        resp = self._endpoint.token(self._client_id, self._client_secret,
                                    scope=scope)
        self._token = resp["access_token"]
        self._expires_at = now + timedelta(seconds=resp["expires_in"])
        self.audit.record("oauth.token_acquired", self._client_id, scope)
        return self._token
