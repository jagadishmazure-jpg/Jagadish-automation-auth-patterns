"""Simulated credential vault.

Models the behaviour enterprise automation platforms rely on: agents fetch
short-lived credentials from a central vault instead of storing them locally.
The vault is fail-closed -- when it is unreachable or sealed, nothing is
handed out -- and the audit log only ever sees secret fingerprints, never
plaintext.
"""
from .audit import AuditLog, fingerprint
from .errors import AuthError


class Vault:
    def __init__(self, clock, audit=None):
        self._clock = clock
        self._store = {}
        self._online = True
        self._sealed = False
        self.audit = audit or AuditLog(clock)

    # -- availability ----------------------------------------------------
    def go_offline(self):
        self._online = False

    def go_online(self):
        self._online = True

    def seal(self):
        self._sealed = True

    def unseal(self):
        self._sealed = False

    def _guard(self):
        if not self._online:
            raise AuthError(AuthError.VAULT_UNREACHABLE, "vault is unreachable")
        if self._sealed:
            raise AuthError(AuthError.VAULT_SEALED, "vault is sealed")

    # -- secrets ----------------------------------------------------------
    def store(self, name, secret):
        self._guard()
        self._store[name] = secret
        self.audit.record("secret.stored", name, fingerprint(secret))

    def retrieve(self, name):
        """Fetch a secret. Raises instead of returning anything when the
        vault cannot be reached -- fail-closed, never fail-open."""
        self._guard()
        try:
            secret = self._store[name]
        except KeyError:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "no secret named %r" % (name,)) from None
        self.audit.record("secret.retrieved", name, fingerprint(secret))
        return secret

    def rotate(self, name, new_secret):
        self._guard()
        if name not in self._store:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "no secret named %r" % (name,))
        old_fp = fingerprint(self._store[name])
        self._store[name] = new_secret
        self.audit.record("secret.rotated", name,
                          "%s -> %s" % (old_fp, fingerprint(new_secret)))
