"""Zero-downtime credential rotation via a dual-credential overlap window.

The failure this prevents: rotating a database password at 02:00 and killing
every in-flight job that fetched the old password at 01:59. The pattern:

1. ``begin_rotation(new)`` -- the new credential becomes primary, the old one
   stays valid for ``overlap_seconds``.
2. During the overlap, both credentials authenticate.
3. After the overlap (or an explicit ``complete_rotation()``), the old one is
   rejected.

Rotation is a *process*, not an event: fetchers pick up the new credential on
their next fetch, and the overlap absorbs the stragglers.
"""
import hmac
from datetime import timedelta

from .audit import AuditLog
from .errors import AuthError


class DualCredentialRotation:
    def __init__(self, clock, overlap_seconds=300, audit=None):
        self._clock = clock
        self._overlap = timedelta(seconds=overlap_seconds)
        self.audit = audit or AuditLog(clock)
        self._current = None
        self._previous = None
        self._overlap_until = None

    def set_initial(self, credential, name="primary"):
        self._current = (name, credential)
        self.audit.record("rotation.initial", name, "set")

    def begin_rotation(self, new_credential, name="primary"):
        if self._current is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "no credential to rotate")
        self._previous = self._current
        self._current = (name, new_credential)
        self._overlap_until = self._clock.now() + self._overlap
        self.audit.record("rotation.began", name,
                          "overlap_until=%s" % self._overlap_until.isoformat())

    def complete_rotation(self, name="primary"):
        self._previous = None
        self._overlap_until = None
        self.audit.record("rotation.completed", name, "old credential retired")

    def _overlap_active(self):
        return (self._previous is not None
                and self._overlap_until is not None
                and self._clock.now() < self._overlap_until)

    def authenticate(self, presented):
        """Accept the current credential, or the previous one while the
        overlap window is open. Constant-time comparison both times."""
        if self._current is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL, "no credential set")
        name, current = self._current
        if hmac.compare_digest(str(current), str(presented)):
            return name
        if self._overlap_active():
            _, previous = self._previous
            if hmac.compare_digest(str(previous), str(presented)):
                self.audit.record("rotation.overlap_hit", name,
                                  "old credential used during overlap")
                return name
        self.audit.record("rotation.rejected", name, "no_match")
        raise AuthError(AuthError.REVOKED_CREDENTIAL,
                        "credential not accepted")
