"""Error taxonomy and retry policy for authentication failures.

Every failure carries a machine-readable ``code`` so automation code can decide
whether to retry the same request, rotate the credential, or escalate to a human.
"""


class AuthError(Exception):
    """Base class for all authentication failures in this library."""

    EXPIRED_CREDENTIAL = "expired_credential"
    REVOKED_CREDENTIAL = "revoked_credential"
    VAULT_UNREACHABLE = "vault_unreachable"
    VAULT_SEALED = "vault_sealed"
    CLOCK_SKEW = "clock_skew"
    BAD_SIGNATURE = "bad_signature"
    UNKNOWN_PRINCIPAL = "unknown_principal"
    CERT_EXPIRED = "cert_expired"
    TICKET_EXPIRED = "ticket_expired"
    WRONG_SERVICE = "wrong_service"
    SCOPE_EXCEEDED = "scope_exceeded"   # asked for more than was granted
    FORBIDDEN = "forbidden"             # authenticated, but not allowed

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# Failures where retrying the identical request may succeed: the credential
# itself is fine, the infrastructure hiccupped. Everything else needs a new
# credential (rotation), a human (revocation), or a config fix (clock skew).
RETRYABLE_CODES = frozenset({AuthError.VAULT_UNREACHABLE})


def is_retryable(error):
    """True when retrying the same request may succeed."""
    return isinstance(error, AuthError) and error.code in RETRYABLE_CODES


class RetryPolicy:
    """Deterministic exponential backoff (no randomness, no sleeping here).

    Callers iterate :meth:`delays` and sleep themselves; tests assert the exact
    sequence.
    """

    def __init__(self, max_attempts=3, base_delay=1.0, multiplier=2.0):
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if base_delay <= 0 or multiplier < 1:
            raise ValueError("base_delay must be > 0 and multiplier >= 1")
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.multiplier = multiplier

    def delays(self):
        """Yield the delay before each retry; length is max_attempts - 1."""
        delay = self.base_delay
        for _ in range(self.max_attempts - 1):
            yield delay
            delay *= self.multiplier

    def should_retry(self, error, attempt):
        """``attempt`` is the 1-based number of attempts already made."""
        return attempt < self.max_attempts and is_retryable(error)
