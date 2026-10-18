"""Hash-chained audit log for authentication events.

Each entry commits to the previous entry's hash, so tampering with history is
detectable via :meth:`AuditLog.verify`. Secrets are never written here: callers
pass :func:`fingerprint` values, never plaintext.
"""
import hashlib
import hmac
import json


def fingerprint(secret):
    """Short, non-reversible identifier for a secret (safe for logs)."""
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


class AuditLog:
    def __init__(self, clock):
        self._clock = clock
        self._entries = []

    def record(self, event_type, principal, detail=""):
        prev = self._entries[-1]["hash"] if self._entries else "GENESIS"
        entry = {
            "seq": len(self._entries),
            "ts": self._clock.now().isoformat(),
            "type": event_type,
            "principal": principal,
            "detail": detail,
            "prev": prev,
        }
        entry["hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self._entries.append(entry)
        return entry

    def entries(self):
        return list(self._entries)

    def verify(self):
        """Recompute the chain; False means history was tampered with."""
        prev = "GENESIS"
        for i, entry in enumerate(self._entries):
            if entry["seq"] != i or entry["prev"] != prev:
                return False
            check = dict(entry)
            claimed = check.pop("hash")
            recomputed = hashlib.sha256(
                json.dumps(check, sort_keys=True).encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(claimed, recomputed):
                return False
            prev = claimed
        return True
