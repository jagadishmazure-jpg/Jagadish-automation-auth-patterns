"""Demo: vaulted service account with rotation (fail-closed)."""
import sys

sys.path.insert(0, ".")

from authpatterns.audit import AuditLog
from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.vault import Vault

clock = FakeClock()
vault = Vault(clock, AuditLog(clock))

vault.store("erp/service-password", "initial-secret-001")
print("stored, retrieved:", vault.retrieve("erp/service-password")
      == "initial-secret-001")

vault.rotate("erp/service-password", "rotated-secret-002")
print("after rotation, new secret served:", vault.retrieve("erp/service-password")
      == "rotated-secret-002")

# fail-closed: vault down -> no credentials, and the failure is retryable
vault.go_offline()
try:
    vault.retrieve("erp/service-password")
except AuthError as e:
    from authpatterns.errors import is_retryable
    print("vault offline -> code=%s retryable=%s" % (e.code, is_retryable(e)))
vault.go_online()

print("audit chain valid:", vault.audit.verify())
print("audit holds fingerprints only:",
      all("secret" not in e["detail"] for e in vault.audit.entries()))
