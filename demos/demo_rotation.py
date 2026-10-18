"""Demo: zero-downtime credential rotation with overlap window."""
import sys
sys.path.insert(0, ".")

from authpatterns.clock import FakeClock
from authpatterns.errors import AuthError
from authpatterns.rotation import DualCredentialRotation

clock = FakeClock()
rot = DualCredentialRotation(clock, overlap_seconds=300)
rot.set_initial("db-password-v1")

print("v1 works:", rot.authenticate("db-password-v1"))

rot.begin_rotation("db-password-v2")
print("during overlap, v1 works:", rot.authenticate("db-password-v1"))
print("during overlap, v2 works:", rot.authenticate("db-password-v2"))

clock.advance(minutes=6)  # overlap window ends
try:
    rot.authenticate("db-password-v1")
    print("v1 still works: UNEXPECTED")
except AuthError as e:
    print("after overlap, v1 rejected:", e.code)
print("after overlap, v2 works:", rot.authenticate("db-password-v2"))
