"""Demo: mTLS handshake and Kerberos ticket flow."""
import sys

sys.path.insert(0, ".")
from datetime import timedelta

from authpatterns.clock import FakeClock
from authpatterns.kerberos import KDC, ServiceServer
from authpatterns.mtls import Certificate, CertificateAuthority, MTLSServer

clock = FakeClock()

# --- mTLS ---
ca = CertificateAuthority("Demo Root CA")
now = clock.now()
cert = ca.sign(Certificate("job-agent-01", now - timedelta(days=1),
                           now + timedelta(days=365)))
server = MTLSServer(clock, [ca], expected_cn="job-agent-01")
print("mTLS session:", server.handshake(cert)["peer"])

# --- Kerberos ---
kdc = KDC(clock)
kdc.add_principal("svc-batch", "batch-password")
tgt = kdc.get_tgt("svc-batch", "batch-password")
ticket = kdc.get_service_ticket(tgt, "cifs/fileserver")
result = ServiceServer("cifs/fileserver", kdc, clock).authenticate(ticket)
print("kerberos authenticated:", result)
