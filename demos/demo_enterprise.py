"""Demo: enterprise-system idioms -- SAP, Oracle wallet, Salesforce, ServiceNow."""
import sys
sys.path.insert(0, ".")

from authpatterns.clock import FakeClock
from authpatterns.enterprise import (
    OracleWallet, SalesforceConnectedApp, SAPServiceUser, SAPSystem,
    ServiceNowInstance,
)
from authpatterns.errors import AuthError

clock = FakeClock()

# SAP: user + password + client
sap = SAPSystem(clock)
sap.add_user(SAPServiceUser("BATCH_SVC", "sap-password", client="100"))
print("SAP logon:", sap.logon("BATCH_SVC", "sap-password", "100")["user"])

# Oracle: wallet, no password in the job definition
wallet = OracleWallet()
wallet.add_entry("PROD_DB", "etl_svc", "db-password")
print("Oracle connect:", wallet.connect("PROD_DB"))

# Salesforce: org-bound connected-app token
sf = SalesforceConnectedApp(clock)
sf.register("etl_app", "sf-secret", org_id="00Dxx0000001ABC")
token = sf.token("etl_app", "sf-secret")
print("Salesforce auth:", sf.authenticate(token, "00Dxx0000001ABC")["org_id"])
try:
    sf.authenticate(token, "00Dxx0000009ZZZ")  # wrong org
except AuthError as e:
    print("wrong org blocked:", e.code)

# ServiceNow: instance-bound basic auth
snow = ServiceNowInstance("https://acme.service-now.com", clock)
snow.add_user("svc_int", "snow-password")
print("ServiceNow auth:",
      snow.basic_auth("svc_int", "snow-password",
                      "https://acme.service-now.com")["user"])
