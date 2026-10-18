"""Auth idioms of traditional enterprise systems.

Automation platforms rarely talk to "an API" in the abstract -- they talk to
an SAP application server, an Oracle database, a Salesforce org, a ServiceNow
instance, or a Windows file share. Each has its own auth idiom, and choosing
the wrong one is a classic enterprise integration failure. This module models
the idioms so the right pattern can be picked per target:

* **SAP** -- service user + client number; locked users and expired passwords
  are distinct, common failure modes.
* **Oracle DB** -- wallet-based auth: credentials live in a client-side wallet,
  the connection string carries no password.
* **Salesforce** -- connected app: server-to-server OAuth scoped to one org.
* **ServiceNow** -- instance-bound auth: basic or OAuth, always tied to the
  instance URL so a token for dev cannot hit prod.
* **File shares** -- Kerberos service ticket plus a share ACL: the ticket
  proves who you are, the ACL decides what you may touch.
"""
import hashlib
import hmac
import secrets
from datetime import timedelta

from .audit import AuditLog
from .errors import AuthError
from .kerberos import ServiceServer


def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               salt, 100_000).hex()


# --------------------------------------------------------------------------
# SAP-style: service user + client
# --------------------------------------------------------------------------

class SAPServiceUser:
    def __init__(self, username, password, client, locked=False,
                 password_expires_at=None):
        self.username = username
        self._salt = secrets.token_bytes(16)
        self._password_hash = _hash_password(password, self._salt)
        self.client = client
        self.locked = locked
        self.password_expires_at = password_expires_at

    def check_password(self, password):
        return hmac.compare_digest(
            self._password_hash, _hash_password(password, self._salt))


class SAPSystem:
    """SAP application server logon: user + password + client number."""

    def __init__(self, clock, audit=None):
        self._clock = clock
        self._users = {}
        self.audit = audit or AuditLog(clock)

    def add_user(self, user):
        self._users[user.username] = user

    def logon(self, username, password, client):
        user = self._users.get(username)
        if user is None or user.client != client:
            self.audit.record("sap.logon_rejected", username,
                              "unknown_user_or_client")
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown user %r for client %r"
                            % (username, client))
        if user.locked:
            self.audit.record("sap.logon_rejected", username, "locked")
            raise AuthError(AuthError.REVOKED_CREDENTIAL,
                            "user %r is locked" % (username,))
        if (user.password_expires_at is not None
                and self._clock.now() >= user.password_expires_at):
            self.audit.record("sap.logon_rejected", username,
                              "password_expired")
            raise AuthError(AuthError.EXPIRED_CREDENTIAL,
                            "password for %r has expired" % (username,))
        if not user.check_password(password):
            self.audit.record("sap.logon_rejected", username, "bad_password")
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "bad password for %r" % (username,))
        self.audit.record("sap.logon", username, "client=%s" % client)
        return {"user": username, "client": client,
                "at": self._clock.now().isoformat()}


# --------------------------------------------------------------------------
# Oracle-style: wallet-based auth
# --------------------------------------------------------------------------

class OracleWallet:
    """Client-side wallet: the connect string names an entry, the wallet
    supplies the credentials. No password ever appears in job definitions."""

    def __init__(self, audit=None, clock=None):
        self._entries = {}
        self.audit = audit or (AuditLog(clock) if clock else None)

    def add_entry(self, connect_string, username, password):
        salt = secrets.token_bytes(16)
        self._entries[connect_string] = {
            "username": username,
            "salt": salt,
            "hash": _hash_password(password, salt),
        }
        if self.audit:
            self.audit.record("wallet.entry_added", connect_string, username)

    def connect(self, connect_string, password=None):
        """Wallet auth ignores any supplied password -- the wallet *is* the
        credential. A connect string with no wallet entry is rejected."""
        entry = self._entries.get(connect_string)
        if entry is None:
            if self.audit:
                self.audit.record("db.connect_rejected", connect_string,
                                  "no_wallet_entry")
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "no wallet entry for %r" % (connect_string,))
        if password is not None and not hmac.compare_digest(
                entry["hash"], _hash_password(password, entry["salt"])):
            if self.audit:
                self.audit.record("db.connect_rejected", connect_string,
                                  "bad_password")
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "bad password for %r" % (connect_string,))
        if self.audit:
            self.audit.record("db.connected", connect_string,
                              entry["username"])
        return {"connect_string": connect_string,
                "user": entry["username"]}


# --------------------------------------------------------------------------
# Salesforce-style: connected app (server-to-server OAuth, org-scoped)
# --------------------------------------------------------------------------

class SalesforceConnectedApp:
    """Server-to-server OAuth where every token is bound to one org id.

    The org binding is the point: a token minted for the sandbox org must
    never authenticate against production, even if the attacker holds it.
    """

    def __init__(self, clock, audit=None):
        self._clock = clock
        self._key = secrets.token_bytes(32)
        self._apps = {}
        self.audit = audit or AuditLog(clock)

    def register(self, client_id, client_secret, org_id):
        self._apps[client_id] = {"secret": client_secret, "org_id": org_id}

    def token(self, client_id, client_secret, ttl_seconds=3600):
        app = self._apps.get(client_id)
        if app is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown connected app %r" % (client_id,))
        if not hmac.compare_digest(app["secret"], client_secret):
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "bad secret for %r" % (client_id,))
        now = self._clock.now()
        body = "%s|%s|%d|%d" % (
            client_id, app["org_id"], int(now.timestamp()),
            int((now + timedelta(seconds=ttl_seconds)).timestamp()))
        sig = hmac.new(self._key, body.encode("utf-8"),
                       hashlib.sha256).hexdigest()
        self.audit.record("sf.token_issued", client_id, app["org_id"])
        return "%s|%s" % (body, sig)

    def authenticate(self, token, org_id):
        try:
            body, sig = token.rsplit("|", 1)
            client_id, token_org, iat, exp = body.split("|")
        except ValueError:
            raise AuthError(AuthError.BAD_SIGNATURE, "malformed token")
        expected = hmac.new(self._key, body.encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise AuthError(AuthError.BAD_SIGNATURE, "token signature invalid")
        if token_org != org_id:
            self.audit.record("sf.rejected", client_id,
                              "wrong_org %s" % token_org)
            raise AuthError(AuthError.WRONG_SERVICE,
                            "token is for org %r, not %r"
                            % (token_org, org_id))
        if self._clock.now().timestamp() > int(exp):
            raise AuthError(AuthError.EXPIRED_CREDENTIAL, "token expired")
        self.audit.record("sf.authenticated", client_id, org_id)
        return {"client_id": client_id, "org_id": org_id}


# --------------------------------------------------------------------------
# ServiceNow-style: instance-bound auth (basic or OAuth)
# --------------------------------------------------------------------------

class ServiceNowInstance:
    """Auth bound to one instance URL: credentials for dev.acme cannot be
    replayed against prod, because the instance is part of the check."""

    def __init__(self, instance_url, clock, audit=None):
        self.instance_url = instance_url
        self._clock = clock
        self._users = {}
        self._tokens = {}
        self.audit = audit or AuditLog(clock)

    def add_user(self, username, password):
        salt = secrets.token_bytes(16)
        self._users[username] = (salt, _hash_password(password, salt))

    def basic_auth(self, username, password, instance_url):
        self._check_instance(instance_url)
        entry = self._users.get(username)
        if entry is None or not hmac.compare_digest(
                entry[1], _hash_password(password, entry[0])):
            self.audit.record("snow.rejected", username, "bad_credentials")
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "bad credentials for %r" % (username,))
        self.audit.record("snow.authenticated", username, "basic")
        return {"user": username, "instance": self.instance_url}

    def issue_oauth_token(self, username, password, instance_url,
                          ttl_seconds=1800):
        self.basic_auth(username, password, instance_url)
        token = "sn_" + secrets.token_hex(16)
        self._tokens[token] = (username,
                               self._clock.now()
                               + timedelta(seconds=ttl_seconds))
        self.audit.record("snow.token_issued", username, self.instance_url)
        return token

    def token_auth(self, token, instance_url):
        self._check_instance(instance_url)
        entry = self._tokens.get(token)
        if entry is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL, "unknown token")
        username, exp = entry
        if self._clock.now() >= exp:
            raise AuthError(AuthError.EXPIRED_CREDENTIAL, "token expired")
        self.audit.record("snow.authenticated", username, "oauth")
        return {"user": username, "instance": self.instance_url}

    def _check_instance(self, instance_url):
        if instance_url != self.instance_url:
            self.audit.record("snow.rejected", instance_url, "wrong_instance")
            raise AuthError(AuthError.WRONG_SERVICE,
                            "credentials are for %r, not %r"
                            % (self.instance_url, instance_url))


# --------------------------------------------------------------------------
# File shares: Kerberos ticket + share ACL
# --------------------------------------------------------------------------

class FileShareAccess:
    """Kerberos proves *who* you are; the share ACL decides *what* you may
    touch. Both checks must pass."""

    def __init__(self, kdc, clock, share_acls, audit=None):
        # share_acls: {share_name: {"service": "cifs/fileserver", "read": [...], "write": [...]}}
        self._kdc = kdc
        self._clock = clock
        self._acls = share_acls
        self.audit = audit or AuditLog(clock)

    def access(self, service_ticket, share, operation="read"):
        acl = self._acls.get(share)
        if acl is None:
            raise AuthError(AuthError.UNKNOWN_PRINCIPAL,
                            "unknown share %r" % (share,))
        server = ServiceServer(acl["service"], self._kdc, self._clock)
        auth = server.authenticate(service_ticket)  # raises on bad ticket
        allowed = acl.get(operation, [])
        if auth["client"] not in allowed:
            self.audit.record("share.denied", auth["client"],
                              "%s %s" % (share, operation))
            raise AuthError(AuthError.BAD_SIGNATURE,
                            "%r is not allowed to %s %r"
                            % (auth["client"], operation, share))
        self.audit.record("share.accessed", auth["client"],
                          "%s %s" % (share, operation))
        return {"client": auth["client"], "share": share,
                "operation": operation}
