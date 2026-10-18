# Decision guide: which pattern for which target

"If the target is X, use pattern Y because Z."

| Target | Pattern (module) | Because |
|---|---|---|
| SAP app server | Service user + client (`enterprise.SAPSystem`) | SAP identity *is* user+client; locked/expired are distinct failures you must handle |
| Oracle / any database | Wallet (`enterprise.OracleWallet`) | Keeps passwords out of job definitions, the #1 leak vector in batch estates |
| Salesforce | Org-bound connected app (`enterprise.SalesforceConnectedApp`) | Org binding stops a sandbox token from ever touching production |
| ServiceNow | Instance-bound auth (`enterprise.ServiceNowInstance`) | Same reason: dev credentials must not work against prod |
| Windows file share | Kerberos ticket + ACL (`enterprise.FileShareAccess`) | Ticket proves identity, ACL grants access; the two checks are independent |
| Modern REST API | OAuth client credentials (`oauth.OAuthClient`) | Short-lived tokens, cached and refreshed before expiry; no long-lived secrets |
| Internal API on a schedule | API key (`api_key.ApiKeyStore`) | Simple, expiry-bounded; fine when OAuth is overkill |
| Service-to-service (east-west) | mTLS (`mtls.MTLSServer`) | Both sides prove identity; no shared secrets to rotate |
| Windows estate services | Kerberos (`kerberos.KDC`) | The estate already runs a KDC; use it instead of inventing auth |
| Any long-lived secret | Vault + rotation (`vault.Vault`, `rotation.DualCredentialRotation`) | One storage place, fail-closed reads, overlap window so rotation never breaks jobs |
| AI agent calling tools | Agent token + governed registry (`agentic.*`) | Agents choose targets at run time; static service accounts cannot cover that |
| Agent acting for a user | Scoped delegation (`agentic.Delegation`) | Subset rule guarantees the agent never exceeds the delegator |

## Rules of thumb

1. **Prefer the target's native idiom.** SAP wants user+client; don't force
   OAuth where the system expects a service user.
2. **Bind credentials to their scope.** Org id, instance URL, service name --
   whatever makes a credential useless outside its intended target.
3. **Short lifetimes beat clever storage.** A 10-minute token that leaks is a
   10-minute problem.
4. **Rotation is a process.** If changing a credential can break a running
   job, you need an overlap window, not a faster change.
