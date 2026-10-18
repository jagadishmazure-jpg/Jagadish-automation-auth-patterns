# Architecture

## Module map

```mermaid
flowchart TB
    subgraph core["Core (every pattern uses these)"]
        clock["clock.py<br/>Clock / FakeClock"]
        errors["errors.py<br/>AuthError taxonomy<br/>RetryPolicy"]
        audit["audit.py<br/>hash-chained AuditLog"]
    end

    subgraph security["Security automation"]
        vault["vault.py<br/>fail-closed vault"]
        apikey["api_key.py<br/>expiry + revocation"]
        oauth["oauth.py<br/>client credentials"]
        mtls["mtls.py<br/>handshake checks"]
        kerb["kerberos.py<br/>TGT -> service ticket"]
        rot["rotation.py<br/>dual-credential overlap"]
    end

    subgraph agentic["Agentic AI"]
        agentid["agentic.py<br/>AgentIssuer"]
        deleg["agentic.py<br/>Delegation (on-behalf-of)"]
        gov["agentic.py<br/>GovernedToolRegistry"]
    end

    subgraph enterprise["Enterprise systems"]
        sap["enterprise.py<br/>SAPSystem"]
        ora["enterprise.py<br/>OracleWallet"]
        sf["enterprise.py<br/>SalesforceConnectedApp"]
        snow["enterprise.py<br/>ServiceNowInstance"]
        share["enterprise.py<br/>FileShareAccess"]
    end

    vault --> clock
    vault --> errors
    vault --> audit
    apikey --> clock
    apikey --> errors
    oauth --> clock
    oauth --> errors
    mtls --> clock
    mtls --> errors
    kerb --> clock
    kerb --> errors
    rot --> clock
    rot --> errors
    agentid --> clock
    agentid --> errors
    agentid --> audit
    sap --> clock
    ora --> audit
    sf --> clock
    snow --> clock
    share --> kerb
```

## Request flow: governed tool call

```mermaid
sequenceDiagram
    participant A as Agent
    participant I as AgentIssuer
    participant R as GovernedToolRegistry
    participant T as Tool

    A->>I: issue(agent_id, scopes)
    I-->>A: identity token (short-lived)
    A->>R: call(token, "get_ticket", args)
    R->>I: validate(token)
    I-->>R: claims (or EXPIRED)
    R->>R: scopes cover tool? grant exists?
    alt allowed
        R->>T: execute(args)
        T-->>R: result
        R-->>A: result
    else denied
        R-->>A: AuthError (audited)
    end
```

## Rotation timeline

```mermaid
gantt
    title Zero-downtime rotation
    dateFormat HH:mm
    axisFormat %H:%M
    section Credentials
    old credential valid           :done, 00:00, 65m
    overlap (both valid)            :active, 60m, 5m
    new credential valid            :done, 60m, 120m
```

## Failure decision flow

```mermaid
flowchart TD
    F["AuthError raised"] --> C{error code}
    C -->|vault_unreachable| R["Retry with backoff"]
    C -->|expired_credential<br/>cert_expired<br/>ticket_expired| ROT["Rotate / re-acquire"]
    C -->|revoked_credential<br/>bad_signature<br/>unknown_principal<br/>wrong_service<br/>vault_sealed| E["Escalate to human"]
    C -->|clock_skew| CFG["Fix clock config"]
```
