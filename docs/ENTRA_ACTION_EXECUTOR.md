# Microsoft Entra–authenticated action execution

Agent Proof Pack can verify a Microsoft Entra **app-only access token issued for the Agent Proof Pack API** before submitting a previously approved PostgreSQL change. The permission is tied to one tenant, one client application, one service-principal object and one named API application role. The existing transaction gate still decides whether the specific row update is permitted.

## Security boundaries

1. Register a **dedicated API** in Entra (single-tenant). Define an application role named `AgentProof.Apply` with **Applications** as its allowed member type. Its App ID URI is the `AGENTPROOF_ENTRA_AUDIENCE` of this guard.
2. Register the caller application, establish its credentials or federated credentials, and explicitly assign it the API's `AgentProof.Apply` app role. This is a resource-specific assignment, not a Microsoft Graph, Fabric, Azure RBAC or directory-admin grant.
3. An operator-controlled executor receives the access token and action UUID; the executor owns the trusted configuration, database connection, source code and network boundary. The agent must **not** be able to edit any `AGENTPROOF_ENTRA_*` variables or call the legacy `agent-guarded apply` executable directly.
4. The wrapper checks the JWT's RSA signature using tenant-scoped Microsoft signing keys, issuer, expiry, not-before, audience, tenant, client app ID, service-principal object ID and assigned application role. ID tokens and delegated user scopes cannot substitute for app-only API access tokens.
5. If the identity is authorized, only the UUID is forwarded to the existing PostgreSQL protected function. The independent database witness still must verify the actual committed effect with a separately protected read-only credential.

An access token for Microsoft Graph, Microsoft Fabric or Azure Management **must not be accepted** by the guard, even when issued to the same client in the same tenant. Microsoft calls accepting another resource's access token a *confused deputy* issue. Likewise, a validated token without the operator's one-use action authorization cannot authorize a database write.

### Protected executor configuration

Install `pip install -e '.[entra,postgresql]'`. The following environment values are supplied **by a protected service or operator**, never by the incoming agent request:

| Variable | Meaning |
| --- | --- |
| `AGENTPROOF_ENTRA_TENANT_ID` | Exactly one approved tenant UUID |
| `AGENTPROOF_ENTRA_AUDIENCE` | App ID URI of **this** guard API |
| `AGENTPROOF_ENTRA_CLIENT_ID` | Allowed caller application client UUID |
| `AGENTPROOF_ENTRA_PRINCIPAL_OID` | Allowed caller service principal **object** UUID (not client ID) |
| `AGENTPROOF_ENTRA_REQUIRED_ROLE` | `AgentProof.Apply` |
| `AGENTPROOF_ENTRA_ACCESS_TOKEN` | Per-request API access token, transient and secret |
| `AGENTPROOF_ACTOR_DSN` | Restricted PostgreSQL EXECUTE-only credential |

The protected executor runs:

```sh
agent-guarded-entra --action-id <operator-issued-uuid>
```

A successful wrapper result is `submitted_unverified`, **never** proof of a correct database effect. The operator follows with `agent-guarded observe` and `agent-guarded check` using independent credentials and the original approved contract.

### Regression coverage

Run `python -m unittest tests/test_entra_authorization.py -v` with optional `entra` dependencies installed. The test suite signs actual RSA JWTs and covers wrong resource, tenant, issuer, client, object ID, application role, delegated scopes, altered signature, expiration and not-before. It asserts that the DB function is never invoked when authentication fails. CI runs this separately from the dependency-light base tests.

### Deployment limits

This is a *reference executor*, not a network API implementation, token-introspection service, immutable approval store or complete revocation guarantee. Key rotation is fetched through Microsoft's current keys; already issued tokens remain usable until expiry unless explicitly blocked by the surrounding system. JWT app roles are not a substitute for database constraints, action-level approval, server-side nonce/replay controls, admission limits or independent observation.

If an application is permitted to run arbitrary shell commands or change trusted environment variables on the executor, it can bypass a local command wrapper. Place the guard behind an isolated API or job boundary with non-agent-controlled configuration and restricted access to the original transaction gate. In a multi-tenant service, never derive the expected audience, tenant, role or caller from untrusted token claims.

### Microsoft reference

- [Access token validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [App-only access and application roles](https://learn.microsoft.com/en-us/entra/identity-platform/app-only-access-primer)
- [Configure API application roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)
