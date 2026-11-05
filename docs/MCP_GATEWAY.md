# Authenticated remote MCP execution gateway (research pilot)

**Status: opt-in isolated-service prototype, not production certified.**

The remote Streamable HTTP MCP tool accepts only an operator-approved UUID.
It verifies an Entra app-only access token for a *dedicated* Agent Proof API,
then calls the existing restricted PostgreSQL one-use transaction function.
It does not accept SQL, policy, grant specifications, credentials or arbitrary
destinations from an AI agent.

## Trust boundary

    Codex / another MCP client -- HTTPS with bearer token -->
    HTTPS reverse proxy -- localhost-only MCP resource server -->
    fixed Entra tenant + aud + app + principal + AgentProof.Apply -->
    fixed EXECUTE-only PostgreSQL identity -->
    agentproof_generic.apply_text_change(preapproved_uuid)

    Operator: creates revocable and expiring grants independently
    Witness:  separately reads database outcome with SELECT-only credentials

The agent must NOT have the executor DSN, database-owner access, grant-writer
permissions, gateway environment, signing keys, or any direct network path to
PostgreSQL. Merely adding an MCP server to an unconfined Codex shell is not
containment: the agent might simply bypass the gateway.

## Controlled deployment

1. Start with the disposable PostgreSQL environment from
   [GENERIC_TRANSACTION_GATE.md](GENERIC_TRANSACTION_GATE.md). Install and
   enroll tables, and provision distinct operator, EXECUTE-only executor
   and read-only witness identities.
2. Register a separate Microsoft Entra resource API (not Graph or Fabric).
   Define the AgentProof.Apply app-only role and assign it to one dedicated
   caller service principal. The token must be issued specifically for the
   guard API audience, and contain the exact expected tenant, client ID,
   principal OID and application role.
3. Host the gateway in a separate trust zone from the agent, with locked
   deployment files and a DB egress path accessible only to the gateway.
   Bind to loopback and expose via a properly configured HTTPS reverse proxy.
4. Provide the following settings from protected service configuration;
   never inject the DB executor DSN into an agent's shell:

   - AGENTPROOF_ENTRA_TENANT_ID: expected tenant UUID
   - AGENTPROOF_ENTRA_AUDIENCE: dedicated api:// guard API audience
   - AGENTPROOF_ENTRA_CLIENT_ID: allowed caller app UUID
   - AGENTPROOF_ENTRA_PRINCIPAL_OID: allowed service principal OID
   - AGENTPROOF_ACTOR_DSN: restricted PostgreSQL EXECUTE-only connection
   - AGENTPROOF_MCP_RESOURCE_URL: external HTTPS endpoint such as
     https://guard.example.com/mcp

   The required AgentProof.Apply role is fixed in the implementation.

5. On a protected Python 3.10+ service instance, start:

       pip install -e '.[gateway]'
       agent-proof-mcp-gateway --host 127.0.0.1 --port 8000

   Public-interface binding is refused. Configure TLS, trusted proxy/Host,
   origin restrictions and network ACLs separately. The loopback service must
   not run in the same untrusted host namespace as an agent with arbitrary
   system administration rights.

## Codex client

Codex supports HTTPS remote MCP connections and tokens from a named environment
variable. Obtain a short-lived Entra API access token through an authorized
OAuth flow; rotate it when it expires.

    codex mcp add agentproof \
      --url https://guard.example.com/mcp \
      --bearer-token-env-var AGENTPROOF_MCP_TOKEN

Never configure this as an agent-local stdio MCP server. The MCP SDK does
not apply HTTP OAuth authorization to stdio/in-memory clients. This tool
additionally checks that an authenticated HTTP identity context exists and
re-verifies the token before any DB call.

There is one exposed tool:

    apply_preapproved_postgres_change(action_id="operator-issued-uuid")

The result state is submitted_unverified, never verified: an independent
SELECT-only witness must run agent-guarded observe and agent-guarded check
against the operator's trusted contract after the transaction.

## Offline tests

    python -m unittest discover -s tests -p 'test_mcp_gateway.py' -v

For HTTP transport tests:

    pip install -e '.[gateway]' 'httpx>=0.27,<1'
    python -m unittest discover -s tests -p 'test_mcp_gateway*.py' -v

The synthetic CI workflow contains no real tokens, production data or
PostgreSQL credentials. Existing gate integration tests separately exercise
actual DB transaction constraints.

## Important limitations

- No live network-isolated Codex-to-PostgreSQL deployment has been validated.
  Container/VM egress policies and absence of bypass paths need explicit tests.
- No durable pre-execution witness acknowledgment or completeness guarantee.
  Recording an action afterward cannot show that no actions were omitted.
- HTTP rate limiting, recovery, key rotation and multi-tenant identity policies
  are not implemented. Replay of the same action UUID is guarded at DB level,
  and ambiguous commit failures require separate reconciliation.
- A database owner can bypass the existing transaction gate. Compromised
  gateway administrators can change the server code or credentials.
- Ethereum anchoring is a separate, experimental concern in
  [PR #14](https://github.com/mhatipog/agent-proof-pack/pull/14).

References: [Codex MCP CLI source](https://github.com/openai/codex/blob/main/codex-rs/cli/src/mcp_cmd.rs),
[MCP SDK HTTP authorization](https://py.sdk.modelcontextprotocol.io/run/authorization/).
