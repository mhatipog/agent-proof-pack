# Authenticated MCP execution with an independent witness

**Status: research prototype. Synthetic CI passed; no live Codex containment test or production deployment.**

The remote MCP service accepts just one operator-issued UUID and a Microsoft Entra app-only access token for a dedicated Agent Proof resource API. No agent-supplied SQL, grant, policy or destination is accepted. Before the transaction gate runs, the gateway must receive and authenticate an independently signed, durably committed witness reservation.

## Three trust zones

    [Untrusted Codex or other MCP agent]
       | HTTPS, dedicated Entra API access token
       v
    [Separately managed MCP gateway]
       | fixed tenant, audience, app, principal, AgentProof.Apply role
       | exact canonical UUID, no agent-supplied SQL
       |
       +---- HTTPS bearer ---> [Independent pre-execution witness]
       |                       private Ed25519 key, durable SQLite ledger
       |                       atomic one-use reservation per UUID
       |                       monotone sequence and signed previous hash
       |                       fresh request nonce bound to caller and action
       |
       | verified signature / fresh challenge / pinned public key
       v
    [PostgreSQL one-use transaction gate]
       | fixed EXECUTE-only actor credential; separate operator issues grants
       v
    [Independent read-only DB outcome verifier]

The gateway must not share its credential store or administrative namespace with the agent. The witness must not share its key, storage or host identity with the gateway. The agent must have no other path to PostgreSQL or to grant creation. Merely installing this MCP server in an unrestricted local Codex shell is not containment.

## Provisioning the witness

Use a dedicated host/VM and service account with a private directory not writable by the gateway or agent. Generate a 32-byte Ed25519 seed and corresponding public key outside the agent environment. Store them in a secret manager; never add them to GitHub or shell history.

Witness service environment:
- AGENTPROOF_WITNESS_SEED_HEX: 64-character lowercase hexadecimal seed; witness server ONLY
- AGENTPROOF_WITNESS_INBOUND_TOKEN: independent random service credential of at least 32 characters

On the witness host:

    python -m pip install -e '.[gateway]'
    agent-proof-witness --host 127.0.0.1 --port 8030 --db /var/lib/agentproof/witness.sqlite3 --max-reservations-per-hour 300

The database is created with private permissions; existing loose permissions or a group/world-writable parent are refused. The witness enforces an atomic, per-principal rolling-hour admission quota (default 300; configurable 1-10,000). Excess reservations receive HTTP 429 without advancing the signed sequence. This bounds per-principal write volume but does not confirm that requested IDs are valid operator grants. The witness binds loopback only. Expose its POST /v1/reservations endpoint through an independently configured HTTPS reverse proxy, preferably requiring gateway mTLS plus source allowlisting. It does not expose arbitrary SQL, grant-writing or receipt-deletion APIs.

## Provisioning the gateway

First install the existing one-use PostgreSQL transaction gate in a disposable database, enroll synthetic test tables and create distinct operator, restricted actor and read-only observer accounts. Then configure a separate Microsoft Entra API with an app-only role named AgentProof.Apply. Do not use a Fabric or Graph access token.

Protected gateway environment:
- AGENTPROOF_ENTRA_TENANT_ID: exact allowed tenant UUID
- AGENTPROOF_ENTRA_AUDIENCE: dedicated api:// guard API resource identifier
- AGENTPROOF_ENTRA_CLIENT_ID: exact calling app registration UUID
- AGENTPROOF_ENTRA_PRINCIPAL_OID: exact calling service principal object UUID
- AGENTPROOF_ACTOR_DSN: fixed restricted PostgreSQL EXECUTE-only connection
- AGENTPROOF_MCP_RESOURCE_URL: external HTTPS address ending in /mcp
- AGENTPROOF_WITNESS_URL: independent HTTPS address ending in /v1/reservations
- AGENTPROOF_WITNESS_OUTBOUND_TOKEN: secret accepted by witness (not visible to agent)
- AGENTPROOF_WITNESS_PUBLIC_KEY: out-of-band pinned 64-character Ed25519 public key

The required AgentProof.Apply role cannot be overridden by the agent or environment.

On the protected gateway host:

    python -m pip install -e '.[gateway]'
    agent-proof-mcp-gateway --host 127.0.0.1 --port 8000

Both servers deliberately bind loopback. Configure HTTPS/TLS, proxy Host/Origin handling, body-size limits, egress ACLs and request-rate limits separately. The MCP SDK enables DNS-rebinding protection by default; adjust the trusted proxy and Host allowlist rather than disabling protections. Reference: https://py.sdk.modelcontextprotocol.io/run/deploy/

## Codex client

Codex supports remote MCP and bearer credentials supplied via an environment variable. Use a short-lived dedicated Entra API token with its own issuance/refresh mechanism, not a Graph or Fabric token.

    codex mcp add agentproof \
      --url https://guard.example.invalid/mcp \
      --bearer-token-env-var AGENTPROOF_MCP_TOKEN

There is just one exposed action:

    apply_preapproved_postgres_change(action_id="operator-issued-uuid")

The gateway checks identity and receives a signed pre-execution ACK before attempting the fixed restricted PostgreSQL function. The database separately verifies the operator-created expiring one-use grant. A signed reservation is evidence of an accepted intent, NOT proof the DB transaction committed.

Success is reported only as submitted_unverified. Afterward, a separately privileged witness runs agent-guarded observe and agent-guarded check using the trusted operator contract. If execution times out, the DB may already have committed. The witness prevents automated re-execution under the same UUID; an operator must reconcile the DB state and issue a fresh grant if needed.

## Independent public-key inspection

Through a protected out-of-band administrative channel, export the witness's ordered signed receipt array as a JSON file. An independent auditor verifies without the witness signing key, PostgreSQL credentials or raw action UUIDs:

    agent-proof-witness-verify \
      --file witness-export.json \
      --public-key-hex <out-of-band-trusted-public-key> \
      --expected-head <previously-pinned-last-receipt-sha256>

Verification covers signatures, records, sequence continuity and previous-receipt hashes. It reports VERIFIED_PREFIX, never a guarantee of all agent activity. A trusted head obtained independently prevents *truncation relative to that head*, not withholding of later reservations. SHA-256-hashed UUIDs are pseudonymous, not encrypted.

Future public blockchain anchoring is separate research in PR #14: https://github.com/mhatipog/agent-proof-pack/pull/14

## Synthetic tests (no secrets or production access)

    python -m pip install -e '.[gateway]' 'httpx>=0.27,<1'
    python -m unittest discover -s tests -p 'test_mcp_gateway*.py' -v
    python -m unittest discover -s tests -p 'test_witness_reservations.py' -v

Tests exercise fake/real RSA JWT claims through MCP HTTP, wrong role/identity, failed witness blocking execution, independent signed reservations and fresh challenges, disk persistence and concurrent duplicate rejection, attempted replay after an ambiguous database result, tampered export and pinned head detection. The original dependency-free test suite still runs without optional gateway packages.

## Limits before a live adversarial Codex trial

- No actual isolated Codex deployment, real Entra app registration or protected service proxy has been tested. The agent must be denied alternative network and administrative paths, not just instructed to use MCP.
- The independent witness can be modified by a compromised witness administrator. Digital signatures prevent falsification by outsiders lacking the private key, not by its owner. Externally pinned heads and future blockchain anchoring improve retrospective detection.
- A compromised gateway administrator can bypass the witness and call PostgreSQL directly. To prove EVERY protected DB execution has a witness ACK, the DB gate itself would need to validate a witness-signed authorization, or an equally independent enforcement mechanism. This is not implemented.
- Authenticated agents can reserve arbitrary well-formed UUIDs with no actual grant. The witness now enforces an atomic per-principal hourly quota, but grant existence preflight, per-IP proxy rate limits, long-term storage retention, backups, key rotation and failover remain necessary.
- SQLite and PostgreSQL are not one distributed transaction. A recorded intent followed by an uncertain DB commit is not proof of rollback or success. Operator reconciliation remains mandatory.
- The witness records accepted post-authentication intents, NOT rejected token attempts, unrelated shell actions, all model reasoning, or omitted actions.
- A database owner can bypass the reference table guard. No production safety certification is claimed.

Reference source: https://github.com/openai/codex/blob/main/codex-rs/core/src/mcp_tool_call.rs
MCP auth: https://py.sdk.modelcontextprotocol.io/run/authorization/
