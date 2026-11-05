# PostgreSQL-enforced independent witness admission

**Research prototype. Disposable PostgreSQL 16 only. Not a production migration.**

The early gateway implementation checked a signed witness receipt *outside* the
database. A compromised gateway holding the restricted database credential
could still call the old one-argument PostgreSQL execution function directly.

The newer database-enforced path prevents that specific bypass when installed
with the required PostgreSQL privileges. The database must verify a short-lived
HMAC admission minted by an independently administered witness before it calls
the existing one-use, row-bound transaction gate.

## Two different cryptographic proofs

The witness retains its Ed25519 key and durable SQLite WAL ledger. Every
accepted action first gets a signed record with an action digest, principal
digest, fresh nonce, timestamp, monotone sequence and previous-receipt digest.

The witness then issues a **separate database admission**: HMAC-SHA256
over the exact action UUID, full signed-receipt SHA-256 digest and issue time.

The HMAC key is shared only by the independent witness service and the trusted
database owner, NEVER by the agent or gateway. PostgreSQL verifies the HMAC
using pgcrypto inside the same transaction as the existing one-use grant.

The exact ASCII message (LF separators) is:

    AgentProof/witness-db/v1
    <lowercase canonical action UUID>
    <lowercase full witness receipt SHA-256>
    <Unix issued-at timestamp in integer seconds>

The proof expires 120 seconds after issue and allows 30 seconds of clock
skew in the future. This is a *symmetric* authorization token, not a public
signature. The Ed25519 witness record remains independently verifiable.

## Deployment order

1. Create a disposable PostgreSQL 16 instance with separately administered
   owner, operator, executor and outcome reader roles.
2. Install examples/postgres_generic_gate/install.sql and enroll the synthetic
   table in the existing guarded trigger system.
3. Install examples/postgres_witness_gate/install.sql as the database owner.
   This installs an isolated pgcrypto extension schema, a protected config
   table and a new witness-enforcing SECURITY DEFINER function.
4. Provision one 32-byte random HMAC key into the database owner-only config
   row, together with the exact expected executor LOGIN role. Deliver the
   same secret to the **independent witness** using separately protected
   infrastructure and secret distribution.
5. REVOKE EXECUTE on agentproof_generic.apply_text_change(uuid) from the
   executor role. The executor must have USAGE on agentproof_witnessed and
   EXECUTE only on agentproof_witnessed.apply(uuid,text,bigint,text).
6. Check ACLs, inherited privileges and function ownership. The executor
   must be unable to SELECT the MAC config, call the old function, create
   grants, change enrolled triggers, own protected tables or modify policy.
7. Configure AGENTPROOF_WITNESS_DB_MAC_KEY_HEX in the witness service only.
   The witness executable now refuses to start without this secret.
8. Configure the gateway normally. The production HTTP server's
   GatewayConfig.from_env() *always* requires a DB admission token and calls
   the witness-enforcing PostgreSQL function. Earlier two-argument executor
   mode is retained only for standalone synthetic in-process tests.

## Real-PostgreSQL verification

The public CI workflow starts its own ephemeral official PostgreSQL 16 service,
installs both gates and provisions a synthetic executor role. It confirms:

- Correct witness admission commits exactly one approved row transition.
- The executor cannot use the older direct SQL function or read MAC secrets.
- Missing, forged, cross-action, expired and prematurely dated tokens fail.
- Replays and parallel requests cannot reuse a successfully consumed grant.
- Failed underlying row-precondition checks roll back without consuming grant.
- Outcome correctness is checked by independent database readback.

Offline protocol tests use: python -m unittest discover -s tests
-p test_witness_db.py -v

The real DB tests use: python -m unittest discover -s tests
-p integration_witness_db.py -v

The GitHub workflow defines only disposable credentials and does not access
a real Entra tenant, customer service or long-lived database.

## Still unproven

This prevents bypass of the witness via the old direct SQL function only if
role separation is installed and the actor has no inherited alternate access.
A privileged database owner can modify the secret or bypass PostgreSQL guards.
A compromised witness can issue new admissions; the public blockchain does
not fix this trust boundary.

A network-isolated Codex deployment, full agent credential and egress
inventory, independently maintained history availability, proper secret
rotation and authenticated HTTPS proxies are still needed. The PostgreSQL
gate protects only explicitly enrolled row changes, not arbitrary external
operations or all possible AI behavior.

An HTTP error can occur after a DB transaction committed. Reconcile the
destination's actual state before issuing a new action grant. This research
is not a certification of production or general AI safety.
