# Configurable PostgreSQL effect gate — one approved text update

**Status: sandbox reference implementation, not an extension you should install into production without independent security review.** This is the next step beyond the fixed customer-status demonstration: the same SQL functions can protect **different ordinary PostgreSQL tables** without changing application-specific trigger code.

The concrete demonstration is not an invented schema. The [Chinook incident-class workflow](../.github/workflows/chinook-incident.yml) imports the upstream [Chinook PostgreSQL 1.4.5](https://github.com/lerocha/chinook-database) digital-store database and executes the gate against its populated `public.customer` and `public.invoice_line` tables.

## Two distinct outcomes

An operator issues **one authorization**: login `incident_prod_actor` can change `customer.email` for `customer_id=1` from its old value to a particular new value, before expiration. It is stored in a protected grant table. The agent gets **EXECUTE** on one function, no permission to issue grants, disable triggers or alter the schema.

1. `SELECT agentproof_generic.apply_text_change(:grant_uuid)` obtains a locked one-use grant; validates login, target table, single-column primary key, TEXT/VARCHAR target, original value, and expiry.
2. A protected trigger permits exactly that update inside the same backend/transaction. Another row/column mutation or a write to any other **enrolled** table raises an error.
3. The whole transaction rolls back if an unauthorized customer or invoice-line write is attempted by an AFTER UPDATE trigger.
4. A committed-action record becomes visible only if the transaction commits. The independent [Proof of Effect](PROOF_OF_EFFECT.md) witness then reads the real customer and invoice-line state with separate SELECT-only credentials.

**Existing PostgreSQL permissions remain the primary boundary.** The trigger enforces a finer single-action scope if an operator has installed it correctly; the after-state witness detects collateral changes in the watched set. The same templates accept different table names and varchar/text update fields, but **do not** implement arbitrary SQL verification, cross-service effects or multi-row transactions.

## Install on a throwaway database only

The [SQL installer](../examples/postgres_generic_gate/install.sql) creates a protected schema with a transaction-bound context, one-use grants, committed outcome rows and two trigger functions. It does not touch application tables until the **trusted owner** explicitly calls `protect_table()` for each one.

SQL below is illustrative. The integration tests create a disposable database and configure the roles; do not execute this on your operational database.

```sql
-- Only a trusted owner/superuser installs and enrolls tables.
\i examples/postgres_generic_gate/install.sql
SELECT agentproof_generic.protect_table('public.customer'::regclass);
SELECT agentproof_generic.protect_table('public.invoice_line'::regclass);

-- A separately authenticated operator controls this request.
INSERT INTO agentproof_generic.grants(
   action_id, target_oid, key_column, key_value, update_column,
   old_value, new_value, executor_role, expires_at
) VALUES (
   '11111111-1111-4111-8111-111111111111',
   'public.customer'::regclass::oid,
   'customer_id', '1', 'email',
   'old-value-from-trusted-read@example.invalid',
   'approved@local.invalid',
   'incident_prod_actor',
   pg_catalog.clock_timestamp() + interval '3 minutes'
);

-- The agent only receives EXECUTE on the scoped entry point,
-- never INSERT on the grants table or ownership of the protected tables.
GRANT USAGE ON SCHEMA agentproof_generic TO incident_prod_actor;
GRANT EXECUTE ON FUNCTION agentproof_generic.apply_text_change(uuid)
  TO incident_prod_actor;
```

An actor's `SESSION_USER` is checked server-side, and the temporary approval context is stored in a protected table with the real PostgreSQL backend PID and transaction ID. It **cannot** be authorized by spoofing a `SET LOCAL` session parameter. The grant is locked for concurrent calls and its consumption rolls back if the operation fails.

The example only works if the operator's exact original value matches the database. Passing the same grant again fails. The functions use properly quoted SQL identifiers, bound values and a hard-coded supported type allowlist.

## Actual external-schema tests

The [test suite](../tests/integration_chinook_generic_gate.py) runs against real populated Chinook records and checks:

- Allowed one-row email update commits, one-time grant is consumed and separate read-only evidence verifies the result.
- Direct customer writes fail even when the actor retains native column UPDATE permission, because no protected action context is present.
- Wrong role, expired/missing grant, stale original value and grant replay are denied.
- A malicious AFTER UPDATE trigger attempting to zero an invoice line causes **atomic rollback** of both the permitted email update and the invoice mutation, leaving the grant usable.
- An additional customer change inside a nested trigger fails.
- An extra unauthorized statement after the approved function returns, in the same transaction, rolls back the whole operation.
- Concurrent calls sharing one grant yield exactly one successful commit.
- Protected invoice lines cannot be updated or truncated even by the owner unless the owner deliberately disables the guards.

The DB owner can alter triggers or grants and bypass the system, so **this is not protection against a compromised administrator**. The independent witness cannot see changes made and reverted entirely between its snapshots; protected DB rows are not an externally immutable audit ledger.

## Production limitations

**Do not deploy this installer against production.** It requires an operator to verify relation ownership, existing trigger behavior, constraints, legitimate other writers, migration procedure and credential separation. It blocks unrelated legitimate writes to enrolled tables until separate approved operation types are implemented.

Only **single-row TEXT/VARCHAR column UPDATEs** on ordinary tables with a single declared primary key are supported in the authorization function. It is not a SQL sandbox, a general DML firewall, an external-service authorization mechanism, or a scalable change-data-capture system.

The credible commercial next step is a controlled pilot with an existing application team and independently managed PostgreSQL roles, measuring which unauthorized operations it prevents, what it breaks, and its transaction overhead. Until then, this remains a reproducible sandbox implementation.
