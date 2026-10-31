# PostgreSQL transaction effect gate

A **sandbox reference implementation**, not a production-ready security extension.

Proof of Effect v0.6 independently observes data before and after an agent action. This additional experiment stops specific unauthorized changes **inside the same PostgreSQL transaction**, before the database commits.

## What it prevents

An administrator issues a one-use grant:

- Exact PostgreSQL login role
- Exact customer primary key
- Required previous status
- Approved new status
- Expiration time
- Unique action ID (UUID)

The restricted actor can invoke exactly one `SECURITY DEFINER` function with that action ID. It has **no direct table UPDATE/DELETE/INSERT privileges**, cannot create grants, and cannot edit the guarded triggers.

The function locks the protected grant row and creates a private action context bound to PostgreSQL's **backend PID and current transaction ID**. The context lives in a table inaccessible to the actor; it is *not* a spoofable `SET LOCAL` session variable. During the approved update, a row trigger allows only the exact status transition for the exact record; all other customer mutations and **all invoice mutations** are refused. Any violation raises an exception and PostgreSQL rolls the entire transaction back, including the approved update and one-time grant consumption.

This is intentionally a **customer-status-only demonstration**. Blocking all invoice mutations would obviously be unsuitable for a functioning production invoice workflow. A production gate needs operator-defined, multi-table contracts, verified role ownership, transaction-scoped audit receipts, lifecycle management and external integration.

## Real reproduction

The [transaction-gate CI](../.github/workflows/transaction-effect-gate.yml) starts **PostgreSQL 16** in a temporary service and provisions three separate database users:

- `postgres` installer/approver with control of the protected schema, authorization rows and schema migrations.
- `effect_actor` with `EXECUTE` on the single approved function but no direct writes.
- `effect_reader` with `SELECT` on only the watched tables for independent Proof of Effect reconciliation.

The tests verify:

1. One authorized status change commits and an independent read-only witness verifies it.
2. Direct SQL writes from the actor are refused by grants.
3. Forging a session variable cannot bypass the gate, even when direct UPDATE permission is temporarily added in the test.
4. Missing, expired, stale, wrong-role and replayed grants fail closed.
5. A malicious **AFTER UPDATE trigger that changes an invoice** causes **both the customer and invoice writes to roll back**, leaving the grant reusable after the faulty trigger is removed.
6. A malicious trigger attempting a second customer update is rejected the same way.
7. TRUNCATE and direct invoice updates fail under the sandbox restrictions.

No customer databases, cloud credentials, or production systems are touched.

## Run it on your own disposable PostgreSQL service

The installation [SQL](../examples/postgres_tx_guard/install.sql) expects sandbox tables `public.customers(id, status, owner)` and `public.invoices(id, amount)`, which the tests create. It deliberately does **not** silently create or modify arbitrary existing business tables. It must be run by a trusted owner in a disposable sandbox, not an agent or unreviewed customer migration.

```sh
python -m pip install -e '.[postgresql]'

# Configure ONLY an isolated temporary PostgreSQL database:
export AGENTPROOF_GATE_TEST_ADMIN_DSN='postgresql://postgres:...@localhost:5432/postgres'
export AGENTPROOF_GATE_TEST_ACTOR_DSN='postgresql://effect_actor:...@localhost:5432/postgres'
export AGENTPROOF_GATE_TEST_READER_DSN='postgresql://effect_reader:...@localhost:5432/postgres'
python -m unittest discover -s tests -p integration_tx_gate.py -v
```

The tests create and reset tables, triggers, functions, and roles. **They will modify the target database. Never point them at a production instance.** The CI workflow shows how to provision all three roles safely in an ephemeral container.

## Open-source foundations and distinctions

| Existing foundation | What is reused |
| --- | --- |
| [PostgreSQL native triggers](https://www.postgresql.org/docs/current/sql-createtrigger.html) | Enforcing row and statement restrictions with transactional exceptions |
| [pgAudit](https://github.com/pgaudit/pgaudit) | Distinction between audit logging and actual transactional enforcement; we do not claim its log guarantees |
| [pgMemento](https://github.com/pgMemento/pgMemento) | Transaction-aware change tracking as a design reference; **no LGPL code copied** |
| [pg-safeupdate](https://github.com/eradman/pg-safeupdate) | Fail-closed blocking philosophy; this gate checks exact authorized *effects*, not just SQL syntax |
| [supa_audit](https://github.com/supabase/supa_audit) | Row-level audit trigger patterns; **no source copied** |
| [psycopg](https://github.com/psycopg/psycopg) | Established PostgreSQL driver used by real integration tests and read-only outcome observer |

This work is not a new policy engine, not a replacement for SQL privileges, and not a claim that triggers are an original invention. It is an executable combination of native database privilege isolation, **one-use role-bound grants**, transaction-scoped enforcement, and independent outcome evidence.

## Security boundaries, including known bypasses

- Any database owner, superuser, or process capable of altering the guarded tables, triggers, schema or security-definer function **can bypass** this demonstration. That is why database role ownership and migration controls matter. Tests exercise no-superuser actor.
- Only the two named tables are monitored. Unwatched tables, external HTTP calls, outbox consumers, messages, file writes, untrusted extensions and side-effecting triggers on unguarded tables are outside scope.
- The issuer of grants is a separately privileged operator. The public test uses local credentials strictly in an ephemeral PostgreSQL service. Do not let an agent mint or modify its own authorization grants.
- A permitted effect alone does not prove which human requested it. Real integration needs authenticated identity, durable review records and binding the approval to the business caller.
- Triggers affect throughput and application behavior. Run a benchmark and review existing triggers/FKs, legitimate invoice paths and backup/rollback procedures before any production adoption.
- The gate does not prevent a database admin from disabling triggers or revoking its own policies.
- For broadly reusable protection, arbitrary operator-defined multi-table contracts need a complete transaction event set. This constrained demonstration does **not** assert that property for other schemas.

For post-commit verification, see [Proof of Effect](PROOF_OF_EFFECT.md) and [PostgreSQL observer](POSTGRESQL.md).
