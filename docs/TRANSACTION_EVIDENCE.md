# Transaction-bound PostgreSQL effect evidence

**Experimental sandbox reference, not a general-purpose PostgreSQL audit or CDC platform.**

The original [Proof of Effect](PROOF_OF_EFFECT.md) compares independent before/after snapshots. That deliberately fails when unrelated legitimate writes occur between observations. This new **transaction-bound witness** verifies an individually approved customer status update by reading *protected, committed transaction records* instead of scanning all customer and invoice rows.

## Mechanism

This reuses the existing [transaction effect gate](TRANSACTION_GATE.md), not a new SQL permissions model. The sandbox installer creates three owner-controlled tables:

- `action_grants`: one-use, expiring approval tied to a **database login** and exact customer/status transition
- `row_effects`: a *AFTER UPDATE* trigger records the actual accepted row's old/new status and PostgreSQL transaction ID; one effect per authorization
- `committed_actions`: the guarded function records the authorized action, its SQL login, and the **same** transaction ID

All are written in the **same PostgreSQL transaction** as the business UPDATE. If the transaction aborts, the row, both evidence records and approval consumption roll back. The guarded function refuses to return success unless the AFTER-trigger event exists. An independent SELECT-only account observes the three records in a single read-only `REPEATABLE READ` snapshot. It rejects missing, unconsumed, mismatched role/key/status, or different-transaction evidence.

The same guard runs both BEFORE and AFTER the UPDATE, verifying the final row after other BEFORE triggers have run. A trigger that silently rewrites the approved status aborts the whole transaction instead of producing misleading proof. This relies on PostgreSQL's documented [final-row AFTER-trigger visibility](https://www.postgresql.org/docs/current/trigger-definition.html), [transactional trigger rollback](https://www.postgresql.org/docs/current/trigger-definition.html), and [repeatable-read snapshot behavior](https://www.postgresql.org/docs/current/transaction-iso.html).

The restricted agent cannot call the guard's owner functions except the authorized action, mint grants, or insert/alter the evidence tables. Direct customer and invoice writes are blocked by sandbox grants/triggers. The operator controls the expected contract and the verifier key separately.

**The specific benefit:** two legitimately approved actions on *different customers* may overlap. Each can be verified by its own action ID even though a before/after whole-table snapshot of one action would reject the other's change. A later permitted update of the *same* customer does not erase the earlier commit proof. Neither case needs full-table observation.

## Try on an isolated disposable PostgreSQL 16 server

Run `tests/integration_tx_gate.py` using the existing [transaction-gate CI](../.github/workflows/transaction-effect-gate.yml) and its three PostgreSQL test roles. **This test creates and resets tables and disables fixture triggers; never point it at a production database.**

The separately controlled operator creates an action grant (as in the test's `grant()` helper). Only then can the restricted actor call:

```sql
SELECT agentproof_guard.apply_customer_status('c4bf3931-375e-42b5-ac79-69b817c9fcab'::uuid);
-- The caller must COMMIT successfully. A returned "applied" alone is not evidence.
```

Create a contract from **the real action UUID issued by the operator**; the UUID above is illustrative and is not preinstalled:

```json
{
  "schema": "agent-proof-pack/transaction-effect-contract/v1",
  "id": "crm_status",
  "action_id": "c4bf3931-375e-42b5-ac79-69b817c9fcab",
  "executor_role": "effect_actor",
  "customer_id": "C-42",
  "from_status": "open",
  "to_status": "won"
}
```

In a separate trusted verifier process:

```sh
python -m pip install -e '.[postgresql]'
export AGENTPROOF_EFFECT_READER_DSN='postgresql://effect_reader:...@localhost:5432/sandbox'
export AGENTPROOF_EFFECT_SIGN_KEY='<random-secret-at-least-32-bytes>'
python -m agentproof.tx_effect \
  --dsn-env AGENTPROOF_EFFECT_READER_DSN \
  --key-env AGENTPROOF_EFFECT_SIGN_KEY \
  --contract tx-contract.json \
  --output tx-receipt.json
```

The reader needs only **SELECT** on `agentproof_guard.action_grants`, `row_effects`, and `committed_actions`, and USAGE on the protected schema, with no access to business tables or writes. The CLI exits 0 for a verified event and 4 for missing/refused/unavailable evidence. Its output is exclusive-create (never overwrites a previous receipt). It emits an HMAC-authenticated, value-redacted in-toto-shaped statement, not a Sigstore identity certificate.

## Predicate v1

The statement uses `https://in-toto.io/Statement/v1` with custom `predicateType`:

`https://github.com/mhatipog/agent-proof-pack/blob/main/docs/TRANSACTION_EVIDENCE.md#predicate-v1`

The predicate schema is `agent-proof-pack/transaction-effect-predicate/v1`, with a digest of the *operator-owned expected contract*, eight explicit checks and a bounded-scope declaration. `witness_hmac_sha256` authenticates the statement with a verifier-held key. `verify_transaction_receipt(receipt, key)` validates authentication, **not** the truth of an independent database read. The statement contains no plaintext customer IDs, role names or status values. Hashes of a low-entropy contract may still be guessable; keep private evidence private.

### Precisely what is established

A successful witness means: *the trusted sandbox's one-use gate committed the exact recorded customer status transition under the specified login, and the row trigger recorded that same transaction.* The invoice trigger denies any modification to the demo invoice table; it is not an audit of arbitrary unguarded tables.

It **does not** establish that the customer's current status is still the same, that other systems or unguarded tables were untouched, or that a person approved the action. It cannot prove durability against the schema owner/superuser, which can change triggers or alter records. A malicious database owner is outside this trust boundary. Actor-owned or agent-fabricated receipts must not count as independent evidence.

### Operational limits and next steps

- This is purposely bound to `public.customers(id,status,owner)` and `public.invoices(id,amount)`. It does **not** retrofit arbitrary existing tables or provide global transaction effects.
- PostgreSQL transaction IDs link records **within this protected database**, not to an external ledger. Evidence rows are mutable by a trusted owner; archived proof must be stored with separately controlled retention.
- The guard blocks *all* invoice writes in this particular sandbox. Production needs explicit multi-table authorizations and careful schema ownership and migration policies.
- Retention, credential rotation, partitioning, monitoring, storage pressure and high-throughput benchmarks have not been solved.
- The separate [snapshot witness](PROOF_OF_EFFECT.md) remains useful for broader read-after-write observations. Transaction-bound evidence is narrower but more robust against concurrent legitimate changes in this guarded use case.

Tests run *real PostgreSQL 16*: two concurrent approvals, previous-action proof after a later update, uncommitted visibility, aborted caller transactions, missing/forged evidence, and preservation of all existing atomic rollback checks.
