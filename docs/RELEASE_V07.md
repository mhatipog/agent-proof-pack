# Agent Proof Pack v0.7.0 — Postgres gate hardening and a usable agent boundary

A focused security and usability release. The generic PostgreSQL transaction gate previously checked proposed values in a BEFORE trigger but could miss a later BEFORE trigger rewriting the same row. This release fixes that verified gap and makes the protected operation accessible through a narrow CLI tool.

## Security correction

- Save the full target row under lock before executing the approved change.
- Re-read the actual stored row after all immediate PostgreSQL BEFORE and AFTER triggers.
- Require **exactly one approved text-field transition**; any other row mutation aborts the transaction and rolls back the one-use grant and committed record.
- Use NULL-safe SQL comparisons (`IS DISTINCT FROM`).
- Add real PostgreSQL regression cases for a later BEFORE trigger that changes an unrelated field or replaces the approved field.

## An actual integration boundary

`agent-guarded apply --action-id UUID` accepts *only* a previously issued grant identifier. Its credentials come from one protected `AGENTPROOF_ACTOR_DSN` variable, not an agent-selectable DSN. The separate `agent-guarded observe` command uses reader-only credentials and signs a current-row/commit-record outcome statement. `agent-guarded check` requires the independently trusted contract, signed receipt and a fresh observation.

The agent cannot mint an approval, supply SQL, or access the witness HMAC key through this command. It remains the deployer's obligation to isolate these processes and credentials.

## Actual data, tests and cost

- Executed on the upstream Chinook PostgreSQL commerce database, not invented production records. This is a **reproduction of a failure class**, not a customer incident.
- Includes invalid action, cross-action receipt substitution, expiry, concurrent grant, rollback and tampering tests.
- First indicative CI median timings (25 operations per path): **7.50 ms native** vs **12.674 ms guarded** (1.69×). The comparison includes connection and commit, excludes witness signing, and is **not a production performance promise**.

Full [security and adoption risk register](https://github.com/mhatipog/agent-proof-pack/blob/v0.7.0/docs/SECURITY_AND_ADOPTION_REVIEW.md) and [operator/agent integration guide](https://github.com/mhatipog/agent-proof-pack/blob/v0.7.0/docs/GENERIC_TRANSACTION_GATE.md).

## Explicit limits

This is still a *reference implementation*. It protects only enrolled ordinary PostgreSQL tables and narrow approved TEXT/VARCHAR updates. It does not handle arbitrary SQL, external side effects, unmonitored tables, database administrators, deferred cross-system work or historical row state after further writes. There is **no confirmed real customer pilot or independent agent adoption**. Do not install its sample SQL on production systems without separate security review.

The GitHub release includes an installable Python wheel; PostgreSQL support requires the optional `psycopg` extra. Nothing is automatically published to PyPI.
