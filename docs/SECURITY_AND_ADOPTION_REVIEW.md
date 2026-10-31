# Security and adoption review — 2026-10-31

**Disposition: reference implementation, not production-ready.**

This is an explicit engineering risk register, not a security certification. The tests below use real PostgreSQL 16 and the independently maintained Chinook sample dataset. No external agent/customer deployment has been observed.

| Priority | Finding | Disposition |
| --- | --- | --- |
| P0 | A later PostgreSQL BEFORE trigger could rewrite a tuple after the generic row guard accepted it | **Mitigated and regression-tested:** lock/read full initial row and compare full stored final row after all immediate triggers; reject unexpected values before grant consumption |
| P0 | Actor-side tool surface is too broad if agents can choose SQL or credentials | **Mitigated:** `agent-guarded apply` accepts only a canonical approved UUID; its DSN comes from a fixed protected environment name |
| P1 | Matching HMAC alone can authenticate stale or wrong-action receipts | **Mitigated:** receipt check requires an independent approved contract, checks the subject digest and rejects future/expired observations; authenticated failure remains non-success |
| P1 | SQL NULL comparisons are not fail-closed in a row guard | **Mitigated:** change policy comparisons to `IS DISTINCT FROM` |
| P1 | Unknown performance overhead discourages adoption | **Measured in disposable CI:** compare 25 normal committed updates vs 25 one-use gated updates, including client connection cost; no production throughput claim |
| P0 | No independent real-world agent/customer incident prevented | **Open:** tests exercise real SQL and a documented incident *class* on a real sample store, not an external production agent |
| P0 | Database owner/superuser can alter grants, functions, and triggers | **Open by design:** requires operational ownership, restricted migration roles, external evidence and isolation; cannot be made safe by an in-database trigger alone |
| P1 | Unenrolled tables, external APIs, deferred/out-of-transaction effects | **Open:** only selected tables/row transitions are covered. Full transaction/cross-service effect tracing is out of scope |
| P1 | Arbitrary DML, multi-row operations and all SQL types | **Open:** the transactional gate supports only one authorized text-field update on an enrolled ordinary table; this is not a general SQL firewall |
| P1 | Whole-table witness scalability/concurrent writers | **Open:** the observer intentionally caps full scans. The transaction receipt path is efficient but specific; broader CDC evidence needs design and validation |
| P2 | Repository claims vs real proof | **Fixed in docs:** separate verified prototype behavior from pilot evidence, commercial adoption and production suitability |

## Reproducible tests

The [Chinook CI](../.github/workflows/chinook-incident.yml) imports a SHA-pinned upstream dataset into temporary PostgreSQL 16. It covers restricted identities, destructive-operation refusal, frozen grants, race/replay, unauthorized invoice mutations, and the **two later BEFORE-trigger rewrite cases**. The [ordinary unit suite](../.github/workflows/ci.yml) covers malformed action IDs, contracts and signed outcome substitution. Run the [minimal API and operator guide](GENERIC_TRANSACTION_GATE.md) to inspect the actual boundaries.

The independently maintained Chinook schema is a realistic relational example, not a customer environment. The referenced Replit 2025 incident explains *why* environment confusion matters; its unavailable production data and exact agent commands were not reproduced.

## Decision needed before production use

1. Enroll an isolated **staging** environment already used by an external agent team, with written access approvals. Do not install the sample SQL on operational databases.
2. Keep the operator's grant/contract, the agent's EXECUTE-only credentials, and the observer's read-only credentials/HMAC key on separate hosts or trust domains.
3. Run a fixed pilot of at least 20 real agent-requested database changes and 20 deliberately unsafe requests. Record successful intended writes, prevented unsafe writes, false denials, latency, and anything outside monitored scope.
4. Require an independent PostgreSQL security review, including role ownership and trigger ordering, and a measured throughput/regression test before using the word **production**.

**Success threshold:** at least one independent external team can integrate without manual intervention from the author, with documented results and no unauthorized writes in the tested scope. Until then, this repository is a demonstrable prototype—not a breakthrough product.
