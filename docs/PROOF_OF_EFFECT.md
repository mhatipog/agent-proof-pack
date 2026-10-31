# Proof of Effect

**A tool returning success does not establish that the business operation was correct.**

This experimental SQLite witness inspects the actual system of record independently of the agent. It checks the intended value and detects unauthorized changes to other rows, columns and watched tables, including inserts/deletes. It does not execute the agent's SQL.

## Run three real database scenarios

```sh
python -m agentproof.effect_cli demo --mode correct
python -m agentproof.effect_cli demo --mode no-op
python -m agentproof.effect_cli demo --mode collateral
```

Only the first should return exit 0. The third updates the requested CRM record **and silently zeroes an unrelated invoice**. It must be rejected. Each demonstration creates an isolated disposable SQLite database, no mocks or cloud credentials.

## Integrate behind a trusted boundary

Start from [the example contract](../examples/proof_of_effect/contract.json). An operator, **not the agent**, defines watched tables, target record, expected value, allowable columns and whether a real mutation is required. The protected verifier reads the SQLite database with a read-only connection and signs a before-snapshot containing keyed HMAC fingerprints of rows and values. The agent must have no access to the HMAC key or protected evidence directory.

```sh
# Run in a verifier isolated from the agent:
export AGENTPROOF_WITNESS_KEY='<high-entropy-secret-of-32-bytes-or-more>'
python -m agentproof.effect_cli capture \
  --db /trusted/crm.db --contract contract.json \
  --key-env AGENTPROOF_WITNESS_KEY --output before.json

# Separately authorized writer performs its operation.

python -m agentproof.effect_cli reconcile \
  --db /trusted/crm.db --contract contract.json --before before.json \
  --key-env AGENTPROOF_WITNESS_KEY --output effect-receipt.json
python -m agentproof.effect_cli verify-witness \
  --receipt effect-receipt.json --key-env AGENTPROOF_WITNESS_KEY
```

The snapshot expires after 600 seconds. The verifier refuses tampered snapshots, changed contracts, missing target rows, wrong values, no-ops when a mutation was required, extra changes to the same row, any change to another watched row/table, schema differences, and unavailable reads. Output files are created exclusively rather than overwritten.

## Predicate v1 — reuse existing standards

The output includes an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) under `statement`, with custom `predicateType`:

`https://github.com/mhatipog/agent-proof-pack/blob/main/docs/PROOF_OF_EFFECT.md#predicate-v1`

Its predicate schema is `agent-proof-pack/effect-predicate/v1` with contract/before/after digests, exact check results, changed-row and changed-cell counts, watched table names and explicit limitations. Raw row values/identifiers are not emitted. The sibling `witness_hmac_sha256` authenticates the statement locally; **this is not itself a DSSE signature**.

The [trusted synthetic GitHub workflow](../.github/workflows/effect-attestation.yml) uses existing [actions/attest](https://github.com/actions/attest) to publish Sigstore-backed attestation of a demo receipt. The signature establishes the GitHub workflow identity and artifact integrity, **not that a customer's database was correct**.

| GitHub building block | Actual use / boundary |
| --- | --- |
| [in-toto/attestation](https://github.com/in-toto/attestation) | Statement v1 structure and subject digest — used |
| [actions/attest](https://github.com/actions/attest) | Sigstore-backed CI provenance — used |
| [open-policy-agent/opa](https://github.com/open-policy-agent/opa) | Production policy decisions — **not integrated**, do not reinvent Rego |
| [OpenTelemetry semantic conventions](https://github.com/open-telemetry/semantic-conventions) | Cross-framework tool spans — **not integrated**; traces aren't evidence of correct state |

## What it cannot prove

`verified` means only that this **operator-defined outcome contract** held for the **explicitly watched SQLite tables** during the observed interval. It does not prove that an agent caused the change. Another actor could modify the same database, and a change made and reversed between checkpoints can go unnoticed. Unwatched tables, external provider side effects, and agent bypasses remain outside scope.

Maximum scope: eight tables, 10,000 rows per table, 200,000 cells total, 1 MB/value. Every watched table needs a single declared primary key. For large or high-write workloads, replace whole-table observations with CDC or read-only provider projections. This version has no durable replay ledger, production IAM isolation or deletion-resistant evidence storage.

This is a reusable reference implementation and a concrete improvement in outcome verification — **not** an industry-first claim or a production security certification.
