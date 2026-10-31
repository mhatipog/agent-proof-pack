# Agent Proof Pack 0.6.0

Independent outcome witnesses for AI-agent database mutations.

This release makes the existing SQLite Proof of Effect witness work against real PostgreSQL, using the same operator-owned contract and evidence format. The first use case is deliberately narrow: an agent updates a customer record, and a separate read-only observer checks both the requested result and collateral changes in other watched tables.

## Included

- PostgreSQL 16 integration exercised in GitHub Actions with a **different, SELECT-only observer role**.
- Consistent read-only PostgreSQL snapshots (repeatable-read isolation), safely composed identifiers, explicit schema/PK checks, and fail-closed RLS detection.
- Shared SQLite/PostgreSQL contract v2 with signed, backend-bound before-snapshots; accepts existing SQLite v1 contracts.
- Detects unexpected table column, index and trigger changes in the configured watch set.
- Fixes a prior false-positive: when a mutation is required, another permitted column changing no longer counts as an actual transition of the **expected** value.
- Optional `psycopg` installation via `pip install -e '.[postgresql]'`; zero additional runtime dependencies for SQLite.
- 13 real PostgreSQL cases and existing SQLite/Terraform/in-toto tests.

## Run the failure locally

```sh
git clone https://github.com/mhatipog/agent-proof-pack
cd agent-proof-pack
python -m agentproof.effect_cli demo --mode correct
python -m agentproof.effect_cli demo --mode collateral
```

The second command returns a nonzero exit because the intended CRM update also changed an unrelated invoice. No database installation is required for this demo.

For a dedicated PostgreSQL read-only account, see [the integration guide](docs/POSTGRESQL.md). The [CI workflow](.github/workflows/postgres-effect.yml) shows the full real-database test.

## Evidence and limitations

The result includes an authenticated, value-redacted, in-toto-shaped statement. It proves agreement with an observed contract across the **watched tables**, not causal attribution, global absence of side effects, or that the agent was authorized to act.

A real deployment must protect the witness identity, signing key, contract and evidence from the agent; grant the witness only read privileges; and enforce write authorization at the actual database boundary. Whole-table scanning is intentionally bounded and is not designed for high-volume transactional production systems. No production certification is implied.

**Source:** [agent-proof-pack](https://github.com/mhatipog/agent-proof-pack) · **License:** MIT.
