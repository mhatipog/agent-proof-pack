# PostgreSQL outcome verification

An agent runs a database update and says it succeeded. The API returned 200. Was the right record changed? Were any other records touched?

`agent-effect` checks a narrowly defined result against the database itself. PostgreSQL is supported alongside SQLite, with the same contract and the same value-redacted in-toto-shaped evidence.

## Try the local demo first

```sh
git clone https://github.com/mhatipog/agent-proof-pack.git
cd agent-proof-pack
python -m agentproof.effect_cli demo --mode correct
python -m agentproof.effect_cli demo --mode collateral
```

The demo uses a disposable SQLite database. The first command exits 0; the second exits 4 because the correct customer update also corrupts an invoice.

## PostgreSQL setup

Install the optional, established psycopg3 adapter:

```sh
python -m pip install -e '.[postgresql]'
```

Use a purpose-specific **SELECT-only role** on the tables being observed. The privileged owner can provision it; the agent and witness must not share credentials.

```sql
CREATE ROLE effect_witness LOGIN PASSWORD '<random-secret>';
GRANT CONNECT ON DATABASE sandbox TO effect_witness;
GRANT USAGE ON SCHEMA public TO effect_witness;
GRANT SELECT ON public.customers, public.invoices TO effect_witness;
```

The example assumes ordinary tables in the `public` schema, single-column declared primary keys and an operator-maintained contract. It deliberately refuses row-level-security-enabled tables, views, partitioned tables, unsupported value types, huge tables and any other condition where observation completeness is uncertain.

The [contract example](../examples/proof_of_effect/contract.json) defines `customers` and `invoices` as watched tables, with one permitted status change on one customer. The verifier is read-only. It cannot execute SQL requested by the agent.

## Typed PostgreSQL columns

The PostgreSQL witness supports `uuid`, `boolean`, `numeric(p,s)` and `timestamp with time zone` in addition to null, text/varchar/char, integer, finite floating-point and bytea. Column types come from the database catalog and are bound into signed observations. Unsupported types (including `jsonb`, arrays, `date`, naive timestamps and unknown domains) fail closed **even if every value in that column is NULL**. Composite primary keys remain unsupported.

Use JSON strings for UUID identifiers and exact NUMERIC values, JSON booleans for BOOLEAN, and ISO 8601 strings with explicit UTC offsets for TIMESTAMPTZ:

```json
{
  "schema": "agent-proof-pack/effect-contract/v2",
  "id": "typed_crm",
  "watch_tables": ["customers", "invoices"],
  "target": {
    "table": "customers",
    "key_column": "id",
    "key": "36f66976-1e4c-4d34-a571-4d086e7c0c3f",
    "expected": {
      "status": "won",
      "balance": "8421.37",
      "active": true,
      "touched_at": "2026-10-31T12:30:00+01:00"
    },
    "allowed_columns": ["status", "balance", "active", "touched_at"],
    "require_change": true
  }
}
```

Never express NUMERIC as a JSON floating-point number: digits may be lost before verification. Numeric comparison is exact and independent of the local decimal context. TIMESTAMPTZ compares as the same UTC instant, independent of the display timezone. Existing SQLite behavior is unchanged; PostgreSQL boolean expectations must be JSON `true` or `false`.

This still verifies only the operator-defined watch set, not causal attribution or production safety.
## Capture, act, reconcile

In an **isolated trusted verifier**, configure two protected secrets: a read-only PostgreSQL DSN and a signing key. The agent must have no access to them, to the before-snapshot or to the expected-outcome contract.

```sh
export EFFECT_READONLY_DSN='postgresql://effect_witness:...@localhost:5432/sandbox'
export EFFECT_SIGN_KEY='<random-32-plus-byte-key>'

python -m agentproof.effect_cli capture --backend postgresql \
  --dsn-env EFFECT_READONLY_DSN --schema public \
  --contract examples/proof_of_effect/contract.json \
  --key-env EFFECT_SIGN_KEY --output before.json

# A separately authorized application now makes its database mutation.

python -m agentproof.effect_cli reconcile --backend postgresql \
  --dsn-env EFFECT_READONLY_DSN --schema public \
  --contract examples/proof_of_effect/contract.json \
  --before before.json --key-env EFFECT_SIGN_KEY \
  --output result.json

python -m agentproof.effect_cli verify-witness \
  --receipt result.json --key-env EFFECT_SIGN_KEY
```

The `capture` output is a short-lived signed baseline, without plaintext cell values or row IDs. The result is a versioned in-toto Statement v1 with a custom predicate and HMAC for trusted local verification. It is **not** a Sigstore certificate or a proof of the agent's identity.

## Actual PostgreSQL CI

The [PostgreSQL workflow](../.github/workflows/postgres-effect.yml) boots PostgreSQL 16 on a temporary GitHub runner, provisions a real restricted role, and tests the observer against genuine SQL mutations. It includes: correct update; no-op; wrong row; the requested update plus an unrelated invoice modification; insertion; index/schema change; RLS concealing data; tampered contracts; and an explicit test that the observer's database user cannot delete rows.

This is a real database integration, not mocked SQL or a claimed customer deployment. It does not use your database or credentials.

## Limits and failure modes

- Read-only `REPEATABLE READ` gives a consistent snapshot **within one observation**. It does not lock the entire business action from before to after, so concurrent legitimate writes may cause conservative failure and concurrent reverts can escape detection.
- The contract scopes which tables and columns are monitored. Changes outside them (external APIs, other tables, event queues) are not covered. Schema fingerprints include column declarations, index definitions and user triggers.
- Supported built-in values include text, integers, finite floats, binary, UUID, exact numeric, booleans and offset-aware timestamptz; unsupported types such as JSON, arrays, date, and naive timestamps still fail closed. The typed representation is verified against catalog column metadata.
- Whole-table scans are capped at 10,000 rows per table and 200,000 cells overall. Large/high-churn tables require CDC or logical-decoding integration rather than this reference implementation.
- The HMAC key is secret and used to create privacy-preserving fingerprints. An operator with the key and a small known-value domain can still guess values. No claim of differential privacy or anonymization is made.
- PostgreSQL metadata is queried from catalogs with safely composed SQL identifiers via psycopg3. No arbitrary agent-provided SQL is executed by the verifier.
- A successful verdict means the *observed data contract* matched over monitored tables; it does **not** prove the agent caused the change or that nothing else happened.

See [the general threat and evidence model](PROOF_OF_EFFECT.md) and the real [PostgreSQL integration tests](../tests/integration_postgres.py).
