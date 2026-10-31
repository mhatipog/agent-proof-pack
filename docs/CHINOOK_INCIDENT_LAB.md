# Real failure class, real PostgreSQL schema: the Chinook incident lab

A coding agent can have a perfectly plausible objective and still run destructive SQL against the wrong environment. That happened in July 2025: Replit acknowledged that its AI coding agent deleted live application data, and explained that development and production had shared a database. A subsequent separation feature was introduced to prevent development operations affecting production.

**Sources:** [Replit's own database separation announcement (July 21, 2025)](https://replit.com/blog/introducing-a-safer-way-to-vibe-code-with-replit-databases) · [Fast Company interview and account of the Replit deletion](https://www.fastcompany.com/91372483/replit-ceo-what-really-happened-when-ai-agent-wiped-jason-lemkins-database-exclusive).

This is **not the victim's database**, not the original agent, and not a claim to have obtained the agent's commands or log. Those details are not public. It is a controlled **reconstruction of the same failure class** against an established third-party application data model.

## What the runnable experiment actually uses

We import the **unchanged PostgreSQL SQL script from [Chinook Database v1.4.5](https://github.com/lerocha/chinook-database)** into an ephemeral PostgreSQL 16 service. The upstream script is pinned to Git commit `4a944a942426e1f3263fe539155fb7ef92b04b4a`; the fixture is downloaded at test time and retains Chinook's MIT copyright notice. No Chinook source code or data is redistributed in this repository.

Chinook is an open-source example of a digital-media commerce system with genuine relational constraints and populated customer, invoice and invoice-line records. Names and sales data in Chinook are **synthetic sample data from the upstream project**; they are not real customers or evidence of actual Replit damage.

The run uses three independent PostgreSQL identities:

| Role | Actual database permission |
| --- | --- |
| `incident_dev_actor` | Cannot even connect to the isolated production database |
| `incident_prod_actor` | May read customer records and update only the `customer.email` column; cannot delete, truncate, drop, or edit invoice lines |
| `incident_witness_reader` | May only SELECT `customer` and `invoice_line`; cannot change them |
| `postgres` bootstrap owner | Separately privileged installer/fixture reset; **can bypass enforcement** and therefore must not be the agent |

## Eleven real SQL checks

The [live CI workflow](../.github/workflows/chinook-incident.yml) executes these tests against the full upstream store database; see [the test code](../tests/integration_chinook_incident.py).

1. A correctly scoped customer email change succeeds, and the independent before/after witness produces an authenticated **verified** statement.
2. An agent reporting success without changing the database fails outcome verification.
3. A **code freeze** enforced by revoking UPDATE permission blocks a previously authorized write; data stays unchanged.
4. A staging-only agent is **denied a connection** to production.
5. A production-scoped agent attempts `DELETE FROM public.customer` and gets a PostgreSQL privilege error; rows remain.
6. `TRUNCATE TABLE public.customer CASCADE` is refused; rows remain.
7. `DROP TABLE public.customer CASCADE` is refused; the table remains.
8. An allowed customer update followed by an unauthorized invoice-line change in the **same transaction** fails and **both changes roll back**.
9. A privileged owner bypasses those grants and commits a customer update **plus invoice-line corruption**; the separate witness refuses to verify the claimed clean outcome.
10. A privileged owner changes an additional customer; the independent witness detects the unexpected effect.
11. The observer account itself cannot delete invoice lines.

Those are real PostgreSQL operations, not assertions against simulated agent tool outputs. Failures are meaningful only under the deliberately scoped privileges; an agent carrying the database owner's credentials is **not** stopped.

## Reproduce

The CI workflow is the recommended executable entry point. It provisions a **throwaway** PostgreSQL 16 service, downloads Chinook at the pinned commit, imports its schema and seed data, creates sandbox credentials, runs the full test suite, then GitHub destroys the container.

[Run and inspect the workflow](https://github.com/mhatipog/agent-proof-pack/actions/workflows/chinook-incident.yml).

For local execution, you need Docker or an isolated PostgreSQL instance, a PostgreSQL CLI, and psycopg3. Follow the exact import and role setup in the workflow; the SQL source **creates and drops a database called `chinook`**. Do not run it against any instance with valuable databases. The tests also reset sample values and must never target a real application.

```sh
python -m unittest discover -s tests -p "integration_chinook_incident.py" -v
```

Without the four test-only connection variables and the imported sample database, the test class skips rather than fabricating a pass.

## What it demonstrates — and what it doesn't

This experiment separates three mechanisms that are too often confused:

- **Prevention:** database isolation and narrowly scoped PostgreSQL privileges stop unauthorized SQL before damage occurs. This is *native PostgreSQL security*, not a novel invention.
- **Atomicity:** a failed statement in the actor's transaction causes the earlier customer update to roll back. Again, this is PostgreSQL's transactional guarantee.
- **Independent detection:** Agent Proof Pack's read-only before/after witness refuses to certify a completed operation when the requested email is unchanged or another watched record changes. That is what this project adds to standard database privileges.

The test does **not** demonstrate an AI model attempting to delete Chinook data autonomously, recover Replit's unpublished trace, prevent an administrator from bypassing privileges, or prove that no unwatched effects occurred.

The next integration milestone is to take the protected [transaction gate](TRANSACTION_GATE.md) from its purpose-built customer-status example to a configurable operation on this same upstream schema, with transaction-linked authorization and evidence. That is separate from this read-only-witness and least-privilege incident lab.
