# Scope and trust model

**Not a general correctness proof.** Approve means *all configured checks passed over the supplied evidence*. It does not mean the action is semantically good, authorized by law, or provably safe. Human approval remains necessary for ambiguous and irreversible actions.

## Trusted components and boundaries

- Policies, permissions, authority snapshots and the verifier runtime must be administered independently from the agent. Do not let the agent edit the policy, call the gateway directly with forged evidence, or select which checks run.
- Inspect and record the destination via a **trusted read-only adapter** after execution, not the agent's own status response. Consider consistency and propagation delays. Verify affected record IDs and effects, not just HTTP 200.
- The `run_guarded` adapter gates the `execute` callback only after preflight approval. Postflight checks cannot roll back an already executed action: use transactional operations, idempotency keys, hold/review states and compensating actions where appropriate.
- Race conditions exist between preflight and execution. For financial or high-risk operations use atomic server-side constraints, transaction isolation, compare-and-swap, and a source-of-truth authorization check at the write boundary.
- This demonstration's SQL token check is a **smoke check, not a parser or SQL safety boundary**. SQL may have destructive behavior through comments, quoted identifiers, stored procedures, execution context and dialect-specific forms. Production SQL policies should parse an explicit dialect, inspect AST and execute only against bounded privileges.
- `unique_action` is a snapshot check, not an atomic distributed idempotency lock. Enforce uniqueness in the target system.
- Receipt SHA-256 values are **integrity digests, not cryptographic identity signatures**. For tamper detection, sign with an HMAC key controlled by the verifier; use an append-only external store for real audit records. HMAC protects a receipt after creation, **not the truth of the observations**.
- Receipts intentionally contain rule IDs, failure reasons and hashes, not raw input values; failure descriptions and metadata can still be sensitive in some contexts. Keep private receipts private. Do not put customer IDs, invoice data, tokens or bank numbers in public demo cases.
- The sample gate is synchronous and single-process. It is not an authenticated service, policy distribution layer, transaction manager or durable approval queue. Do not deploy it as a financial enforcement system without completing those controls.

## Fail-closed cases

A missing datum, unsupported rule, non-finite amount, empty rule list, revoked tool permission or unavailable observation must **not silently turn into approval**. An execution error is `indeterminate_execution` because some side effects may have happened before an exception. An unreadable after-state is `unverifiable_after_action`.

## Reporting problems

Please open a GitHub issue **without** including real customer data, tokens, credentials or private evidence. Prefer a synthetic reproduction.
