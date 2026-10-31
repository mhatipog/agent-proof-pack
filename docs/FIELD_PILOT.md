# Field pilot: one agent workflow, independently verified

We are seeking **up to three early pilot workflows** involving agents that do more than chat: invoice creation, CRM updates, database changes, automated email or operational tool calls.

## Offer

A limited-scope pilot provides:

1. One specific operation and its authoritative state/permission source.
2. Ten to fifty synthetic, sanitized or explicitly consented golden and failure cases.
3. A readable policy with independently controlled business and permission invariants.
4. A **preflight** approval/block/escalate gate before the tool call.
5. A **postflight** read-after-write check with a verified receipt or explicit discrepancy.
6. A CI pack rerun after model, prompt, code or agent changes.
7. A short handover showing exactly what the checker does *not* guarantee.

The first three selected pilots can be scoped **free of implementation fees** in exchange for feedback and permission to publish an **anonymized, mutually approved** case study. Hosting, third-party service and travel charges (if needed) must be agreed separately in advance. This is an invitation, not a promise of acceptance or blanket free consulting.

## Fit

Best fit: a company already running a narrow agentic workflow with a reliable system-of-record read API, a business owner willing to define correct outcomes, and a sandbox test environment.

Poor fit: nobody can say what "correct" means; the agent alone supplies its own evidence; no independent state can be observed; or the action is irreversible and cannot be held for approval.

**Security:** No customer datasets, secrets, employee or personal records should be uploaded to public GitHub issues. Discuss sensitivity, authorization, privacy and retention before any private exchange. We do not retain a customer's real failures in a shared corpus without explicit approval.

## Commercial model after validation

The initial offer is a service, not a subscription product: a fixed-price verification pack for one narrowly scoped operation, with potential paid regression maintenance. Pricing depends on complexity and access; no client is obligated to purchase future services.

[Propose a pilot without sensitive information](https://github.com/mhatipog/agent-proof-pack/issues/new?template=pilot.yml).
