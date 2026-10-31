# Agent Proof Pack

**The AI agent said it was done. What independently proves that?**

[![CI](https://github.com/mhatipog/agent-proof-pack/actions/workflows/ci.yml/badge.svg)](https://github.com/mhatipog/agent-proof-pack/actions/workflows/ci.yml)

A small, **dependency-free Python verification harness** for the actions AI agents take: preflight permission and business-rule checks, independent read-after-write verification, machine-readable receipts, and CI regression cases. No LLM judge. No model-specific SDK. MIT licensed.

> An `approve` verdict means the configured invariants pass on evidence **you supplied**. It is not a universal correctness proof. For anything consequential, collect authority and after-state from trusted systems *outside the agent* and enforce authorization at the actual write boundary.

## Now useful with real Terraform plans (v0.3)

**A production incident is not a unit-test problem. It's an execution-boundary problem.** Agent Proof Pack now accepts an actual saved Terraform binary plan, interprets its resource changes, and returns a fail-closed verdict *before* an agent gets to run apply.

Try the two included **sanitized, offline** plans with no cloud account or Terraform installation:

```bash
python -m agentproof terraform --plan-json examples/terraform/safe-plan.json --policy examples/terraform/policy.json
# approve (exit 0)
python -m agentproof terraform --plan-json examples/terraform/destructive-plan.json --policy examples/terraform/policy.json
# block (exit 4)
```

For **real plans**, use `terraform plan -out=tfplan`, then `python -m agentproof terraform --plan tfplan --policy your-policy.json`. A reusable read-only [GitHub Action](action.yml) is included. There is also an explicit, approval-hash-bound `--execute` wrapper, but it **does not claim post-apply verification**. The example policy is deliberately limited to the illustrative `terraform_data` resource type; supply your own trusted policy for anything else.

[**Step-by-step Terraform integration and security limits**](docs/TERRAFORM_GATE.md) · [Incident-grounded controls](docs/INCIDENT_EVIDENCE.md) · [Propose a sandbox pilot](https://github.com/mhatipog/agent-proof-pack/issues/new?template=pilot.yml)

## See the failure in 30 seconds

```bash
python -m agentproof suite
python -m examples.crm_demo
python -m unittest discover -s tests -v
```

The CRM example has three modes:

```text
success      -> verified                executed=True
unauthorized -> refused                 executed=False
no-op        -> postcondition_failed    executed=True
```

One mode truly changes a synthetic CRM record. Another tries an unauthorized tool and is stopped **before** executing. The third reports no exception but leaves the CRM unchanged: an independent read catches the false success.

[**Browse the 16 reproducible cases →**](docs/CASE_STUDY.md)

### Incident-grounded controls (v0.2)

**Five public incidents and security demonstrations, 16 additional simulated regression cases.** They address production data deletion, unreviewed infrastructure plans, over-scoped API tokens, private-to-public data leaks and outbound exfiltration. The tests reproduce *control scenarios*, not the actual incidents.

```bash
python -m agentproof suite --cases examples/incident_cases.json
```

New checks: `exact_grant` (principal/tool/resource/operation/environment **as a tuple**), `action_binding` (approved action SHA-256 plus unchanged target revision), `information_flow` (independently classified source → destination), and `https_origin` (exact HTTPS origin, not suffix matching). See the [source-linked incident study](docs/INCIDENT_EVIDENCE.md).

**Important:** These are deterministic checks, not an enforcement proxy or production security certification. The trusted executor must enforce the decision immediately at the write boundary. Independent permissions, classified data, protected resources, network restrictions and backend idempotency are still required.

## What can it check?

| Stage | Built-in invariant | Example |
| --- | --- | --- |
| Preflight | `decimal_total`, `max_amount` | Invoice lines + tax equal the exact payable amount |
| Preflight | `exists_in`, `required`, `equals` | Customer exists in the authoritative list |
| Preflight | `tool_permission`, `unchanged` | Tool/resource allowed; bank-account change escalates |
| Preflight | `unique_action` | Detect a replayed action ID (not an atomic lock) |
| Preflight | `no_destructive_sql` | Detect obvious DROP/TRUNCATE/DELETE as a **smoke check only** |
| Postflight | `state_matches`, `effects_subset` | Expected vs actual CRM record; no unauthorized side effects |
| Postflight | `required` | Provider receipt is present after claimed email delivery |

Missing evidence is a failure. Policies are JSON documents with a deliberately limited allowlist of rule kinds — **no eval, no arbitrary user-provided code**. The default is `block`; selected rules can `escalate`. A receipt records each check, verdict, verifier version, policy and evidence SHA-256 hashes. An optional verifier-held HMAC key authenticates the receipt contents.

## CLI with your own evidence

Use a separate trusted adapter to populate the JSON evidence. Example data and policy:

```json
{"id":"payment-check-v1","rules":[{"id":"amount-cap","kind":"max_amount","value":"proposed.amount","limit":"authority.max_amount"},{"id":"permissions","kind":"tool_permission","tool":"action.tool","resource":"action.resource","allowed_tools":"grants.tools","allowed_resources":"grants.resources"}]}
```

Save that as `policy.json`. Then save `evidence.json`:

```json
{"phase":"preflight","action":{"id":"payment-123","tool":"payment.prepare","resource":"acct:demo"},"proposed":{"amount":"8421.37"},"authority":{"max_amount":"9000.00"},"grants":{"tools":["payment.prepare"],"resources":["acct:demo"]}}
```

```bash
python -m agentproof verify --policy policy.json --evidence evidence.json --output receipt.json
# exit 0 = approve, 3 = escalate, 4 = block/unavailable
```

To authenticate the receipt, keep your HMAC key in the verifier runtime, **not** in the agent's environment or repository:

```bash
export APP_PROOF_HMAC="your-private-random-secret"
python -m agentproof verify --policy policy.json --evidence evidence.json --output receipt.json --signing-key-env APP_PROOF_HMAC
python -m agentproof check-signature --receipt receipt.json --signing-key-env APP_PROOF_HMAC
```

For programmatic execution gating, import `run_guarded` from [`agentproof.gate`](agentproof/gate.py) and supply your own independent preflight evidence, tool callback, and target-system readback callback.

## Practical limits

- **Authority, permissions and observed after-state must be independently collected.** The verifier cannot detect forged inputs from an untrusted agent.
- The SQL regex is not sufficient for production migrations; use a real dialect-aware parser and database roles.
- A checked action can still fail after execution; postflight mismatch means **investigate or compensate**, not that an automatic rollback occurred.
- The in-process replay check and preflight permissions are defense-in-depth, not a substitute for server-side atomic authorization and idempotency.
- Hash receipts are not signatures; use an HMAC key or external signing plus durable independent storage for actual audits.

[Threat model and integration cautions](docs/SECURITY.md)

## First pilot

**Give us one workflow your agent already performs. We'll add independent checks that make silent mistakes detectably harder.**

A useful first engagement: 10–50 sanitized golden test cases; explicit business invariants and grants; separate expected/actual target-state reading; human escalation for risky changes; and a CI pack that reruns after each agent upgrade. Avoid sending real customer data in public issues.

Interested in piloting? [See the field-pilot offer](docs/FIELD_PILOT.md) and [submit a privacy-safe pilot request](https://github.com/mhatipog/agent-proof-pack/issues/new?template=pilot.yml). Describe the *kind* of workflow, not sensitive examples.

**Status:** research / MVP, not a certified assurance product. This project is independent of any specific model or agent framework.