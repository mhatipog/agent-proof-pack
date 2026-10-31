# Terraform saved-plan safety gate

**Agent says "I can apply this." The gate answers which exact resources and operations are permitted.**

Agent Proof Pack reviews a Terraform **saved binary plan**, not an agent's description. It reads a saved plan through the official Terraform CLI and returns a deterministic `approve` / `block` verdict. A separately opted-in wrapper may execute only a hash-approved binary plan using a private copy.

> Experimental MVP for authorized environments, not certified Terraform policy enforcement. Successful Terraform apply is `apply_completed_unverified`, not independent proof that real-world state is correct.

## 30-second demo (no Terraform or cloud account required)

Clone the repository and run:

~~~bash
python -m agentproof terraform --plan-json examples/terraform/safe-plan.json --policy examples/terraform/policy.json
# "verdict": "approve"; CLI exit 0

python -m agentproof terraform --plan-json examples/terraform/destructive-plan.json --policy examples/terraform/policy.json
# "verdict": "block"; CLI exit 4
~~~

These are **synthetic fixtures**. JSON-only mode is not bound to an executable plan, and must not be used as execution authorization.

## Real saved-plan review — read-only

Install Python 3.10+ and Terraform. Start in a sandbox with suitable permissions:

~~~bash
terraform init
terraform plan -out=tfplan
python -m agentproof terraform --plan tfplan \
    --policy policy.json --output review.json
~~~

The saved plan is hashed and `terraform show -json tfplan` is parsed internally. **Raw plan JSON is never included in the receipt**: Terraform warns that JSON output can contain sensitive plaintext values. Read-only review suppresses Terraform stderr and fails closed on errors.

Start with [the demonstration policy](../examples/terraform/policy.json) and change the illustrative `terraform_data` type to **exact** types relevant to your workflow.

| Policy key | Enforcement |
| --- | --- |
| `allowed_resource_types` | Exact permitted Terraform types, no wildcards |
| `allowed_actions` | Explicit action names, e.g. create / update / read / no-op |
| `max_changed_resources` | Upper bound on modified resource instances |
| `protected_addresses` | Addresses which cannot change |
| `allow_destructive_addresses` | Exact addresses allowed to delete/replace; also requires delete in permitted actions |
| `allowed_output_names` | Permitted root output changes |
| `allow_resource_drift` | Whether non-no-op drift is allowed; default recommended false |

Both Terraform replacement sequences, `["delete","create"]` and `["create","delete"]`, are destructive. Unknown actions, incomplete, errored or unapplyable plans, deferred changes, action invocations, pending checks, unapproved output changes and unsupported plan versions fail closed. The `complete` property is required; older Terraform releases without it will be refused.

## Optional approval-bound apply (real infrastructure write)

1. A human or a protected approval workflow records the **exact saved binary plan SHA-256**; this approval is independent from the agent.
2. A protected runner holding the actual infrastructure credentials invokes the gate using a policy and digest that the agent cannot modify. It verifies the hash, copies the plan to a private mode-0600 snapshot, inspects the snapshot via Terraform, rechecks its hash, then applies that same snapshot.

~~~bash
sha256sum tfplan   # for an independent approver, not self-approval by the agent

# CAUTION: this command actually changes infrastructure:
python -m agentproof terraform --plan tfplan \
    --policy policy.json --approved-sha256 <approved-64-character-hash> \
    --execute
~~~

If a check fails, **apply is never called**. This is not transactional: partial operations can still occur if Terraform fails mid-apply. Terraform state locking, provider-side authorization, backup retention and Terraform's own stale-plan rejection remain essential. An agent with direct Terraform credentials can bypass the wrapper entirely; isolate the privileged executor.

Do not share binary plans, raw `terraform show -json` output, or sensitive logs. Never run the apply example against production just to try it.

## Reusable GitHub Action (review only)

The repository ships a [composite Action](../action.yml). Install Terraform and Python on the caller runner, and pin this Action to a reviewed immutable commit:

~~~yaml
- name: Make saved plan (no apply)
  run: terraform plan -out=tfplan
- name: Review exactly that saved plan
  uses: mhatipog/agent-proof-pack@<pin-reviewed-commit-sha>
  with:
    plan: tfplan
    policy: infrastructure/approved-policy.json
~~~

The Action does **not** call apply. In CI the allowed policy and Action version must come from trusted, protected code; never run untrusted pull-request code with write-capable credentials.

## Scope and limitations

This check does not prove that provider updates cannot cause hidden side effects, that a successful apply modified real-world resources as intended, or that an independently approved hash was genuinely approved. It cannot protect infrastructure when the agent can bypass the gateway, alter the trusted policy, or access the cloud credentials. Post-apply verification requires read-only, authoritative system queries and an independent evidence store — work for the next sandbox field pilot.

**Authoritative references:** [Terraform JSON plan format](https://developer.hashicorp.com/terraform/internals/json-format) · [Saved plan apply](https://developer.hashicorp.com/terraform/cli/commands/apply) · [Sensitive JSON warning](https://developer.hashicorp.com/terraform/cli/commands/show) · [Saved plan confidentiality](https://developer.hashicorp.com/terraform/tutorials/cli/plan).
