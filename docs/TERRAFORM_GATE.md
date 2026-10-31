# Terraform saved-plan safety gate

**Agent says "I can apply this." The gate answers which exact resources and operations are permitted.**

Agent Proof Pack reviews a Terraform **saved binary plan**, not an agent's description. It reads a saved plan through the official Terraform CLI and returns a deterministic `approve` / `block` verdict. A separate execution wrapper requires a short-lived authenticated approval and independent postflight evidence for the supported sandbox adapter.

> Experimental MVP, not certified Terraform policy enforcement. `verified` is only issued when the expected filesystem bytes are observed independently; other kinds of resource require separate trusted adapters.

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

**Import and move protection:** Terraform can modify state by importing a remote object or moving a resource address even if the reported action is `no-op`. The gate explicitly refuses `change.importing`, generated import configuration and `previous_address` moves. This MVP offers no override for these state operations; review them independently.


## Signed, scope-bound execution and independent result proof (v0.4)

**Breaking safety change:** a standalone `--approved-sha256` cannot authorize `--execute` any more. It is valid only for **read-only** saved-plan comparison. Execution requires an HMAC-signed, expiring approval that covers the exact binary plan, policy, environment **and** independently defined expected outcome. The HMAC key must be accessible only to a trusted approver and protected executor, never to the agent.

Our sandbox is the [official local_file provider](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file), which creates a real local file. The postflight observer reads the file bytes via OS directory handles with no-follow protections, independently from Terraform's state file, and hashes them without printing their contents.

### Protected approver step

Create a private policy and expected-state manifest. Examples are provided at [policy.json](../examples/terraform/live-file/policy.json) and [expectations.json](../examples/terraform/live-file/expectations.json).

The following command must run in a **separate trusted approval environment**, never inside the agent's own job, and only after an actual human/protected review. Supply a randomly generated key of at least 32 bytes via a protected secret:

~~~bash
python -m agentproof issue-terraform-approval \
  --plan saved.tfplan --policy policy.json \
  --expectations expectations.json --environment sandbox \
  --approver security-reviewer --key-env APP_APPROVAL_KEY \
  --ttl-seconds 900 --output signed-approval.json
~~~

The manifest expires after 15 minutes by default (up to 60 minutes); it binds the exact plan hash, policy digest, expected-state digest and environment, and authenticates these fields with HMAC-SHA256. It is **not** an identity provider or a server-side one-time nonce store.

### Protected executor step

Run only in an authorized sandbox whose apply permissions are unavailable to the agent:

~~~bash
python -m agentproof terraform \
  --plan saved.tfplan --policy policy.json \
  --approval signed-approval.json --approval-key-env APP_APPROVAL_KEY \
  --environment sandbox --expectations expectations.json \
  --observe-root /trusted/sandbox/root --execute
~~~

After a completed execution, the returned JSON outcome is HMAC-signed with the executor-held key. Check stored receipts using:

~~~bash
python -m agentproof check-outcome --receipt proof.json --key-env APP_APPROVAL_KEY
# VALID (exit 0) or INVALID (exit 4)
~~~

**This authenticates the recorded outcome, not its ultimate truth.** Trust depends on the independent observer, protected executor, secret key and where the receipt is stored; an attacker with write access can still delete an unprotected receipt. Production deployments need durable, immutable evidence storage and stronger key isolation.

**Warning: `--execute` invokes real Terraform apply.** Never try this against production as an experiment. If signature, expiry, plan/policy binding, or preflight validation fails, apply is not called. After a successful apply, the observer reads the actual file and returns `verified` only on a matching digest. If Terraform returns success without writing the expected bytes, the verdict is `postcondition_failed`. Mismatch is an incident requiring investigation, **not an automatic rollback**.

### Verified zero-cloud sandbox

[The CI integration](../.github/workflows/terraform-integration.yml) uses an ephemeral temporary directory, Terraform 1.10.5, the official local provider, a **synthetic CI-only approval key**, and an independently read `proof.txt`. It demonstrates the technical flow, deliberately corrupts the output and verifies that a second observation fails. **This demonstration's key is intentionally not secret** and proves no operational separation of duties. Do not copy its key handling to production.

### Trust limits

- Approver identity is currently an authenticated *claim bound to the key*, not an OAuth identity or reviewed operator certificate. A compromised key can issue approvals.
- There is no durable replay/idempotency store or independent cloud permission enforcement. State locking and cloud IAM remain mandatory.
- Filesystem observation is independent of Terraform state, but only proves exact file contents at observation time. It does not verify hidden provider side effects or cloud resources.
- The observer refuses unsafe/duplicate paths, symlinks and unbounded files. Root directory, policy, expectations and permissions must themselves come from a trusted executor.
- Terraform apply can partially execute and fail. The system does not roll back effects or claim that a successful command is always correct.
- Do not upload raw plans, Terraform JSON, state files or provider logs to public CI artifacts.

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

This check does not prove that provider updates cannot cause hidden side effects, that a successful apply modified real-world resources as intended, or that an independently approved hash was genuinely approved. It cannot protect infrastructure when the agent can bypass the gateway, alter the trusted policy, or access the cloud credentials. File-based independent post-apply verification is implemented for the local sandbox. Production cloud resources still require authoritative read-only API adapters and an agent-inaccessible evidence store.

**Authoritative references:** [Terraform JSON plan format](https://developer.hashicorp.com/terraform/internals/json-format) · [Saved plan apply](https://developer.hashicorp.com/terraform/cli/commands/apply) · [Sensitive JSON warning](https://developer.hashicorp.com/terraform/cli/commands/show) · [Saved plan confidentiality](https://developer.hashicorp.com/terraform/tutorials/cli/plan).
