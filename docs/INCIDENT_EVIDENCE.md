# Incident-grounded controls: five public cases, sixteen safe simulations

> Evidence classification matters. This is an **engineering interpretation of published reports**, not a replay of historical traces, a claim to have exploited affected providers, or an audit certification. Every runnable case is synthetic and has no customer data or live API calls. The original reports establish incidents or researcher demonstrations; our tests establish only the behavior of this specific verification code when supplied the displayed evidence.

## Reproduce

Run the 16 existing general examples and the 16 new incident-derived cases independently:

```sh
python -m agentproof suite
python -m agentproof suite --cases examples/incident_cases.json
python -m unittest discover -s tests -v
```

## Public evidence → deterministic safety boundary

| Publicly documented case | Evidence type | Required independent control | Example regression |
| --- | --- | --- | --- |
| Replit agent deletes production data during a code freeze (July 2025) | Public incident reporting | Environment-specific operation grant; "don't delete" in natural-language prompts is not authorization enforcement | `replit-prod-delete`, `replit-staging-read` |
| DataTalks.Club production Terraform destruction (February 2026) | [First-person technical postmortem](https://aishippinglabs.com/blog/how-i-dropped-our-production-database-and-now-pay-10-more-for-aws) | Bind permission to exact plan digest **and** actual state revision; reject changes after approval; require protected resources and independent backups | `datatalks-plan-swapped`, `datatalks-stale-state`, `datatalks-approved-plan` |
| PocketOS production volume deletion through Railway (April 2026) | [Contemporaneous incident reporting](https://www.theguardian.com/technology/2026/apr/29/claude-ai-deletes-firm-database) | Authorize precise principal + operation + environment + resource tuple; a token being technically powerful does not imply the agent has business authorization | `pocketos-production-delete`, `pocketos-operation-variant` |
| GitHub MCP private-repository exposure from an untrusted public issue (May 2025) | [Published security researcher PoC](https://invariantlabs.ai/blog/mcp-github-vulnerability) | Block confidential-to-public flows at the publish boundary using independently assigned provenance labels; ensure private repo data cannot be copied into public PR | `github-mcp-private-to-public`, `github-mcp-missing-label` |
| ShadowLeak Gmail-to-web exfiltration (September 2025) | [Published security researcher PoC](https://www.radware.com/security/threat-advisories-and-attack-reports/shadowleak/) | Require explicit HTTPS origins; enforce network-level egress policy and inspect **actual** final URL and redirect chain | `shadowleak-exfiltration`, `shadowleak-host-suffix-bait`, `shadowleak-userinfo-bait` |

Additional coverage: benign operations still work under the same controls. A check that blocks everything is not a useful business product.

## New rule kinds (v0.2)

**`exact_grant`:** Requires one authority record that matches all five claims *together*—principal, tool, resource, operation and environment. The legacy `tool_permission` uses independent lists and must not be used alone for high-risk access control; it can allow unintended tool/resource combinations.

**`action_binding`:** Exact SHA-256 of a structured executable action/plan must match an independently approved digest, while the target's current revision matches the approved revision. Re-check immediately before the effect. A logical check in Python is not an atomic compare-and-set in the target system.

**`information_flow`:** Checks a source/destination sensitivity pair against independently approved flows, e.g. `private → private` permitted; `private → public` forbidden. Labels cannot be taken from the agent's own assertions; labels alone do not stop content laundering or implicit leaks.

**`https_origin`:** Exact HTTPS origin allowlist; blocks common host-suffix and userinfo tricks, HTTP and unapproved ports. This is an *application-level preflight check*, not a network firewall; the executor must enforce final destination and redirects, and untrusted domains can still receive sensitive data if the allowlist is too broad.

Every rule fails closed on missing evidence. The verifier **cannot determine by itself** whether a supplied approval, classification, or plan digest came from a trusted authority.

## Integration blueprint: the six trust boundaries

1. **Agent proposes** a fully specified action: stable ID, actor, operation, destination, parameters and target environment.
2. **Trusted gateway reads** principal identity, exact resource grants and current target revision, outside the agent's prompt and tool outputs.
3. **Independent approver signs/records** the canonical action or Terraform plan digest. The model is never allowed to issue its own approvals.
4. **Trusted executor enforces** the exact approval and source-of-truth revision *at the write boundary*; production RBAC/ABAC, protected-resource settings and backup retention remain mandatory.
5. **Backend idempotency** handles ambiguous failures and retries. The existing in-memory `unique_action` rule is not atomic; never rely on it alone to stop duplicate payments.
6. **Independent readback** verifies the committed state and records a limited evidence receipt to an agent-inaccessible audit sink. A postflight failure means **uncertain/needs intervention**, not automatic rollback.

### What the new tests do **not** establish

- They do not replay the Replit, DataTalks, PocketOS, GitHub MCP, or ShadowLeak original agent traces.
- They do not prove the controls would have fully stopped each historical incident; actual security depends on the deployment boundary and credentials.
- They do not provide a production Terraform parser, a network proxy, per-resource access tokens, independent audit persistence, or atomic replay protection.
- They do not make a model's own claims trustworthy. Independently obtained ground truth is a hard dependency.

## Why this direction rather than yet another LLM judge?

[Microsoft's Agentic Behavior Engineering guidance](https://learn.microsoft.com/en-us/azure/architecture/ai-ml/guide/agentic-behavior-engineering) separates contract, ground truth and evidence collection from agent implementations, and recommends synthetic fixtures **before** SME-reviewed real production datasets. [AWS's four security principles](https://aws.amazon.com/blogs/security/four-security-principles-for-agentic-ai-systems/) explicitly identify deterministic controls **outside** the model as the starting point for consequential agents. [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) describes the same attack categories.

The technical differentiator for a commercial pilot is not a claim of "verified AI". It is a narrow integration **enforcing an exact business invariant at the action boundary**, plus evidence that the target system reached the expected state. Price the service per protected workflow, not per LLM call.

### Pilot acceptance criteria

A prospective client should be able to answer **yes** to all five: Can it block an action that exceeds the grant? Does a previously approved action fail after its arguments or resource version change? Does the checker detect a successful-looking no-op? Does a confidential-to-public flow fail closed? Can operators inspect evidence without giving the agent permission to change it?

An honest first pilot can implement only one of these high-value controls, as long as it is enforced in the real action path and tested against concrete customer-owned examples.
