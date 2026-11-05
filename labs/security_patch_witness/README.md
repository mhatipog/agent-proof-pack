# Patch witness — causal differential lab (v2)

**A zero-dependency, zero-API-cost experiment** for validating a proposed fix to a *known, synthetic* Python authorization bug.

This is not a scanner, a code-writing agent, a security sandbox, a proof of exploitability, or a certification of production patches. It makes bounded evidence claims rather than trusting either an agent's summary or a successful end result.

## How verification works

1. **Static gate (zero executions):** SHA-256 identities are calculated for both sources; Python AST fingerprints check that the named target function actually changed. Cosmetic edits and unchanged targets fail closed.
2. **Differential tests (two executions per case):** A trusted, human-defined contract supplies explicit vulnerable and expected patched behavior. Negative security cases run before preservation cases. Every case gets a fresh namespace; target-function call tracing checks reachability.
3. **Counterfactual dependency test (one more execution per case):** Replace only the named patched top-level function with its original source, leaving other patched code unchanged. If the original behavior does not return, the changed target alone does not explain the fix and the result is inconclusive.
4. **Bounded machine-readable evidence:** Source and target fingerprints, probe observations, counterfactual digest, skipped probes, reason codes and execution counts. Budget exhaustion is inconclusive, never success.

The synthetic path-prefix example catches a false authorization of /publicity as if it were /public and preserves legitimate public-file and admin access.

## Run locally

From this directory, execute: python -m unittest discover -s tests -v

Python 3.10+; standard library only; no external services, paid API calls, cloud CI, downloads, secrets or database.

The programmatic interface is verify(before_path, after_path, entrypoint, target_function, cases, max_executions=100, fail_fast=True). Each Case has name, positional args, expected before boolean, and expected after boolean. An output status of differential_and_counterfactual_probes_passed refers ONLY to the declared trusted-fixture probes.

**Never run this against files from an untrusted agent or an external PR:** fixture loading uses Python exec in the current process.

## Why causal checks matter

A trivial implementation can return the desired final answer for unrelated reasons: denying everybody, routing around the vulnerable function, or filtering in a caller while the vulnerable function remains unchanged. This lab exercises each of these. Even when the named target is both called and superficially edited, the real outcome may be caused elsewhere. Counterfactual target reversion detects this specific false-attribution case.

A successful revert test is **stronger evidence of dependency, not proof of causal completeness**. The patch could still have bypasses, hidden state, unrelated side effects or missing variants.

## Free, extensible architecture

Contract → cheap triage → observation adapter → independent evaluation → evidence.

The existing observation adapter understands trusted local Python functions and boolean results only. Other languages and services require isolated external executors; do not turn this in-process evaluator into a generic patch runner.

- Prefer local runtimes and standard-library parsers.
- Record JSON evidence and SHA-256 identities. Git is a free content ledger, not trusted runtime attestation.
- Protect specifications, observer and verifier-held secrets from the agent evaluated.
- Future caching must key on code, contract, runner and environment identities, with invalidation on change.
- Execute untrusted patches only inside properly isolated disposable environments with network/secrets/filesystem controls.
- Avoid continuous cloud polling, expensive model loops and unnecessary GitHub Actions.

## Threat boundaries

This runner is **not isolated**: importing a fixture can access the host filesystem, start subprocesses or use the network. Per-case namespaces reduce accidental state contamination but are not a security boundary. Python profiling is not tamper-proof against hostile code. There are **no timeouts or memory limits**; max_executions counts probes but cannot stop a hanging probe.

Counterfactual construction supports one undecorated top-level Python function. Nested functions, decorators, native code and broader behavior need other adapters. JSON is not signed; SHA-256 binds source bytes but does not make the source or runner trusted.

## Reference

OpenAI, [A thousand fewer paths to root](https://openai.com/index/a-thousand-fewer-paths-to-root/) (4 November 2026), reports that 20/200 apparently successful exploits in an early campaign followed a *different vulnerability* than assigned. Our small lab addresses that methodological failure mode without reproducing the Linux research, importing unpublished exploits or paying for model inference.
