# OpenAI Agents SDK: approval and audit regressions

This is an optional, standalone test lab for two publicly reported problems in the OpenAI Agents Python SDK. It uses the SDK's deterministic ScriptedModel and in-memory side effects. No API key, network call or real-world action is needed.

- [#5413: cross-run approval transfer](https://github.com/openai/openai-agents-python/issues/5413). The same Agent instance and a reused tool-call identity can cause an old approval item to authorize a new run.
- [#5470: lost guardrail evidence](https://github.com/openai/openai-agents-python/issues/5470). Input/output guardrails may execute after resume while their results disappear from the returned run's audit record.

## Run independently

From the Agent Proof Pack repository root, in a disposable Python 3.10+ environment:

~~~sh
python -m pip install 'openai-agents==0.24.0'
python -m unittest discover -s labs/openai_agents_sdk_integrity -p 'test_*.py' -v
~~~

The two named regression tests are designed to **fail on affected SDK versions** and pass when the defects are fixed. The no-approval control is expected to pass. A failed import is not a reproduced vulnerability. Record the installed package version with the result.

This lab is intentionally outside the product's normal test discovery directory. It is not imported by agentproof, does not change package dependencies and does not affect the standard product test suite.

## Scope and limits

Both linked issues are already public. These tests establish specific SDK state-machine properties, not production exploitability or a vulnerability in an OpenAI-hosted service. Cross-run transfer needs the same Agent object, a reused call ID, matching arguments and an application that presents an old approval. The guardrail result bug does **not** mean the guardrails themselves were bypassed.

[Realtime interruption issue #5416](https://github.com/openai/openai-agents-python/issues/5416) is **not** covered: determining whether a real side effect committed after an interruption requires a separate backend ledger and realtime environment. A stopped response is not evidence of a cancelled external operation.

No claims of live SDK execution or passing end-to-end tests are made here. For newly discovered, undisclosed security consequences, use the [SDK private vulnerability reporting policy](https://github.com/openai/openai-agents-python/blob/main/SECURITY.md) instead of a public issue.
