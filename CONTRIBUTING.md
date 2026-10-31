# Contributing

Agent Proof Pack is a small deterministic reference implementation. Contributions should help establish an observable correctness condition, not create another LLM judge.

- Work in a branch and submit a focused non-draft PR.
- Include a synthetic, redacted regression fixture and its expected verdict for any new rule.
- Run `python -m unittest discover -s tests -v` and `python -m agentproof suite`.
- Describe the trust boundary: which state or permission source is independent from the agent?
- Avoid real customer data, credentials, financial information, API responses or internal traces.
- Don't claim a universal security or correctness proof; identify false positives, bypasses and limitations.
