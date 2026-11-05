# Patch witness (research lab)

A small **differential evidence gate** for a known synthetic security defect, inspired by OpenAI's 4 November 2026 research, *A thousand fewer paths to root*.

**Not** a vulnerability scanner, an exploit generator, a sandbox, a root-cause proof, a production patch certifier, or a commercial security product. It intentionally does not examine actual unpublished vulnerabilities.

## What it checks

- The vulnerable version demonstrably has the stated behavior on a specified negative-security probe.
- The proposed fix removes that behavior **and** preserves defined legitimate behavior.
- Both observations actually call the claimed target function, using a CPython frame-code identity trace rather than trusting a process exit code or agent narrative.
- Reports include both source SHA-256 digests, each probe's result, and explicit inconclusive reasons.
- A cosmetic patch, an unrelated-path workaround, a patch that blocks everybody, or a baseline that never reproduced all fail closed.

### Try it

From this directory:

```sh
python -m unittest discover -s tests -v
```

No API calls or external dependencies. All fixtures are toy authorization functions built inside temporary directories by the test suite.

## Trust boundary

The runner `exec`s fixture modules and is **only suitable for locally trusted synthetic code**. Do not point it at untrusted AI-generated patches or third-party source without moving execution into a properly isolated, resource-limited VM/container with no secrets or network access and a separately controlled observer. The trace confirms that the target function ran; it **cannot prove that that function caused the observed authorization result**. It does not test full vulnerability variants, native-memory vulnerabilities, kernel code, build reproducibility, or runtime exploitability.

For useful future evidence, the independent witness must additionally observe control-flow/data-flow attribution across the actual bug site, run known attack variants, check regressions, bind tested artifacts to reviewed commits and sign attestations from a separate identity. No trust or security certification should be claimed before those extensions and adversarial review.

## Source

[OpenAI: A thousand fewer paths to root (4 Nov 2026)](https://openai.com/index/a-thousand-fewer-paths-to-root/). An early campaign reported 20/200 apparently successful exploits that took a *different* vulnerability than the assigned one. That is why this experimental gate requires a trace of the named target function and never treats the final outcome alone as sufficient evidence.
