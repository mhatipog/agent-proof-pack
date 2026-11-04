"""Execute optional Agents SDK regression requirements without hiding unexpected errors.

Two named properties are known broken on the pinned 0.24.0 SDK. They are
reported as REPRODUCED rather than treating a known failure as a broken CI run.
Unexpected failures and any exceptions fail this runner; a future fix is OK.
"""

from __future__ import annotations

import importlib.metadata
import io
import sys
import unittest

from test_sdk_action_integrity import ActionIntegrityTests

CASES = (
    ("test_no_approval_means_no_execution", None),
    (
        "test_stale_approval_cannot_authorize_a_separate_run",
        "A foreign approval caused an additional action in the second run",
    ),
    (
        "test_approved_tool_guardrail_results_survive_resume",
        "Input guardrail ran but its evidence was lost",
    ),
)


def main() -> int:
    print("openai-agents:", importlib.metadata.version("openai-agents"), flush=True)
    unexpected = False
    for name, expected_message in CASES:
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
            unittest.TestSuite([ActionIntegrityTests(name)])
        )
        if result.errors:
            print(f"ERROR {name}: {stream.getvalue()}", flush=True)
            unexpected = True
        elif result.failures:
            if (
                expected_message
                and len(result.failures) == 1
                and expected_message in result.failures[0][1]
            ):
                print(f"REPRODUCED {name} (expected regression failure)", flush=True)
            else:
                print(f"UNEXPECTED_FAILURE {name}: {stream.getvalue()}", flush=True)
                unexpected = True
        elif result.wasSuccessful():
            status = "FIXED" if expected_message else "PASS"
            print(f"{status} {name}", flush=True)
        else:
            print(f"UNKNOWN_RESULT {name}: {stream.getvalue()}", flush=True)
            unexpected = True
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
