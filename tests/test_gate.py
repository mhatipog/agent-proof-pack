import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from crm_demo import demo
from agentproof.gate import run_guarded

PRE = {"id": "pre", "rules": [{"id": "exists", "kind": "required", "path": "proposed.id"}]}
POST = {"id": "post", "rules": [{"id": "receipt", "kind": "required", "path": "after.provider_id"}]}


class GateTests(unittest.TestCase):
    def test_good_action_verified(self):
        r = demo("success")
        self.assertEqual(r["state"], "verified")
        self.assertTrue(r["executed"])

    def test_disallowed_tool_never_called(self):
        r = demo("unauthorized")
        self.assertEqual(r["state"], "refused")
        self.assertFalse(r["executed"])

    def test_false_success_detected(self):
        r = demo("no-op")
        self.assertEqual(r["state"], "postcondition_failed")
        self.assertTrue(r["executed"])

    def test_exec_blocked_when_preflight_fails(self):
        calls = []
        r = run_guarded(pre_policy=PRE, post_policy=POST, pre_evidence={},
                        execute=lambda: calls.append("called"),
                        observe=lambda: {"provider_id": "1"})
        self.assertEqual(calls, [])
        self.assertEqual(r["state"], "refused")

    def test_execution_exception_not_approved(self):
        def fail():
            raise RuntimeError("secret never shown")
        r = run_guarded(pre_policy=PRE, post_policy=POST,
                        pre_evidence={"proposed": {"id": 1}}, execute=fail,
                        observe=lambda: {"provider_id": "1"})
        self.assertEqual(r["state"], "indeterminate_execution")
        self.assertNotIn("secret", str(r))

    def test_observation_failure_not_approved(self):
        def fail_observe():
            raise TimeoutError("can't verify")
        r = run_guarded(pre_policy=PRE, post_policy=POST,
                        pre_evidence={"proposed": {"id": 1}}, execute=lambda: None,
                        observe=fail_observe)
        self.assertEqual(r["state"], "unverifiable_after_action")

    def test_postfailure_is_not_preflight_refusal(self):
        r = run_guarded(pre_policy=PRE, post_policy=POST,
                        pre_evidence={"proposed": {"id": 1}}, execute=lambda: None,
                        observe=lambda: {})
        self.assertEqual(r["state"], "postcondition_failed")
        self.assertEqual(r["postflight"]["verdict"], "block")


if __name__ == "__main__":
    unittest.main()
