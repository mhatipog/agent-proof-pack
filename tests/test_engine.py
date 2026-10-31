import json
import unittest
from copy import deepcopy
from pathlib import Path

from agentproof.engine import CheckError, PolicyError, decimal, digest, evaluate, verify_signature

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "examples/cases.json").read_text())


class ExampleFixtures(unittest.TestCase):
    def test_all_cases(self):
        self.assertGreaterEqual(len(CASES), 10)
        for c in CASES:
            with self.subTest(c["id"]):
                got = evaluate(c["policy"], c["evidence"], evaluated_at="2026-01-01T00:00:00Z")
                self.assertEqual(got["verdict"], c["expected"])
                self.assertEqual(got["policy_sha256"], digest(c["policy"]))
                self.assertEqual(got["evidence_sha256"], digest(c["evidence"]))


class EngineSecurity(unittest.TestCase):
    def setUp(self):
        self.policy = {"id": "check", "rules": [{"id": "exists", "kind": "required", "path": "after.receipt_id"}]}
        self.event = {"phase": "postflight", "action": {"id": "a1"}, "after": {"receipt_id": "provider-77"}}

    def test_signature(self):
        receipt = evaluate(self.policy, self.event, signing_key="unique verifier key")
        self.assertTrue(verify_signature(receipt, "unique verifier key"))
        self.assertFalse(verify_signature(receipt, "wrong key"))

    def test_signature_fails_if_edited(self):
        receipt = evaluate(self.policy, self.event, signing_key="key")
        receipt["verdict"] = "block"
        self.assertFalse(verify_signature(receipt, "key"))

    def test_signature_fails_if_receipt_hash_tampered(self):
        receipt = evaluate(self.policy, self.event, signing_key="key")
        receipt["receipt_sha256"] = "0" * 64
        self.assertFalse(verify_signature(receipt, "key"))

    def test_unsigned_receipt_not_authenticated(self):
        self.assertFalse(verify_signature(evaluate(self.policy, self.event), "key"))

    def test_approves_when_proven(self):
        self.assertEqual(evaluate(self.policy, self.event)["verdict"], "approve")

    def test_missing_after_fails_closed(self):
        event = deepcopy(self.event)
        event.pop("after")
        self.assertEqual(evaluate(self.policy, event)["verdict"], "block")

    def test_rule_without_evidence_is_not_pass(self):
        event = deepcopy(self.event)
        event["after"]["receipt_id"] = ""
        self.assertEqual(evaluate(self.policy, event)["verdict"], "block")

    def test_empty_rules_denied(self):
        with self.assertRaises(PolicyError):
            evaluate({"id": "empty", "rules": []}, self.event)

    def test_unsupported_kind_denied(self):
        with self.assertRaises(PolicyError):
            evaluate({"id": "x", "rules": [{"id": "eval", "kind": "python_eval"}]}, self.event)

    def test_duplicate_ids_denied(self):
        rule = self.policy["rules"][0]
        with self.assertRaises(PolicyError):
            evaluate({"id": "x", "rules": [rule, rule]}, self.event)

    def test_invalid_failure_action_denied(self):
        rule = {**self.policy["rules"][0], "on_fail": "ignore"}
        with self.assertRaises(PolicyError):
            evaluate({"id": "x", "rules": [rule]}, self.event)

    def test_escalation_does_not_approve(self):
        policy = deepcopy(self.policy)
        policy["rules"][0]["on_fail"] = "escalate"
        self.assertEqual(evaluate(policy, {"after": {}})["verdict"], "escalate")

    def test_block_precedes_escalate(self):
        policy = deepcopy(self.policy)
        policy["rules"].append({"id": "other", "kind": "required", "path": "after.other", "on_fail": "escalate"})
        self.assertEqual(evaluate(policy, {"after": {}})["verdict"], "block")

    def test_float_rejected(self):
        with self.assertRaises(CheckError):
            decimal(0.01, money=True)

    def test_nonfinite_rejected(self):
        with self.assertRaises(CheckError):
            decimal("NaN", money=True)

    def test_money_precision_rejected(self):
        with self.assertRaises(CheckError):
            decimal("0.001", money=True)

    def test_boolean_rejected(self):
        with self.assertRaises(CheckError):
            decimal(True)

    def test_digest_stable_key_order(self):
        self.assertEqual(digest({"a": 1, "b": 2}), digest({"b": 2, "a": 1}))

    def test_does_not_include_private_data_in_receipt(self):
        event = deepcopy(self.event)
        event["after"]["receipt_id"] = "secret-account-value"
        receipt = evaluate(self.policy, event)
        self.assertNotIn("secret-account-value", json.dumps(receipt))

    def test_empty_hmac_key_denied(self):
        with self.assertRaises(PolicyError):
            evaluate(self.policy, self.event, signing_key="")


if __name__ == "__main__":
    unittest.main()
