"""No cloud credentials or real Terraform invocation required."""
import hashlib
import json
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from agentproof.terraform_guard import (
    TerraformGateError, apply_saved_plan, review_plan, review_saved_plan, saved_plan_sha256,
)

ROOT = Path(__file__).resolve().parents[1] / "examples/terraform"
POLICY = json.loads((ROOT / "policy.json").read_text())
SAFE = json.loads((ROOT / "safe-plan.json").read_text())
DESTRUCTIVE = json.loads((ROOT / "destructive-plan.json").read_text())


class TerraformReviewTests(unittest.TestCase):
    def blocked(self, plan, policy=None):
        self.assertEqual(review_plan(plan, policy or POLICY)["verdict"], "block")

    def test_safe_plan(self):
        r = review_plan(SAFE, POLICY)
        self.assertEqual(r["verdict"], "approve")
        self.assertEqual(r["changed_resource_count"], 1)
        self.assertEqual(r["source"], "json_fixture")

    def test_replacement_delete_create(self):
        self.blocked(DESTRUCTIVE)

    def test_replacement_create_delete(self):
        p = deepcopy(DESTRUCTIVE)
        p["resource_changes"][0]["change"]["actions"] = ["create", "delete"]
        self.blocked(p)

    def test_plain_delete(self):
        p = deepcopy(DESTRUCTIVE)
        p["resource_changes"][0]["change"]["actions"] = ["delete"]
        self.blocked(p)

    def test_explicit_delete_only_exact_address(self):
        p = deepcopy(DESTRUCTIVE)
        policy = deepcopy(POLICY)
        policy["allowed_actions"].append("delete")
        policy["allow_destructive_addresses"] = ["terraform_data.example"]
        self.assertEqual(review_plan(p, policy)["verdict"], "approve")
        p["resource_changes"][0]["address"] = "terraform_data.other"
        self.blocked(p, policy)

    def test_protected_resource(self):
        p = deepcopy(SAFE)
        p["resource_changes"][0]["address"] = "terraform_data.critical"
        self.blocked(p)

    def test_resource_type(self):
        p = deepcopy(SAFE)
        p["resource_changes"][0]["type"] = "aws_db_instance"
        self.blocked(p)

    def test_change_budget(self):
        policy = deepcopy(POLICY)
        policy["max_changed_resources"] = 0
        self.blocked(SAFE, policy)

    def test_deferred_and_action_invocations(self):
        for field in ("deferred_changes", "deferred_action_invocations", "action_invocations"):
            with self.subTest(field=field):
                p = deepcopy(SAFE)
                p[field] = [{"address": "action.unknown"}]
                self.blocked(p)

    def test_errored_or_incomplete_plan(self):
        for field, value in (("complete", False), ("errored", True),
                             ("applyable", False), ("format_version", "2.0")):
            with self.subTest(field=field):
                p = deepcopy(SAFE)
                p[field] = value
                self.blocked(p)
        p = deepcopy(SAFE)
        p.pop("complete")
        self.blocked(p)

    def test_detect_drift(self):
        p = deepcopy(SAFE)
        p["resource_drift"] = [{"address": "aws_db_instance.prod",
                                "change": {"actions": ["update"]}}]
        self.blocked(p)

    def test_terraform_checks(self):
        p = deepcopy(SAFE)
        p["checks"] = [{"status": "unknown"}]
        self.blocked(p)

    def test_output_changes(self):
        p = deepcopy(SAFE)
        p["output_changes"] = {"password": {"actions": ["update"], "after": "sensitive"}}
        self.blocked(p)
        policy = deepcopy(POLICY)
        policy["allowed_output_names"].append("password")
        self.assertEqual(review_plan(p, policy)["verdict"], "approve")

    def test_missing_resources(self):
        p = deepcopy(SAFE)
        del p["resource_changes"]
        with self.assertRaises(TerraformGateError):
            review_plan(p, POLICY)

    def test_unknown_action(self):
        p = deepcopy(SAFE)
        p["resource_changes"][0]["change"]["actions"] = ["upsert"]
        with self.assertRaises(TerraformGateError):
            review_plan(p, POLICY)

    def test_no_sensitive_values_in_receipt(self):
        p = deepcopy(SAFE)
        p["variables"] = {"password": {"value": "secret-do-not-disclose"}}
        p["resource_changes"][0]["change"]["after"]["token"] = "secret-do-not-disclose"
        receipt = json.dumps(review_plan(p, POLICY))
        self.assertNotIn("secret-do-not-disclose", receipt)
        self.assertNotIn("password", receipt)

    def test_binary_digest_bound_to_review(self):
        sha = hashlib.sha256(b"plan").hexdigest()
        self.assertEqual(review_plan(SAFE, POLICY, plan_sha256=sha,
                                     expected_sha256=sha)["verdict"], "approve")
        self.assertEqual(review_plan(SAFE, POLICY, plan_sha256=sha,
                                     expected_sha256="0"*64)["verdict"], "block")

    def test_policy_unknown_field(self):
        policy = deepcopy(POLICY)
        policy["allow_all"] = True
        with self.assertRaises(TerraformGateError):
            review_plan(SAFE, policy)

    def test_destructive_requires_exact_allowance(self):
        policy = deepcopy(POLICY)
        policy["allowed_actions"].append("delete")
        with self.assertRaises(TerraformGateError):
            review_plan(SAFE, policy)

    def test_saved_plan_reads_terraform_show_not_raw_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "saved.tfplan"
            plan.write_bytes(b"test-plan")
            with patch("agentproof.terraform_guard.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, json.dumps(SAFE).encode(), b"")
                r = review_saved_plan(plan, POLICY, expected_sha256=saved_plan_sha256(plan))
            self.assertEqual(r["verdict"], "approve")
            self.assertEqual(r["source"], "saved_plan")
            self.assertEqual(run.call_args.args[0][1:3], ["show", "-json"])

    def test_unapproved_apply_never_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "saved.tfplan"
            plan.write_bytes(b"destructive-plan")
            called = []
            def fake_run(args, **kwargs):
                called.append(args[1])
                if args[1] == "show":
                    return subprocess.CompletedProcess(args, 0, json.dumps(DESTRUCTIVE).encode(), b"")
                raise AssertionError("apply must not be called")
            with patch("agentproof.terraform_guard.subprocess.run", side_effect=fake_run):
                r = apply_saved_plan(plan, POLICY, approved_sha256=saved_plan_sha256(plan))
            self.assertEqual(r["state"], "refused")
            self.assertEqual(called, ["show"])

    def test_approved_apply_same_private_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "saved.tfplan"
            plan.write_bytes(b"allow-plan")
            sha = saved_plan_sha256(plan)
            paths = []
            def fake_run(args, **kwargs):
                paths.append(Path(args[-1]))
                self.assertEqual(saved_plan_sha256(paths[-1]), sha)
                if args[1] == "show":
                    return subprocess.CompletedProcess(args, 0, json.dumps(SAFE).encode(), b"")
                self.assertEqual(args[1:3], ["apply", "-input=false"])
                return subprocess.CompletedProcess(args, 0)
            with patch("agentproof.terraform_guard.subprocess.run", side_effect=fake_run):
                r = apply_saved_plan(plan, POLICY, approved_sha256=sha)
            self.assertEqual(r["state"], "apply_completed_unverified")
            self.assertTrue(r["executed"])
            self.assertEqual(paths[0], paths[1])
            self.assertNotEqual(paths[0], plan)
            self.assertFalse(paths[0].exists())

    def test_wrong_approved_digest_no_terraform_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan"
            plan.write_bytes(b"plan")
            with patch("agentproof.terraform_guard.subprocess.run") as run:
                with self.assertRaises(TerraformGateError):
                    apply_saved_plan(plan, POLICY, approved_sha256="0"*64)
                run.assert_not_called()

    def test_state_move_even_noop_must_block(self):
        p = deepcopy(SAFE)
        p["resource_changes"][0]["change"]["actions"] = ["no-op"]
        p["resource_changes"][0]["previous_address"] = "terraform_data.old"
        self.blocked(p)

    def test_import_does_not_hide_in_create_action(self):
        p = deepcopy(SAFE)
        p["resource_changes"][0]["change"]["importing"] = {"id": "existing-resource"}
        self.blocked(p)

    def test_generated_import_config_also_blocks(self):
        p = deepcopy(SAFE)
        p["resource_changes"][0]["change"]["generated_config"] = "resource \"terraform_data\" \"example\" {}"
        self.blocked(p)

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan"
            plan.write_bytes(b"plan")
            link = Path(tmp) / "link"
            link.symlink_to(plan)
            with self.assertRaises(TerraformGateError):
                saved_plan_sha256(link)


if __name__ == "__main__":
    unittest.main()
