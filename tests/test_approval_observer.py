"""Sandbox, no cloud credentials: signed approvals and actual bytes postflight."""
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from agentproof.approval import ApprovalError, issue, validate, verify_outcome
from agentproof.attest import ObservationError, observe_files
from agentproof.terraform_guard import apply_saved_plan, saved_plan_sha256

ROOT = Path(__file__).resolve().parents[1] / "examples/terraform"
POLICY = json.loads((ROOT / "policy.json").read_text())
SAFE = json.loads((ROOT / "safe-plan.json").read_text())
SECRET = "test-only-approval-secret-with-adequate-length-0123456789"
PAYLOAD = b"expected-independent-postflight-bytes"
EXPECTED = {"schema": "agent-proof-pack/file-expectations/v1", "files": [
    {"path": "proof.txt", "sha256": hashlib.sha256(PAYLOAD).hexdigest()}]}


class ApprovalTests(unittest.TestCase):
    def approval(self, **changes):
        args = dict(plan_sha256=hashlib.sha256(b"plan").hexdigest(), policy=POLICY,
                    expectations=EXPECTED, environment="sandbox",
                    approver="independent-reviewer", key=SECRET, ttl_seconds=300,
                    now=1000)
        args.update(changes)
        return issue(**args)

    def verify(self, manifest, **changes):
        args = dict(plan_sha256=hashlib.sha256(b"plan").hexdigest(), policy=POLICY,
                    expectations=EXPECTED, environment="sandbox", key=SECRET, now=1100)
        args.update(changes)
        return validate(manifest, **args)

    def test_valid_scope(self):
        self.verify(self.approval())

    def test_changed_plan_denied(self):
        with self.assertRaises(ApprovalError):
            self.verify(self.approval(), plan_sha256="0"*64)

    def test_changed_policy_denied(self):
        p = deepcopy(POLICY)
        p["max_changed_resources"] = 2
        with self.assertRaises(ApprovalError):
            self.verify(self.approval(), policy=p)

    def test_changed_expectations_denied(self):
        e = deepcopy(EXPECTED)
        e["files"][0]["sha256"] = "0"*64
        with self.assertRaises(ApprovalError):
            self.verify(self.approval(), expectations=e)

    def test_changed_environment_denied(self):
        with self.assertRaises(ApprovalError):
            self.verify(self.approval(), environment="production")

    def test_tampered_signature_denied(self):
        a = self.approval()
        a["approver"] = "someone-else"
        with self.assertRaises(ApprovalError):
            self.verify(a)

    def test_expired_approval_denied(self):
        with self.assertRaises(ApprovalError):
            self.verify(self.approval(), now=1301)

    def test_future_approval_denied(self):
        with self.assertRaises(ApprovalError):
            self.verify(self.approval(), now=999)

    def test_unknown_manifest_field_denied(self):
        a = self.approval()
        a["grant_everything"] = True
        with self.assertRaises(ApprovalError):
            self.verify(a)

    def test_weak_signer_key_denied(self):
        with self.assertRaises(ApprovalError):
            self.approval(key="password")


class IndependentObservationTests(unittest.TestCase):
    def test_real_bytes_match(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "proof.txt").write_bytes(PAYLOAD)
            r = observe_files(Path(d), EXPECTED)
            self.assertEqual(r["state"], "verified")
            self.assertEqual(r["observations"][0]["observed_sha256"], EXPECTED["files"][0]["sha256"])

    def test_silent_noop_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(observe_files(Path(d), EXPECTED)["state"], "mismatch")

    def test_corrupted_bytes_fail(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "proof.txt").write_bytes(b"wrong")
            self.assertEqual(observe_files(Path(d), EXPECTED)["state"], "mismatch")

    def test_symlink_to_external_secrets_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            outside = Path(d) / "secret"
            outside.write_bytes(PAYLOAD)
            root = Path(d) / "workspace"
            root.mkdir()
            (root / "proof.txt").symlink_to(outside)
            self.assertEqual(observe_files(root, EXPECTED)["state"], "mismatch")

    def test_traversal_paths_rejected(self):
        for path in ("../secret", "/etc/passwd", "sub//file", "sub/./file", "sub\\file"):
            with self.subTest(path=path):
                e = deepcopy(EXPECTED)
                e["files"][0]["path"] = path
                with self.assertRaises(ObservationError):
                    observe_files(Path("."), e)

    def test_file_content_never_emitted(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "proof.txt").write_bytes(PAYLOAD)
            self.assertNotIn(PAYLOAD.decode(), json.dumps(observe_files(Path(d), EXPECTED)))


class ExecutionBoundaryTests(unittest.TestCase):
    def test_signed_plan_then_independent_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = root / "saved.tfplan"
            plan.write_bytes(b"safe-plan-bytes")
            a = issue(plan_sha256=saved_plan_sha256(plan), policy=POLICY,
                      expectations=EXPECTED, environment="sandbox",
                      approver="test-reviewer", key=SECRET)
            calls = []
            def fake_run(args, **kwargs):
                calls.append(args[1])
                if args[1] == "show":
                    return subprocess.CompletedProcess(args, 0, json.dumps(SAFE).encode(), b"")
                (root / "proof.txt").write_bytes(PAYLOAD)
                return subprocess.CompletedProcess(args, 0)
            with patch("agentproof.terraform_guard.subprocess.run", side_effect=fake_run):
                result = apply_saved_plan(plan, POLICY, approval=a, approval_key=SECRET,
                    environment="sandbox", expectations=EXPECTED, observe_root=root)
            self.assertEqual(result["state"], "verified")
            self.assertEqual(calls, ["show", "apply"])
            self.assertTrue(result["executed"])

    def test_authenticated_receipt_detects_later_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = root / "saved.tfplan"
            plan.write_bytes(b"safe-plan-bytes")
            a = issue(plan_sha256=saved_plan_sha256(plan), policy=POLICY,
                      expectations=EXPECTED, environment="sandbox",
                      approver="test-reviewer", key=SECRET)
            def fake_run(args, **kwargs):
                if args[1] == "show":
                    return subprocess.CompletedProcess(args, 0, json.dumps(SAFE).encode(), b"")
                (root / "proof.txt").write_bytes(PAYLOAD)
                return subprocess.CompletedProcess(args, 0)
            with patch("agentproof.terraform_guard.subprocess.run", side_effect=fake_run):
                result = apply_saved_plan(plan, POLICY, approval=a, approval_key=SECRET,
                    environment="sandbox", expectations=EXPECTED, observe_root=root)
            self.assertTrue(verify_outcome(result, SECRET))
            self.assertFalse(verify_outcome(result, "some-other-key-that-is-very-long-and-incorrect"))
            result["state"] = "postcondition_failed"
            self.assertFalse(verify_outcome(result, SECRET))

    def test_invalid_approval_blocks_before_terraform(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = root / "saved.tfplan"
            plan.write_bytes(b"safe-plan-bytes")
            a = issue(plan_sha256=saved_plan_sha256(plan), policy=POLICY,
                      expectations=EXPECTED, environment="sandbox",
                      approver="test-reviewer", key=SECRET)
            a["environment"] = "production"
            with patch("agentproof.terraform_guard.subprocess.run") as run:
                with self.assertRaises(ApprovalError):
                    apply_saved_plan(plan, POLICY, approval=a, approval_key=SECRET,
                        environment="sandbox", expectations=EXPECTED, observe_root=root)
                run.assert_not_called()

    def test_success_claim_but_no_write_is_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = root / "saved.tfplan"
            plan.write_bytes(b"safe-plan-bytes")
            a = issue(plan_sha256=saved_plan_sha256(plan), policy=POLICY,
                      expectations=EXPECTED, environment="sandbox",
                      approver="test-reviewer", key=SECRET)
            def fake_run(args, **kwargs):
                return (subprocess.CompletedProcess(args, 0, json.dumps(SAFE).encode(), b"")
                        if args[1] == "show" else subprocess.CompletedProcess(args, 0))
            with patch("agentproof.terraform_guard.subprocess.run", side_effect=fake_run):
                r = apply_saved_plan(plan, POLICY, approval=a, approval_key=SECRET,
                    environment="sandbox", expectations=EXPECTED, observe_root=root)
            self.assertEqual(r["state"], "postcondition_failed")
            self.assertTrue(r["executed"])


if __name__ == "__main__":
    unittest.main()
