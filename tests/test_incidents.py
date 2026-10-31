"""Offline tests for *simulated* cases derived from published incident reports."""
import json
import unittest
from copy import deepcopy
from pathlib import Path

from agentproof.engine import digest, evaluate
from agentproof.gate import run_guarded

LIBRARY = json.loads((Path(__file__).resolve().parents[1] / "examples" / "incident_cases.json").read_text())
BY_ID = {case["id"]: case for case in LIBRARY["cases"]}


class SourcedIncidentRegressions(unittest.TestCase):
    def test_library_records_provenance(self):
        self.assertGreaterEqual(len(LIBRARY["cases"]), 12)
        for incident in LIBRARY["sources"].values():
            self.assertIn(incident["type"], ("reported incident", "first-person incident postmortem",
                                            "security researcher proof of concept"))
            self.assertTrue(incident["url"].startswith("https://"))
        for case in LIBRARY["cases"]:
            self.assertIn(case["source_key"], LIBRARY["sources"])
            self.assertEqual(case["origin"][:9], "synthetic")

    def test_all_case_verdicts(self):
        for case in LIBRARY["cases"]:
            with self.subTest(case["id"]):
                receipt = evaluate(case["policy"], case["evidence"], evaluated_at="2026-10-31T00:00:00Z")
                self.assertEqual(receipt["verdict"], case["expected"])
                self.assertEqual(receipt["policy_sha256"], digest(case["policy"]))

    def test_plan_fingerprint_is_exact(self):
        original = deepcopy(BY_ID["datatalks-approved-plan"])
        self.assertEqual(evaluate(original["policy"], original["evidence"])["verdict"], "approve")
        original["evidence"]["action"]["plan"]["destroy"].append("aws_db_snapshot.main")
        self.assertEqual(evaluate(original["policy"], original["evidence"])["verdict"], "block")

    def test_revision_fails_closed(self):
        original = deepcopy(BY_ID["datatalks-approved-plan"])
        original["evidence"]["authority"].pop("current_revision")
        self.assertEqual(evaluate(original["policy"], original["evidence"])["verdict"], "block")

    def test_exact_grant_is_not_cartesian_product(self):
        base = deepcopy(BY_ID["pocketos-staging-read"])
        base["evidence"]["authority"]["grants"].append({
            "principal": "staging-agent", "tool": "railway.volume",
            "resource": "railway/prod/db-volume", "operation": "read", "environment": "production"
        })
        base["evidence"]["action"]["tool"] = "railway.volume"
        # Tool and resource each appear in a grant; the tuple does not.
        self.assertEqual(evaluate(base["policy"], base["evidence"])["verdict"], "block")

    def test_missing_principal_blocks(self):
        base = deepcopy(BY_ID["pocketos-staging-read"])
        base["evidence"]["action"].pop("principal")
        self.assertEqual(evaluate(base["policy"], base["evidence"])["verdict"], "block")

    def test_mismatched_environment_blocks(self):
        base = deepcopy(BY_ID["pocketos-staging-read"])
        base["evidence"]["action"]["environment"] = "production"
        self.assertEqual(evaluate(base["policy"], base["evidence"])["verdict"], "block")

    def test_origin_allowlist_not_suffix_match(self):
        base = deepcopy(BY_ID["shadowleak-approved-destination"])
        for url in ("https://mail.example.test.evil.invalid/v1/send",
                    "https://mail.example.test@evil.invalid/x",
                    "http://mail.example.test/x",
                    "https://mail.example.test:8443/x",
                    "https://mail.example.test\\evil.invalid/x",
                    "https://mail.example.test\n@evil.invalid/x"):
            with self.subTest(url=url):
                base["evidence"]["action"]["url"] = url
                self.assertEqual(evaluate(base["policy"], base["evidence"])["verdict"], "block")

    def test_untrusted_classification_fails_closed(self):
        base = deepcopy(BY_ID["github-mcp-public-to-public"])
        base["evidence"]["authority"]["source_label"] = None
        self.assertEqual(evaluate(base["policy"], base["evidence"])["verdict"], "block")

    def test_unauthorized_executor_never_runs(self):
        base = BY_ID["pocketos-production-delete"]
        executed = []
        result = run_guarded(
            pre_policy=base["policy"],
            post_policy={"id": "post", "rules": [{"id": "receipt", "kind": "required", "path": "after.receipt"}]},
            pre_evidence=base["evidence"],
            execute=lambda: executed.append("ran"), observe=lambda: {"receipt": "ok"})
        self.assertEqual(result["state"], "refused")
        self.assertFalse(result["executed"])
        self.assertEqual(executed, [])

    def test_allowed_executor_runs_and_verifies(self):
        base = BY_ID["pocketos-staging-read"]
        executed = []
        result = run_guarded(
            pre_policy=base["policy"],
            post_policy={"id": "post", "rules": [{"id": "receipt", "kind": "required", "path": "after.receipt"}]},
            pre_evidence=base["evidence"],
            execute=lambda: executed.append("ran"), observe=lambda: {"receipt": "provider-confirmation"})
        self.assertEqual(result["state"], "verified")
        self.assertEqual(executed, ["ran"])


if __name__ == "__main__":
    unittest.main()
