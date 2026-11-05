import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from patch_witness import Case, verify

BASE = '''
def target_check(role, path):
    return role == "admin" or path.startswith("/public")

def alternative_check(role, path):
    return False

def can_read(role, path, route="target"):
    if route == "alternative":
        return alternative_check(role, path)
    return target_check(role, path)
'''
FIX = BASE.replace('path.startswith("/public")', '(path == "/public" or path.startswith("/public/"))')
DECOY = BASE + '\n# cosmetically changed but vulnerability remains\n'
WRONG_PATH = BASE.replace('return target_check(role, path)', 'return alternative_check(role, path)')
OVERBLOCK = BASE.replace('role == "admin" or path.startswith("/public")', 'False')

CASES = [
    Case("block_prefix_confusion", ("guest", "/publicity/secret"), True, False),
    Case("preserve_public_access", ("guest", "/public/file"), True, True),
    Case("preserve_admin_access", ("admin", "/private/file"), True, True),
]


class PatchWitnessTest(unittest.TestCase):
    def run_pair(self, before: str, after: str, cases=CASES):
        with tempfile.TemporaryDirectory() as d:
            first, second = Path(d) / "baseline.py", Path(d) / "patched.py"
            first.write_text(before, encoding="utf-8")
            second.write_text(after, encoding="utf-8")
            return verify(first, second, "can_read", "target_check", cases)

    def test_real_fix_passes(self):
        report = self.run_pair(BASE, FIX)
        self.assertEqual("differential_and_counterfactual_probes_passed", report["status"])
        self.assertTrue(all(c["before"]["target_called"] for c in report["cases"]))

    def test_cosmetic_patch_does_not_pass(self):
        report = self.run_pair(BASE, DECOY)
        self.assertEqual("inconclusive", report["status"])
        self.assertEqual("target_function_not_changed", report["reason"])

    def test_wrong_path_does_not_pass_even_if_outcome_matches(self):
        report = self.run_pair(BASE, WRONG_PATH)
        self.assertEqual("inconclusive", report["status"])
        self.assertEqual("target_function_not_changed", report["reason"])

    def test_overblocking_not_a_fix(self):
        report = self.run_pair(BASE, OVERBLOCK)
        self.assertEqual("inconclusive", report["status"])
        self.assertEqual("patch_not_validated", report["cases"][1]["reason"])

    def test_fails_closed_when_baseline_did_not_reproduce(self):
        report = self.run_pair(FIX, FIX + "\n# change", CASES)
        self.assertEqual("inconclusive", report["status"])
        self.assertEqual("target_function_not_changed", report["reason"])

    def test_identical_hash_not_a_patch(self):
        report = self.run_pair(BASE, BASE)
        self.assertEqual("inconclusive", report["status"])

    def test_no_transition_case_is_inconclusive(self):
        report = self.run_pair(BASE, FIX, CASES[1:])
        self.assertEqual("inconclusive", report["status"])

    def test_duplicate_cases_rejected(self):
        with self.assertRaises(ValueError):
            self.run_pair(BASE, FIX, [CASES[0], CASES[0]])


if __name__ == "__main__":
    unittest.main()
