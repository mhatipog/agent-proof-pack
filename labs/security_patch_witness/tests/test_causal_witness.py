import tempfile
import unittest
from pathlib import Path
from test_patch_witness import BASE, FIX, CASES
from patch_witness import Case, verify


class CausalWitnessTest(unittest.TestCase):
    def run_pair(self, before=BASE, after=FIX, cases=CASES, **kw):
        with tempfile.TemporaryDirectory() as d:
            first, second = Path(d) / 'before.py', Path(d) / 'after.py'
            first.write_text(before)
            second.write_text(after)
            return verify(first, second, 'can_read', 'target_check', list(cases), **kw)

    def test_counterfactual_reintroduces_bug(self):
        report = self.run_pair()
        self.assertEqual('differential_and_counterfactual_probes_passed', report['status'])
        self.assertEqual([True, True, True], [r['passed'] for r in report['counterfactual']])
        self.assertTrue(report['target_changed'])
        self.assertEqual(9, report['executions'])
        self.assertEqual('all_declared_probes_passed', report['reason'])

    def test_wrong_cause_is_rejected_even_when_target_called(self):
        # A superficial target change, while the *caller* filters the vulnerable path.
        # The target is still called but restoring it doesn't restore the vulnerability.
        after = BASE.replace('return role == "admin" or path.startswith("/public")',
                             'return bool(role == "admin" or path.startswith("/public"))')
        after = after.replace('return target_check(role, path)',
                              'return target_check(role, path) and path != "/publicity/secret"')
        report = self.run_pair(after=after)
        self.assertTrue(all(r['passed'] for r in report['cases']))
        self.assertEqual('inconclusive', report['status'])
        self.assertEqual('counterfactual_failed', report['reason'])
        self.assertFalse(report['counterfactual'][0]['passed'])

    def test_negative_first_saves_executions(self):
        failures = [Case('control_first', ('admin', '/private/file'), True, True),
                    Case('attack', ('guest', '/publicity/secret'), True, False)]
        report = self.run_pair(after=BASE.replace('path.startswith("/public")', 'path.startswith("/public") and True'), cases=failures)
        self.assertEqual('patch_not_validated', report['reason'])
        self.assertEqual('attack', report['cases'][0]['name'])
        self.assertEqual(['control_first'], report['skipped_cases'])
        self.assertEqual(2, report['executions'])

    def test_budget_cap_enforced(self):
        report = self.run_pair(max_executions=4)
        self.assertEqual('execution_budget_exhausted', report['reason'])
        self.assertEqual(4, report['executions'])
        self.assertEqual('inconclusive', report['status'])

    def test_counterfactual_budget_cap_fails_closed(self):
        report = self.run_pair(max_executions=6)
        self.assertEqual('execution_budget_exhausted', report['reason'])
        self.assertEqual(6, report['executions'])
        self.assertEqual('inconclusive', report['status'])

    def test_comment_only_target_does_not_pass(self):
        # A comment inserted inside target must not be misidentified as a real change.
        after = BASE.replace('return role == "admin"', '# changed!\n    return role == "admin"')
        report = self.run_pair(after=after)
        self.assertEqual('target_function_not_changed', report['reason'])
        self.assertEqual(0, report['executions'])

    def test_error_does_not_leak_exception_message(self):
        after = FIX.replace('return role == "admin"', 'raise ValueError("SENSITIVE_TEST_ONLY")\n    return role == "admin"')
        report = self.run_pair(after=after)
        self.assertEqual('execution_error', report['reason'])
        self.assertNotIn('SENSITIVE_TEST_ONLY', str(report))

    def test_duplicate_target_is_not_valid(self):
        with self.assertRaises(ValueError):
            self.run_pair(after=FIX + '\ndef target_check(role, path):\n    return False\n')

    def test_no_required_transition_is_rejected_at_zero_execution(self):
        report = self.run_pair(cases=CASES[1:])
        self.assertEqual('no_security_transition', report['reason'])
        self.assertEqual(0, report['executions'])

    def test_no_external_requirements(self):
        import json
        self.assertIsInstance(json.dumps(self.run_pair()), str)


if __name__ == '__main__':
    unittest.main()
