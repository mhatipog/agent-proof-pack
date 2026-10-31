"""Fast offline regression tests for transaction-bound authenticated receipts."""
import copy
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import uuid4

from agentproof.effect import EffectError
from agentproof.tx_receipt_verify import main as verify_cli
from agentproof.tx_effect import (
    CONTRACT_SCHEMA, _validate_contract, observe_transaction,
    verify_transaction_receipt,
)

KEY = "offline-transaction-witness-test-key-not-production-2026"
ACTION = "c4bf3931-375e-42b5-ac79-69b817c9fcab"


def contract():
    return {
        "schema": CONTRACT_SCHEMA,
        "id": "crm_status",
        "action_id": ACTION,
        "executor_role": "effect_actor",
        "customer_id": "C-42",
        "from_status": "open",
        "to_status": "won",
    }


def db_rows():
    grant = ("effect_actor", "C-42", "open", "won", object())
    committed = (833, "effect_actor", "C-42", "open", "won")
    effect = (833, "C-42", "open", "won")
    return grant, committed, effect


class TransactionEvidenceUnitTests(unittest.TestCase):
    @patch("agentproof.tx_effect._read_records")
    def test_verified_signs_only_authorized_transaction_event(self, read):
        read.return_value = db_rows()
        receipt = observe_transaction("trusted-reader-dsn", contract(), KEY)
        self.assertEqual(receipt["statement"]["predicate"]["status"], "verified")
        self.assertTrue(verify_transaction_receipt(receipt, KEY))
        self.assertEqual(len(receipt["statement"]["predicate"]["checks"]), 8)
        self.assertNotIn("C-42", repr(receipt))
        self.assertNotIn("effect_actor", repr(receipt))
        self.assertNotIn(ACTION, repr(receipt))
        self.assertEqual(read.call_args.args[1], ACTION)

    @patch("agentproof.tx_effect._read_records")
    def test_missing_and_uncommitted_refused(self, read):
        for state in [(None, None, None),
                      (("effect_actor", "C-42", "open", "won", None), None, None)]:
            with self.subTest(state=state):
                read.return_value = state
                receipt = observe_transaction("reader", contract(), KEY)
                self.assertEqual(receipt["statement"]["predicate"]["status"], "failed")
                self.assertTrue(verify_transaction_receipt(receipt, KEY))

    @patch("agentproof.tx_effect._read_records")
    def test_wrong_transaction_or_row_effect_refused(self, read):
        cases = [
            (db_rows()[0], db_rows()[1], (834, "C-42", "open", "won")),
            (db_rows()[0], db_rows()[1], (833, "C-99", "open", "won")),
            (db_rows()[0], (833, "other_role", "C-42", "open", "won"), db_rows()[2]),
            (db_rows()[0], db_rows()[1], None),
        ]
        for state in cases:
            with self.subTest(state=state):
                read.return_value = state
                self.assertEqual(observe_transaction("reader", contract(), KEY)
                                 ["statement"]["predicate"]["status"], "failed")

    @patch("agentproof.tx_effect._read_records")
    def test_tampered_verdict_cannot_be_forged(self, read):
        read.return_value = db_rows()
        receipt = observe_transaction("reader", contract(), KEY)
        self.assertFalse(verify_transaction_receipt(receipt, KEY + "wrong"))
        altered = copy.deepcopy(receipt)
        altered["statement"]["predicate"]["status"] = "failed"
        self.assertFalse(verify_transaction_receipt(altered, KEY))
        altered = copy.deepcopy(receipt)
        altered["statement"]["predicate"]["checks"][0]["status"] = "fail"
        self.assertFalse(verify_transaction_receipt(altered, KEY))

    @patch("agentproof.tx_effect._read_records")
    def test_offline_receipt_command_refuses_tampering_and_signed_failures(self, read):
        read.return_value = db_rows()
        valid = observe_transaction("reader", contract(), KEY)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "effect.json"
            with patch.dict(os.environ, {"AGENTPROOF_TEST_VERIFIER_KEY": KEY}):
                path.write_text(json.dumps(valid), encoding="utf8")
                args = ["--receipt", str(path), "--key-env", "AGENTPROOF_TEST_VERIFIER_KEY"]
                self.assertEqual(verify_cli(args), 0)
                bad = copy.deepcopy(valid)
                bad["statement"]["predicate"]["checks"][0]["status"] = "fail"
                path.write_text(json.dumps(bad), encoding="utf8")
                self.assertEqual(verify_cli(args), 4)
                read.return_value = (None, None, None)
                failed = observe_transaction("reader", contract(), KEY)
                path.write_text(json.dumps(failed), encoding="utf8")
                self.assertEqual(verify_cli(args), 4)

    def test_contract_requires_canonical_uuid_and_exact_expected_scope(self):
        baseline = contract()
        self.assertEqual(_validate_contract(baseline), ACTION)
        cases = [
            {"action_id": str(uuid4()).upper()},
            {"action_id": "invalid"},
            {"from_status": "won"},
            {"executor_role": "role';DROP TABLE"},
            {"customer_id": ""},
            {"unexpected": "extra"},
        ]
        for changes in cases:
            candidate = {**baseline, **changes}
            with self.subTest(changes=changes), self.assertRaises(EffectError):
                _validate_contract(candidate)


if __name__ == "__main__":
    unittest.main()
