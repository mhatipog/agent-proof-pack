"""No database required: strict untrusted-tool interface and tamper checks."""
import copy
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from agentproof.effect import EffectError
from agentproof.generic_cli import (
    validate_contract, apply_approved, observe_approved, verify_outcome,
)

KEY = "verifier-only-strong-sandbox-signing-key-with-enough-bytes"
CONTRACT = {
    "schema": "agent-proof-pack/generic-transaction-contract/v1",
    "id": "order_change", "action_id": "11111111-1111-4111-8111-111111111111",
    "executor_role": "restricted_agent", "table": "public.customer",
    "key_column": "customer_id", "key_value": "1",
    "update_column": "email", "old_value": "old@example.invalid",
    "new_value": "new@example.invalid",
}


class GenericInterfaceTests(unittest.TestCase):
    def test_valid_contract(self):
        validate_contract(CONTRACT)

    def test_rejects_changed_schema(self):
        c = copy.deepcopy(CONTRACT)
        c["schema"] = "unknown"
        with self.assertRaises(EffectError):
            validate_contract(c)

    def test_rejects_noncanonical_uuid(self):
        c = copy.deepcopy(CONTRACT)
        c["action_id"] = "AAAAAAAA-1111-4111-8111-111111111111"
        with self.assertRaises(EffectError):
            validate_contract(c)

    def test_rejects_agent_sql(self):
        with self.assertRaises(EffectError):
            apply_approved("a-read-only-connection", "DELETE FROM invoice")

    def test_rejects_dynamic_table_name(self):
        c = copy.deepcopy(CONTRACT)
        c["table"] = "public.customer;DELETE FROM invoice"
        with self.assertRaises(EffectError):
            validate_contract(c)

    def test_rejects_extra_authorization_fields(self):
        c = copy.deepcopy(CONTRACT)
        c["allow_any_change"] = True
        with self.assertRaises(EffectError):
            validate_contract(c)

    def test_noop_expectation_rejected(self):
        c = copy.deepcopy(CONTRACT)
        c["new_value"] = c["old_value"]
        with self.assertRaises(EffectError):
            validate_contract(c)

    def test_no_database_connection_needed_to_fail_closed(self):
        with self.assertRaises(EffectError):
            observe_approved("", CONTRACT, KEY)

    def test_exact_contract_and_freshness_are_required_for_useful_proof(self):
        grant = (42, "customer_id", "1", "email", "old@example.invalid",
                 "new@example.invalid", "restricted_agent", datetime.now(timezone.utc), None)
        committed = (42, "customer_id", "1", "email", "old@example.invalid",
                     "new@example.invalid", "restricted_agent", 123456)
        with patch("agentproof.generic_cli._read",
                   return_value=(grant, committed, ("public", "customer", False, False),
                                 "new@example.invalid")):
            receipt = observe_approved("unused", CONTRACT, KEY)
        self.assertEqual(receipt["statement"]["predicate"]["status"], "verified")
        self.assertTrue(verify_outcome(receipt, KEY, contract=CONTRACT))
        wrong = copy.deepcopy(CONTRACT)
        wrong["action_id"] = "22222222-2222-4222-8222-222222222222"
        self.assertFalse(verify_outcome(receipt, KEY, contract=wrong))
        self.assertFalse(verify_outcome(receipt, KEY, contract=CONTRACT,
                                        now=datetime.now(timezone.utc) + timedelta(hours=1)))
        self.assertFalse(verify_outcome(receipt, KEY, contract=CONTRACT,
                                        now=datetime.now(timezone.utc) - timedelta(hours=1)))
        self.assertFalse(verify_outcome(receipt, KEY, contract=CONTRACT,
                                        max_age_seconds=-1))

    def test_signed_success_without_hmac_rejected(self):
        receipt = {"statement": {"_type": "https://in-toto.io/Statement/v1",
                  "predicateType": "custom", "predicate": {"status": "verified"}},
                   "witness_hmac_sha256": "0" * 64}
        self.assertFalse(verify_outcome(receipt, KEY))


if __name__ == "__main__":
    unittest.main()
