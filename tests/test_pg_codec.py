"""PostgreSQL value codec tests; these need no PostgreSQL server."""
import unittest
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from uuid import UUID

from agentproof.effect import EffectError, _validate_contract
from agentproof.pg_codec import pg_type_kind, normalize_pg_value

SAMPLE = {
    "schema": "agent-proof-pack/effect-contract/v2",
    "id": "typed_demo",
    "watch_tables": ["customers"],
    "target": {
        "table": "customers", "key_column": "id",
        "key": "36f66976-1e4c-4d34-a571-4d086e7c0c3f",
        "expected": {"active": True}, "allowed_columns": ["active"],
        "require_change": True,
    }
}


class PostgreSQLCodecTests(unittest.TestCase):
    def test_uuid_object_matches_canonical_json_string(self):
        raw = UUID("36f66976-1e4c-4d34-a571-4d086e7c0c3f")
        self.assertEqual(normalize_pg_value(raw, "uuid"),
                         normalize_pg_value(str(raw).upper(), "uuid", from_contract=True))

    def test_numeric_preserves_all_significant_digits_under_low_decimal_context(self):
        exact = "123456789012345678901234567890123456789.123456789012345678901234567890"
        with localcontext() as ctx:
            ctx.prec = 8
            self.assertEqual(normalize_pg_value(Decimal(exact), "numeric(80,30)"),
                             normalize_pg_value(exact, "numeric(80,30)", from_contract=True))
        self.assertNotEqual(normalize_pg_value("8421.37000001", "numeric", from_contract=True),
                            normalize_pg_value(Decimal("8421.37"), "numeric"))
        self.assertEqual(normalize_pg_value(Decimal("-0.00"), "numeric"),
                         normalize_pg_value("0", "numeric", from_contract=True))

    def test_numeric_refuses_float_and_nonfinite(self):
        for value in [8421.37, "NaN", "Infinity", "4,200"]:
            with self.subTest(value=value), self.assertRaises(EffectError):
                normalize_pg_value(value, "numeric", from_contract=True)
        with self.assertRaises(EffectError):
            normalize_pg_value(Decimal("NaN"), "numeric")

    def test_timestamps_compare_as_same_absolute_instant(self):
        observed = datetime(2026, 10, 31, 11, 30, tzinfo=timezone.utc)
        expected = "2026-10-31T12:30:00+01:00"
        self.assertEqual(normalize_pg_value(observed, "timestamp(6) with time zone"),
                         normalize_pg_value(expected, "timestamp with time zone", from_contract=True))
        with self.assertRaises(EffectError):
            normalize_pg_value("2026-10-31T11:30:00", "timestamp with time zone", from_contract=True)

    def test_boolean_must_be_boolean(self):
        self.assertEqual(normalize_pg_value(True, "boolean"),
                         normalize_pg_value(True, "boolean", from_contract=True))
        for bad in [1, 0, "true", "1"]:
            with self.subTest(bad=bad), self.assertRaises(EffectError):
                normalize_pg_value(bad, "boolean", from_contract=True)

    def test_unknown_column_type_rejected_even_for_null(self):
        for kind in ["jsonb", "timestamp without time zone", "date", "text[]", "mystery_domain"]:
            with self.subTest(kind=kind), self.assertRaises(EffectError):
                normalize_pg_value(None, kind)

    def test_pg_boolean_contract_keeps_sqlite_restriction(self):
        _validate_contract(SAMPLE, backend="postgresql")
        with self.assertRaises(EffectError):
            _validate_contract(SAMPLE)
    
    def test_type_precision_recognition(self):
        for name in ["numeric(18,2)", "character varying(255)", "timestamp(3) with time zone",
                     "boolean", "uuid", "double precision", "bytea"]:
            with self.subTest(name=name):
                self.assertIsInstance(pg_type_kind(name), str)


if __name__ == "__main__":
    unittest.main()
