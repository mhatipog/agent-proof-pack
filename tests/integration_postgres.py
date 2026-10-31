"""Integration checks against an ephemeral real PostgreSQL service.

Run only with AGENTPROOF_TEST_ADMIN_DSN and AGENTPROOF_TEST_READER_DSN.
The two users MUST be different. Never use customer/production databases.
"""
import copy
import os
import unittest
from agentproof.effect import EffectError, verify_witness
from agentproof.postgres_effect import capture_postgres, reconcile_postgres

try:
    import psycopg
except ImportError:
    psycopg = None

ADMIN = os.environ.get('AGENTPROOF_TEST_ADMIN_DSN')
READER = os.environ.get('AGENTPROOF_TEST_READER_DSN')
KEY = 'test-only-separated-observer-key-2026-very-long'
CONTRACT = {
    'schema': 'agent-proof-pack/effect-contract/v2',
    'id': 'customer_status', 'watch_tables': ['customers', 'invoices'],
    'target': {
        'table': 'customers', 'key_column': 'id', 'key': 'C-42',
        'expected': {'status': 'won'}, 'allowed_columns': ['status'],
        'require_change': True,
    },
}


@unittest.skipUnless(psycopg is not None and ADMIN and READER, 'requires real PG service and separated credentials')
class PostgreSQLRealIntegration(unittest.TestCase):
    def setUp(self):
        if ADMIN == READER:
            self.fail('test requires different admin and reader connections')
        with psycopg.connect(ADMIN) as conn:
            conn.execute('DROP TABLE IF EXISTS public.customers CASCADE')
            conn.execute('DROP TABLE IF EXISTS public.invoices CASCADE')
            conn.execute('CREATE TABLE public.customers (id TEXT PRIMARY KEY, status TEXT NOT NULL, owner TEXT)')
            conn.execute('CREATE TABLE public.invoices (id TEXT PRIMARY KEY, amount INTEGER NOT NULL)')
            conn.execute("INSERT INTO public.customers VALUES ('C-42','open','ada'),('C-99','open','ben')")
            conn.execute("INSERT INTO public.invoices VALUES ('I-1',100)")
            conn.execute('GRANT SELECT ON public.customers, public.invoices TO witness_reader')
        self.before = capture_postgres(READER, CONTRACT, KEY, now=1000)
    def change(self, query):
        with psycopg.connect(ADMIN) as conn:
            conn.execute(query)
    def result(self, *, before=None, contract=None):
        return reconcile_postgres(READER, contract or CONTRACT,
                                  before or self.before, KEY, now=1001)
    def verdict(self):
        result = self.result()
        self.assertTrue(verify_witness(result, KEY))
        self.assertEqual(result['statement']['predicate']['backend'], 'postgresql')
        return result['statement']['predicate']['status']
    def test_correct_update(self):
        self.change("UPDATE public.customers SET status='won' WHERE id='C-42'")
        self.assertEqual(self.verdict(), 'verified')
    def test_silent_noop(self):
        self.assertEqual(self.verdict(), 'failed')
    def test_collateral_invoice_update(self):
        self.change("UPDATE public.customers SET status='won' WHERE id='C-42'")
        self.change("UPDATE public.invoices SET amount=0 WHERE id='I-1'")
        self.assertEqual(self.verdict(), 'failed')
    def test_unauthorized_other_customer_update(self):
        self.change("UPDATE public.customers SET status='won' WHERE id='C-42'")
        self.change("UPDATE public.customers SET status='lost' WHERE id='C-99'")
        self.assertEqual(self.verdict(), 'failed')
    def test_wrong_record(self):
        self.change("UPDATE public.customers SET status='won' WHERE id='C-99'")
        self.assertEqual(self.verdict(), 'failed')
    def test_insert_collateral(self):
        self.change("UPDATE public.customers SET status='won' WHERE id='C-42'")
        self.change("INSERT INTO public.invoices VALUES ('I-2',999)")
        self.assertEqual(self.verdict(), 'failed')
    def test_schema_change_detected(self):
        self.change("ALTER TABLE public.invoices ADD COLUMN note TEXT")
        self.change("UPDATE public.customers SET status='won' WHERE id='C-42'")
        self.assertEqual(self.verdict(), 'failed')
    def test_index_change_detected(self):
        self.change('CREATE INDEX idx_invoice_amount ON public.invoices(amount)')
        self.change("UPDATE public.customers SET status='won' WHERE id='C-42'")
        self.assertEqual(self.verdict(), 'failed')
    def test_constraint_change_detected(self):
        self.change("ALTER TABLE public.invoices ADD CONSTRAINT ck_nonnegative CHECK(amount >= 0)")
        self.change("UPDATE public.customers SET status='won' WHERE id='C-42'")
        self.assertEqual(self.verdict(), 'failed')
    def test_rls_denies_partial_visibility(self):
        self.change('ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY')
        with self.assertRaises(EffectError):
            self.result()
    def test_reader_cannot_write(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(READER) as conn:
                conn.execute("DELETE FROM public.invoices WHERE id='I-1'")
    def test_wrong_backend_cannot_replay_snapshot(self):
        from agentproof.effect import reconcile
        with self.assertRaises(EffectError):
            reconcile(None, CONTRACT, self.before, KEY, now=1001, reader=lambda *_: {})
    def test_contract_modified_fails_closed(self):
        c = copy.deepcopy(CONTRACT)
        c['target']['allowed_columns'].append('owner')
        with self.assertRaises(EffectError):
            self.result(contract=c)
    def test_reader_snapshot_does_not_contain_plaintext(self):
        blob = repr(self.before)
        self.assertNotIn('C-42', blob)
        self.assertNotIn('I-1', blob)
        self.assertNotIn("'won'", blob)

    def prepare_typed_schema(self):
        """Realistic CRM + invoice tables, with independently readable PG types."""
        import uuid
        from datetime import datetime, timezone
        from decimal import Decimal
        customer_id = uuid.UUID("36f66976-1e4c-4d34-a571-4d086e7c0c3f")
        invoice_id = uuid.UUID("7dd57212-76d2-49d8-8bc7-3724f42e5d90")
        with psycopg.connect(ADMIN) as conn:
            conn.execute("DROP TABLE public.customers CASCADE")
            conn.execute("DROP TABLE public.invoices CASCADE")
            conn.execute("""
              CREATE TABLE public.customers (
                id UUID PRIMARY KEY, status TEXT NOT NULL,
                balance NUMERIC(80,30) NOT NULL, active BOOLEAN NOT NULL,
                touched_at TIMESTAMPTZ NOT NULL
              )""")
            conn.execute("""
              CREATE TABLE public.invoices (
                id UUID PRIMARY KEY, amount NUMERIC(80,30) NOT NULL
              )""")
            conn.execute("""
              INSERT INTO public.customers
                (id,status,balance,active,touched_at) VALUES (%s,%s,%s,%s,%s)
              """, (customer_id, "open", Decimal("1.000"), False,
                    datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc)))
            conn.execute("INSERT INTO public.invoices VALUES (%s,%s)",
                         (invoice_id, Decimal("100.00")))
            conn.execute("GRANT SELECT ON public.customers, public.invoices TO witness_reader")
        contract = {
            "schema": "agent-proof-pack/effect-contract/v2",
            "id": "crm_typed", "watch_tables": ["customers", "invoices"],
            "target": {
                "table": "customers", "key_column": "id", "key": str(customer_id),
                "expected": {
                    "status": "won", "balance": "8421.370000000000000000000000000000",
                    "active": True, "touched_at": "2026-10-31T12:30:00+01:00",
                },
                "allowed_columns": ["status", "balance", "active", "touched_at"],
                "require_change": True,
            },
        }
        return customer_id, invoice_id, contract, capture_postgres(READER, contract, KEY, now=1000)

    def apply_typed_change(self, customer_id):
        from datetime import datetime, timezone
        from decimal import Decimal
        with psycopg.connect(ADMIN) as conn:
            conn.execute("""
              UPDATE public.customers
                SET status='won', balance=%s, active=TRUE, touched_at=%s
                WHERE id=%s
              """, (Decimal("8421.37"), datetime(2026, 10, 31, 11, 30,
                                                  tzinfo=timezone.utc), customer_id))

    def test_typed_schema_correct_effect_verifies(self):
        customer_id, _, contract, before = self.prepare_typed_schema()
        self.apply_typed_change(customer_id)
        result = reconcile_postgres(READER, contract, before, KEY, now=1001)
        self.assertEqual(result["statement"]["predicate"]["status"], "verified")
        self.assertTrue(verify_witness(result, KEY))
        self.assertNotIn("8421.37", repr(result))
        self.assertNotIn(str(customer_id), repr(result))

    def test_typed_schema_silent_noop_fails(self):
        _, _, contract, before = self.prepare_typed_schema()
        result = reconcile_postgres(READER, contract, before, KEY, now=1001)
        self.assertEqual(result["statement"]["predicate"]["status"], "failed")

    def test_typed_schema_collateral_invoice_change_fails(self):
        customer_id, invoice_id, contract, before = self.prepare_typed_schema()
        self.apply_typed_change(customer_id)
        with psycopg.connect(ADMIN) as conn:
            conn.execute("UPDATE public.invoices SET amount=0 WHERE id=%s", (invoice_id,))
        result = reconcile_postgres(READER, contract, before, KEY, now=1001)
        self.assertEqual(result["statement"]["predicate"]["status"], "failed")

    def test_typed_schema_wrong_exact_numeric_fails(self):
        customer_id, _, contract, before = self.prepare_typed_schema()
        self.apply_typed_change(customer_id)
        with psycopg.connect(ADMIN) as conn:
            conn.execute("UPDATE public.customers SET balance=%s WHERE id=%s",
                         ("8421.370000000000000000000000000001", customer_id))
        result = reconcile_postgres(READER, contract, before, KEY, now=1001)
        self.assertEqual(result["statement"]["predicate"]["status"], "failed")

    def test_typed_schema_rejects_naive_timestamp_expectation(self):
        customer_id, _, contract, _ = self.prepare_typed_schema()
        contract["target"]["expected"]["touched_at"] = "2026-10-31T11:30:00"
        before = capture_postgres(READER, contract, KEY, now=1000)
        self.apply_typed_change(customer_id)
        with self.assertRaises(EffectError):
            reconcile_postgres(READER, contract, before, KEY, now=1001)

    def test_unsupported_null_jsonb_fails_closed(self):
        self.change("ALTER TABLE public.customers ADD COLUMN extra JSONB")
        with self.assertRaises(EffectError):
            capture_postgres(READER, CONTRACT, KEY, now=1000)



if __name__ == '__main__':
    unittest.main()
