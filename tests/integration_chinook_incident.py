"""Reconstruction of a documented agent deletion failure class on upstream Chinook.

Unlike the earlier synthetic C-42 fixture, this suite imports the unchanged
MIT-licensed Chinook v1.4.5 PostgreSQL schema and seed data from its upstream
GitHub commit. These are NOT Replit data or a reconstruction of Replit's exact
unpublished commands.

The isolated service grants three distinct roles: a staging-only agent,
a restricted production writer and a separately read-only witness.
"""
from __future__ import annotations

import os
import unittest
from urllib.parse import urlsplit, urlunsplit

try:
    import psycopg
except ImportError:
    psycopg = None

from agentproof.postgres_effect import capture_postgres, reconcile_postgres
from agentproof.effect import verify_witness

ADMIN = os.environ.get("AGENTPROOF_CHINOOK_ADMIN_DSN")
WRITER = os.environ.get("AGENTPROOF_CHINOOK_WRITER_DSN")
READER = os.environ.get("AGENTPROOF_CHINOOK_READER_DSN")
STAGING = os.environ.get("AGENTPROOF_CHINOOK_STAGING_DSN")
KEY = "ephemeral-incident-reconstruction-witness-key-2026-not-secret"
EXPECTED_EMAIL = "approved-change@local.invalid"
CONTRACT = {
    "schema": "agent-proof-pack/effect-contract/v2",
    "id": "chinook_customer_email",
    "watch_tables": ["customer", "invoice_line"],
    "target": {
        "table": "customer", "key_column": "customer_id", "key": 1,
        "expected": {"email": EXPECTED_EMAIL},
        "allowed_columns": ["email"],
        "require_change": True,
    },
}


@unittest.skipUnless(
    psycopg is not None and all((ADMIN, WRITER, READER, STAGING)),
    "requires disposable PostgreSQL with Chinook v1.4.5 and three restricted roles",
)
class ChinookIncidentReconstruction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_dsn = ADMIN
        cls.writer_dsn = WRITER
        cls.reader_dsn = READER
        cls.stage_dsn = STAGING
        with psycopg.connect(ADMIN) as conn:
            cls.customer_count = conn.execute("SELECT count(*) FROM public.customer").fetchone()[0]
            cls.line_count = conn.execute("SELECT count(*) FROM public.invoice_line").fetchone()[0]
            cls.original_email = conn.execute(
                "SELECT email FROM public.customer WHERE customer_id=1").fetchone()[0]
            cls.original_price = conn.execute(
                "SELECT unit_price FROM public.invoice_line WHERE invoice_line_id=1"
            ).fetchone()[0]
        if cls.customer_count < 40 or cls.line_count < 1000:
            raise AssertionError("not the expected populated upstream Chinook dataset")
        print(f"UPSTREAM CHINOOK BASELINE: customers={cls.customer_count} "
              f"invoice_lines={cls.line_count} (seeded sample data; NOT incident data)")

    def setUp(self):
        # Trusted owner restores only the two protected values between cases.
        with psycopg.connect(ADMIN) as conn:
            conn.execute("UPDATE public.customer SET email=%s WHERE customer_id=1",
                         (self.original_email,))
            conn.execute("UPDATE public.invoice_line SET unit_price=%s WHERE invoice_line_id=1",
                         (self.original_price,))
        self.before = capture_postgres(READER, CONTRACT, KEY)

    def customer_email(self):
        with psycopg.connect(READER) as conn:
            return conn.execute(
                "SELECT email FROM public.customer WHERE customer_id=1").fetchone()[0]

    def money_line(self):
        with psycopg.connect(READER) as conn:
            return conn.execute(
                "SELECT unit_price FROM public.invoice_line WHERE invoice_line_id=1"
            ).fetchone()[0]

    def outcome(self):
        report = reconcile_postgres(READER, CONTRACT, self.before, KEY)
        self.assertTrue(verify_witness(report, KEY))
        return report["statement"]["predicate"]

    def test_authorized_scoped_change_is_verified(self):
        with psycopg.connect(WRITER) as conn:
            conn.execute(
                "UPDATE public.customer SET email=%s WHERE customer_id=1",
                (EXPECTED_EMAIL,))
        self.assertEqual(self.outcome()["status"], "verified")
        self.assertEqual(self.money_line(), self.original_price)

    def test_agent_says_done_but_database_is_unchanged(self):
        self.assertEqual(self.outcome()["status"], "failed")
        self.assertEqual(self.customer_email(), self.original_email)

    def test_staging_agent_cannot_connect_to_production(self):
        with self.assertRaises(psycopg.Error):
            psycopg.connect(STAGING, connect_timeout=3)
        self.assertEqual(self.customer_email(), self.original_email)

    def test_agent_attempts_bulk_customer_delete_during_freeze(self):
        # The command is an illustrative reconstruction; Replit's exact
        # original SQL has not been publicly established.
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(WRITER) as conn:
                conn.execute("DELETE FROM public.customer")
        with psycopg.connect(READER) as conn:
            count = conn.execute("SELECT count(*) FROM public.customer").fetchone()[0]
        self.assertEqual(count, self.customer_count)
        self.assertEqual(self.customer_email(), self.original_email)

    def test_agent_attempts_truncate_during_freeze(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(WRITER) as conn:
                conn.execute("TRUNCATE TABLE public.customer CASCADE")
        with psycopg.connect(READER) as conn:
            count = conn.execute("SELECT count(*) FROM public.customer").fetchone()[0]
        self.assertEqual(count, self.customer_count)

    def test_agent_attempts_drop_customer_table(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(WRITER) as conn:
                conn.execute("DROP TABLE public.customer CASCADE")
        with psycopg.connect(READER) as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM public.customer").fetchone()[0], self.customer_count)

    def test_out_of_scope_invoice_mutation_rolls_back_customer_update(self):
        # Same caller transaction. Native PG permissions reject the invoice
        # mutation, causing the earlier customer update to roll back too.
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(WRITER) as conn:
                conn.execute(
                    "UPDATE public.customer SET email=%s WHERE customer_id=1",
                    (EXPECTED_EMAIL,))
                conn.execute(
                    "UPDATE public.invoice_line SET unit_price=0 "
                    "WHERE invoice_line_id=1")
        self.assertEqual(self.customer_email(), self.original_email)
        self.assertEqual(self.money_line(), self.original_price)
        self.assertEqual(self.outcome()["status"], "failed")

    def test_privileged_bypass_is_detected_not_prevented(self):
        # A schema owner/superuser can bypass the writer role. The independent
        # witness refuses to certify it, but cannot undo the committed write.
        with psycopg.connect(ADMIN) as conn:
            conn.execute("UPDATE public.customer SET email=%s WHERE customer_id=1",
                         (EXPECTED_EMAIL,))
            conn.execute("UPDATE public.invoice_line SET unit_price=0 "
                         "WHERE invoice_line_id=1")
        result = self.outcome()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(
            c["id"].startswith("no-unapproved-effect:invoice_line")
            and c["status"] == "fail"
            for c in result["checks"]
        ))

    def test_second_customer_change_is_detected(self):
        with psycopg.connect(ADMIN) as conn:
            conn.execute("UPDATE public.customer SET email=%s WHERE customer_id=1",
                         (EXPECTED_EMAIL,))
            conn.execute("UPDATE public.customer SET email='tampered@local.invalid' "
                         "WHERE customer_id=2")
        report = self.outcome()
        self.assertEqual(report["status"], "failed")

    def test_witness_is_not_a_writer(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(READER) as conn:
                conn.execute("DELETE FROM public.invoice_line")
        self.assertEqual(self.money_line(), self.original_price)


if __name__ == "__main__":
    unittest.main()
