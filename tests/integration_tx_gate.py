"""Real PostgreSQL transaction effect gate, isolated test database only.

Runs in GitHub Actions with ephemeral postgres:16; actor has EXECUTE-only
rights. Installer/approver uses admin privileges exclusively for fixture setup.
"""
from __future__ import annotations
import os
import pathlib
import uuid
import unittest
from datetime import datetime, timedelta, timezone

import psycopg

from agentproof.postgres_effect import capture_postgres, reconcile_postgres
from agentproof.effect import verify_witness

ADMIN = os.getenv("AGENTPROOF_GATE_TEST_ADMIN_DSN")
AGENT = os.getenv("AGENTPROOF_GATE_TEST_ACTOR_DSN")
READER = os.getenv("AGENTPROOF_GATE_TEST_READER_DSN")
KEY = "isolated-test-witness-key-never-use-in-production-2026"
ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = {
    "schema": "agent-proof-pack/effect-contract/v2", "id": "guarded_status",
    "watch_tables": ["customers", "invoices"],
    "target": {"table": "customers", "key_column": "id", "key": "C-42",
               "expected": {"status": "won"}, "allowed_columns": ["status"],
               "require_change": True},
}


@unittest.skipUnless(ADMIN and AGENT and READER, "isolated PostgreSQL gate service required")
class TransactionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ADMIN or not AGENT or not READER:
            return
        with psycopg.connect(ADMIN) as c:
            c.execute("CREATE TABLE public.customers(id text primary key, status text not null, owner text not null)")
            c.execute("CREATE TABLE public.invoices(id text primary key, amount integer not null)")
        install = (ROOT / "examples/postgres_tx_guard/install.sql").read_text(encoding="utf8")
        with psycopg.connect(ADMIN, autocommit=True) as c:
            c.execute(install)
            c.execute("REVOKE ALL ON public.customers, public.invoices FROM PUBLIC")
            c.execute("GRANT USAGE ON SCHEMA agentproof_guard TO effect_actor")
            c.execute("GRANT EXECUTE ON FUNCTION agentproof_guard.apply_customer_status(uuid) TO effect_actor")
            c.execute("GRANT SELECT ON public.customers, public.invoices TO effect_reader")
            c.execute("GRANT SELECT ON agentproof_guard.committed_actions TO effect_reader")
            c.execute("GRANT USAGE ON SCHEMA agentproof_guard TO effect_reader")

    def setUp(self):
        with psycopg.connect(ADMIN) as c:
            # Only installer can toggle guarded fixture triggers to reset
            # the ephemeral tables between tests. Actor has no DDL rights.
            for table in ("customers", "invoices"):
                c.execute(f"ALTER TABLE public.{table} DISABLE TRIGGER USER")
            c.execute("TRUNCATE public.customers, public.invoices")
            c.execute("DELETE FROM agentproof_guard.active_actions")
            c.execute("DELETE FROM agentproof_guard.committed_actions")
            c.execute("DELETE FROM agentproof_guard.action_grants")
            c.execute("INSERT INTO public.customers VALUES ('C-42','open','ada'),('C-99','open','ben')")
            c.execute("INSERT INTO public.invoices VALUES ('I-1',100)")
            for table in ("customers", "invoices"):
                c.execute(f"ALTER TABLE public.{table} ENABLE TRIGGER USER")

    def grant(self, *, customer="C-42", before="open", after="won",
              role="effect_actor", expiry=120):
        action = uuid.uuid4()
        with psycopg.connect(ADMIN) as c:
            c.execute("""
                INSERT INTO agentproof_guard.action_grants
                  (action_id, customer_id, executor_role, from_status, to_status, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (action, customer, role, before, after,
                  datetime.now(timezone.utc) + timedelta(seconds=expiry)))
        return action

    def act(self, action):
        with psycopg.connect(AGENT) as c:
            return c.execute("SELECT agentproof_guard.apply_customer_status(%s)", (action,)).fetchone()[0]

    def state(self):
        with psycopg.connect(ADMIN) as c:
            customer = c.execute("SELECT status FROM public.customers WHERE id='C-42'").fetchone()[0]
            invoice = c.execute("SELECT amount FROM public.invoices WHERE id='I-1'").fetchone()[0]
        return customer, invoice

    def consumed(self, action):
        with psycopg.connect(ADMIN) as c:
            return c.execute("SELECT consumed_at IS NOT NULL FROM agentproof_guard.action_grants WHERE action_id=%s", (action,)).fetchone()[0]

    def committed(self, action):
        with psycopg.connect(READER) as c:
            return c.execute("""
                SELECT executor_role, customer_id, from_status, to_status, transaction_id
                FROM agentproof_guard.committed_actions WHERE action_id=%s
            """, (action,)).fetchone()

    def test_simultaneous_attempts_only_one_can_commit(self):
        from concurrent.futures import ThreadPoolExecutor
        action = self.grant()
        def attempt(_):
            try:
                return self.act(action)
            except psycopg.Error:
                return "refused"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, range(2)))
        self.assertCountEqual(outcomes, ["applied", "refused"])
        self.assertEqual(self.state(), ("won", 100))
        self.assertTrue(self.consumed(action))
        self.assertIsNotNone(self.committed(action))

    def test_authorized_update_and_independent_witness(self):
        before = capture_postgres(READER, CONTRACT, KEY)
        action = self.grant()
        self.assertEqual(self.act(action), "applied")
        result = reconcile_postgres(READER, CONTRACT, before, KEY)
        self.assertEqual(result["statement"]["predicate"]["status"], "verified")
        self.assertTrue(verify_witness(result, KEY))
        self.assertEqual(self.state(), ("won", 100))
        self.assertTrue(self.consumed(action))
        self.assertEqual(self.committed(action)[:4], ("effect_actor", "C-42", "open", "won"))

    def test_direct_write_forbidden_by_privileges(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(AGENT) as c:
                c.execute("UPDATE public.customers SET status='won' WHERE id='C-42'")
        self.assertEqual(self.state(), ("open", 100))

    def test_forged_session_variable_cannot_authorize_write(self):
        # Even if an operator accidentally gives direct UPDATE privileges,
        # the trigger does NOT trust spoofable transaction-local GUCs.
        with psycopg.connect(ADMIN) as c:
            c.execute("GRANT UPDATE ON public.customers TO effect_actor")
        try:
            with self.assertRaises(psycopg.Error):
                with psycopg.connect(AGENT) as c:
                    c.execute("SELECT pg_catalog.set_config('agentproof_guard.action_id', %s, true)",
                              (str(self.grant()),))
                    c.execute("UPDATE public.customers SET status='won' WHERE id='C-42'")
            self.assertEqual(self.state(), ("open", 100))
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("REVOKE UPDATE ON public.customers FROM effect_actor")

    def test_one_time_grant_replay_denied(self):
        action = self.grant()
        self.act(action)
        with self.assertRaises(psycopg.Error):
            self.act(action)
        self.assertTrue(self.consumed(action))
        self.assertEqual(self.state(), ("won", 100))

    def test_expired_grant_rejected(self):
        action = self.grant(expiry=-10)
        with self.assertRaises(psycopg.Error):
            self.act(action)
        self.assertEqual(self.state(), ("open", 100))
        self.assertFalse(self.consumed(action))
        self.assertIsNone(self.committed(action))

    def test_wrong_executor_role_denied(self):
        action = self.grant(role="some_other_role")
        with self.assertRaises(psycopg.Error):
            self.act(action)
        self.assertFalse(self.consumed(action))

    def test_missing_grant_denied(self):
        with self.assertRaises(psycopg.Error):
            self.act(uuid.uuid4())

    def test_stale_expected_status_rolls_back(self):
        action = self.grant(before="pending")
        with self.assertRaises(psycopg.Error):
            self.act(action)
        self.assertEqual(self.state(), ("open", 100))
        self.assertFalse(self.consumed(action))

    def test_admin_cannot_accidentally_modify_invoice(self):
        # With sandbox guard installed even admin-side writes require
        # intentionally disabling the trigger: no silent collateral effects.
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(ADMIN) as c:
                c.execute("UPDATE public.invoices SET amount=0 WHERE id='I-1'")
        self.assertEqual(self.state(), ("open", 100))

    def test_trigger_generated_invoice_change_rolls_back_whole_action(self):
        with psycopg.connect(ADMIN) as c:
            c.execute("""
              CREATE FUNCTION public.inject_invoice() RETURNS trigger
              LANGUAGE plpgsql AS $$
              BEGIN
                UPDATE public.invoices SET amount=0 WHERE id='I-1';
                RETURN NEW;
              END; $$;
            """)
            c.execute("""
              CREATE TRIGGER zz_inject_invoice AFTER UPDATE ON public.customers
              FOR EACH ROW EXECUTE FUNCTION public.inject_invoice();
            """)
        try:
            action = self.grant()
            with self.assertRaises(psycopg.Error):
                self.act(action)
            self.assertEqual(self.state(), ("open", 100))
            self.assertFalse(self.consumed(action))
            self.assertIsNone(self.committed(action))
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("DROP TRIGGER zz_inject_invoice ON public.customers")
                c.execute("DROP FUNCTION public.inject_invoice()")
        # The failed transaction must not consume its grant.
        self.assertEqual(self.act(action), "applied")
        self.assertEqual(self.state(), ("won", 100))
        self.assertIsNotNone(self.committed(action))

    def test_trigger_generated_other_customer_change_rolls_back(self):
        with psycopg.connect(ADMIN) as c:
            c.execute("""
              CREATE FUNCTION public.inject_customer() RETURNS trigger
              LANGUAGE plpgsql AS $$
              BEGIN
                UPDATE public.customers SET status='won' WHERE id='C-99';
                RETURN NEW;
              END; $$;
            """)
            c.execute("""
              CREATE TRIGGER zz_inject_customer AFTER UPDATE ON public.customers
              FOR EACH ROW WHEN (NEW.id='C-42')
              EXECUTE FUNCTION public.inject_customer();
            """)
        try:
            action = self.grant()
            with self.assertRaises(psycopg.Error):
                self.act(action)
            self.assertEqual(self.state(), ("open", 100))
            self.assertFalse(self.consumed(action))
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("DROP TRIGGER zz_inject_customer ON public.customers")
                c.execute("DROP FUNCTION public.inject_customer()")

    def test_truncate_refused(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(ADMIN) as c:
                c.execute("TRUNCATE public.invoices")
        self.assertEqual(self.state(), ("open", 100))

    def test_grants_hidden_from_agent(self):
        action = self.grant()
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(AGENT) as c:
                c.execute("SELECT * FROM agentproof_guard.action_grants")
        self.assertFalse(self.consumed(action))


if __name__ == "__main__":
    unittest.main()
