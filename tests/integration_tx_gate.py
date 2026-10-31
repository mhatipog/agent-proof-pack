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
from agentproof.tx_effect import observe_transaction, verify_transaction_receipt, CONTRACT_SCHEMA

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
            c.execute("GRANT SELECT ON agentproof_guard.committed_actions, agentproof_guard.row_effects, agentproof_guard.action_grants TO effect_reader")
            c.execute("GRANT USAGE ON SCHEMA agentproof_guard TO effect_reader")

    def setUp(self):
        with psycopg.connect(ADMIN) as c:
            # Only installer can toggle guarded fixture triggers to reset
            # the ephemeral tables between tests. Actor has no DDL rights.
            for table in ("customers", "invoices"):
                c.execute(f"ALTER TABLE public.{table} DISABLE TRIGGER USER")
            c.execute("TRUNCATE public.customers, public.invoices")
            c.execute("DELETE FROM agentproof_guard.active_actions")
            c.execute("DELETE FROM agentproof_guard.row_effects")
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

    def tx_contract(self, action, *, customer="C-42", before="open", after="won"):
        return {
            "schema": CONTRACT_SCHEMA,
            "id": "crm_status_tx",
            "action_id": str(action),
            "executor_role": "effect_actor",
            "customer_id": customer,
            "from_status": before,
            "to_status": after,
        }

    def tx_witness(self, action, *, customer="C-42", before="open", after="won"):
        return observe_transaction(READER, self.tx_contract(
            action, customer=customer, before=before, after=after), KEY)

    def test_transaction_bound_witness_without_whole_table_scan(self):
        action = self.grant()
        self.assertEqual(self.tx_witness(action)["statement"]["predicate"]["status"], "failed")
        self.assertEqual(self.act(action), "applied")
        result = self.tx_witness(action)
        self.assertEqual(result["statement"]["predicate"]["status"], "verified")
        self.assertTrue(verify_transaction_receipt(result, KEY))
        self.assertNotIn("C-42", repr(result))
        with psycopg.connect(READER) as c:
            row = c.execute("""
                SELECT transaction_id FROM agentproof_guard.row_effects WHERE action_id=%s
            """, (action,)).fetchone()
        self.assertEqual(row[0], self.committed(action)[4])

    def test_transaction_event_invisible_until_actual_commit(self):
        action = self.grant()
        with psycopg.connect(AGENT) as c:
            self.assertEqual(c.execute(
                "SELECT agentproof_guard.apply_customer_status(%s)", (action,)
            ).fetchone()[0], "applied")
            # The function returned, but the caller has not committed yet.
            self.assertEqual(self.tx_witness(action)["statement"]["predicate"]["status"], "failed")
        self.assertEqual(self.tx_witness(action)["statement"]["predicate"]["status"], "verified")

    def test_two_concurrent_approved_actions_have_independent_proofs(self):
        from concurrent.futures import ThreadPoolExecutor
        # A whole-table before/after observer for C-42 will conservatively fail
        # when an unrelated legitimate C-99 change happens in the interval.
        before_snapshot = capture_postgres(READER, CONTRACT, KEY)
        first = self.grant(customer="C-42")
        second = self.grant(customer="C-99")
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(self.act, (first, second)))
        self.assertEqual(result, ["applied", "applied"])
        self.assertEqual(self.tx_witness(first)["statement"]["predicate"]["status"], "verified")
        self.assertEqual(self.tx_witness(second, customer="C-99")
                         ["statement"]["predicate"]["status"], "verified")
        old = reconcile_postgres(READER, CONTRACT, before_snapshot, KEY)
        self.assertEqual(old["statement"]["predicate"]["status"], "failed")

    def test_later_authorized_update_does_not_invalidate_previous_proof(self):
        first = self.grant()
        self.act(first)
        second = self.grant(before="won", after="closed")
        self.act(second)
        self.assertEqual(self.tx_witness(first)["statement"]["predicate"]["status"], "verified")
        self.assertEqual(self.tx_witness(second, before="won", after="closed")
                         ["statement"]["predicate"]["status"], "verified")
        self.assertEqual(self.state(), ("closed", 100))

    def test_rolled_back_action_has_no_transaction_proof(self):
        action = self.grant()
        with psycopg.connect(ADMIN) as c:
            c.execute("GRANT UPDATE ON public.customers TO effect_actor")
        try:
            with self.assertRaises(psycopg.Error):
                with psycopg.connect(AGENT) as c:
                    c.execute("SELECT agentproof_guard.apply_customer_status(%s)", (action,))
                    c.execute("UPDATE public.customers SET status='won' WHERE id='C-99'")
            self.assertEqual(self.tx_witness(action)["statement"]["predicate"]["status"], "failed")
            self.assertFalse(self.consumed(action))
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("REVOKE UPDATE ON public.customers FROM effect_actor")

    def test_later_before_trigger_rewrite_cannot_create_false_proof(self):
        # PostgreSQL BEFORE triggers run in name order. The approval guard
        # originally saw a valid proposed status; this later trigger changes
        # the final stored row. The AFTER guard must abort the entire action.
        with psycopg.connect(ADMIN) as c:
            c.execute("""
              CREATE FUNCTION public.rewrite_approved_status() RETURNS trigger
              LANGUAGE plpgsql AS $
              BEGIN
                NEW.status := 'lost';
                RETURN NEW;
              END; $;
            """)
            c.execute("""
              CREATE TRIGGER zz_rewrite_status BEFORE UPDATE ON public.customers
              FOR EACH ROW EXECUTE FUNCTION public.rewrite_approved_status();
            """)
        action = self.grant()
        try:
            with self.assertRaises(psycopg.Error):
                self.act(action)
            self.assertEqual(self.state(), ("open", 100))
            self.assertFalse(self.consumed(action))
            self.assertEqual(self.tx_witness(action)["statement"]["predicate"]["status"], "failed")
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("DROP TRIGGER zz_rewrite_status ON public.customers")
                c.execute("DROP FUNCTION public.rewrite_approved_status()")

    def test_disabled_after_evidence_trigger_fails_closed(self):
        # This is protection against accidental misconfiguration, not a
        # defense against a malicious table owner or superuser.
        with psycopg.connect(ADMIN) as c:
            c.execute("ALTER TABLE public.customers DISABLE TRIGGER agentproof_customer_effect")
        action = self.grant()
        try:
            with self.assertRaises(psycopg.Error):
                self.act(action)
            self.assertEqual(self.state(), ("open", 100))
            self.assertEqual(self.tx_witness(action)["statement"]["predicate"]["status"], "failed")
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("ALTER TABLE public.customers ENABLE TRIGGER agentproof_customer_effect")

    def test_missing_row_evidence_fails_even_if_commit_receipt_remains(self):
        action = self.grant()
        self.act(action)
        with psycopg.connect(ADMIN) as c:
            c.execute("DELETE FROM agentproof_guard.row_effects WHERE action_id=%s", (action,))
        self.assertEqual(self.tx_witness(action)["statement"]["predicate"]["status"], "failed")

    def test_unprivileged_actor_cannot_forge_effect_record(self):
        action = self.grant()
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(AGENT) as c:
                c.execute("""
                    INSERT INTO agentproof_guard.row_effects
                    (action_id, transaction_id, customer_id, from_status, to_status)
                    VALUES (%s, 1234, 'C-42', 'open', 'won')
                """, (action,))
        self.assertEqual(self.tx_witness(action)["statement"]["predicate"]["status"], "failed")

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

    def test_approved_function_followed_by_unapproved_write_rolls_back_both(self):
        # An actor might wrap the approved function and another statement
        # in one caller-managed transaction. The private context must be
        # cleared before the function returns, not only at final COMMIT.
        action = self.grant()
        with psycopg.connect(ADMIN) as c:
            c.execute("GRANT UPDATE ON public.customers TO effect_actor")
        try:
            with self.assertRaises(psycopg.Error):
                with psycopg.connect(AGENT) as c:
                    self.assertEqual(c.execute(
                        "SELECT agentproof_guard.apply_customer_status(%s)",
                        (action,)).fetchone()[0], "applied")
                    c.execute("UPDATE public.customers SET status='won' WHERE id='C-99'")
            self.assertEqual(self.state(), ("open", 100))
            self.assertFalse(self.consumed(action))
            self.assertIsNone(self.committed(action))
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
