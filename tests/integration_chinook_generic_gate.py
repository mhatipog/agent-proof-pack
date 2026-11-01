"""Generic transaction-bound gate exercised on the unchanged upstream Chinook schema.

Must run AFTER the read-only Chinook incident reconstruction in the same
disposable PostgreSQL 16 service. The tests install protected triggers and
reset sample data, so NEVER run against an existing database.
"""
from __future__ import annotations

import os
import uuid
import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

import psycopg

from agentproof.postgres_effect import capture_postgres, reconcile_postgres
from agentproof.effect import verify_witness, EffectError
from agentproof.generic_cli import apply_approved, observe_approved, verify_outcome

ADMIN = os.getenv("AGENTPROOF_CHINOOK_ADMIN_DSN")
WRITER = os.getenv("AGENTPROOF_CHINOOK_WRITER_DSN")
READER = os.getenv("AGENTPROOF_CHINOOK_READER_DSN")
KEY = "isolated-generic-witness-key-for-chinook-only-2026"
TARGET = "approved-change@local.invalid"
ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = {
    "schema": "agent-proof-pack/effect-contract/v2",
    "id": "chinook_generic_guarded_email",
    "watch_tables": ["customer", "invoice_line"],
    "target": {
        "table": "customer", "key_column": "customer_id", "key": 1,
        "expected": {"email": TARGET}, "allowed_columns": ["email"],
        "require_change": True,
    },
}


@unittest.skipUnless(
    ADMIN and WRITER and READER,
    "requires isolated upstream Chinook PG service with role isolation",
)
class GenericChinookGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with psycopg.connect(ADMIN) as c:
            cls.original_email = c.execute(
                "SELECT email FROM public.customer WHERE customer_id=1"
            ).fetchone()[0]
            cls.original_second = c.execute(
                "SELECT email FROM public.customer WHERE customer_id=2"
            ).fetchone()[0]
            cls.original_price = c.execute(
                "SELECT unit_price FROM public.invoice_line WHERE invoice_line_id=1"
            ).fetchone()[0]

        install = (ROOT / "examples/postgres_generic_gate/install.sql").read_text(
            encoding="utf8")
        with psycopg.connect(ADMIN, autocommit=True) as c:
            c.execute(install)
            c.execute("SELECT agentproof_generic.protect_table('public.customer'::regclass)")
            c.execute("SELECT agentproof_generic.protect_table('public.invoice_line'::regclass)")
            c.execute("GRANT USAGE ON SCHEMA agentproof_generic TO incident_prod_actor")
            c.execute("GRANT EXECUTE ON FUNCTION agentproof_generic.apply_text_change(uuid) TO incident_prod_actor")
            c.execute("GRANT USAGE ON SCHEMA agentproof_generic TO incident_witness_reader")
            c.execute("GRANT SELECT ON agentproof_generic.committed, agentproof_generic.grants TO incident_witness_reader")

    def setUp(self):
        # Only the trusted owner can temporarily disable these fixture guards;
        # in a production installation, this capability must never be granted
        # to the agent or its application role.
        with psycopg.connect(ADMIN) as c:
            c.execute("ALTER TABLE public.customer DISABLE TRIGGER USER")
            c.execute("ALTER TABLE public.invoice_line DISABLE TRIGGER USER")
            c.execute("UPDATE public.customer SET email=%s WHERE customer_id=1",
                      (self.original_email,))
            c.execute("UPDATE public.customer SET email=%s WHERE customer_id=2",
                      (self.original_second,))
            c.execute("UPDATE public.invoice_line SET unit_price=%s WHERE invoice_line_id=1",
                      (self.original_price,))
            c.execute("DELETE FROM agentproof_generic.active")
            c.execute("DELETE FROM agentproof_generic.committed")
            c.execute("DELETE FROM agentproof_generic.grants")
            c.execute("ALTER TABLE public.customer ENABLE TRIGGER USER")
            c.execute("ALTER TABLE public.invoice_line ENABLE TRIGGER USER")
        self.before = capture_postgres(READER, CONTRACT, KEY)

    def grant(self, *, row="1", old=None, after=TARGET, role="incident_prod_actor",
              expiry=120):
        action = uuid.uuid4()
        with psycopg.connect(ADMIN) as c:
            c.execute("""
                INSERT INTO agentproof_generic.grants
                    (action_id,target_oid,key_column,key_value,update_column,
                     old_value,new_value,executor_role,expires_at)
                VALUES (%s, 'public.customer'::regclass::oid, 'customer_id', %s,
                        'email', %s, %s, %s, %s)
            """, (action, row, old or self.original_email, after, role,
                  datetime.now(timezone.utc) + timedelta(seconds=expiry)))
        return action

    def act(self, action):
        with psycopg.connect(WRITER) as c:
            return c.execute(
                "SELECT agentproof_generic.apply_text_change(%s)",
                (action,)).fetchone()[0]

    def state(self):
        with psycopg.connect(READER) as c:
            return (
                c.execute("SELECT email FROM public.customer WHERE customer_id=1").fetchone()[0],
                c.execute("SELECT unit_price FROM public.invoice_line WHERE invoice_line_id=1").fetchone()[0],
            )

    def consumed(self, action):
        with psycopg.connect(ADMIN) as c:
            return c.execute(
                "SELECT consumed_at IS NOT NULL FROM agentproof_generic.grants "
                "WHERE action_id=%s", (action,)).fetchone()[0]

    def committed(self, action):
        with psycopg.connect(READER) as c:
            return c.execute(
                "SELECT executor_role, key_value, old_value, new_value, txid "
                "FROM agentproof_generic.committed WHERE action_id=%s",
                (action,)).fetchone()

    def proof(self):
        result = reconcile_postgres(READER, CONTRACT, self.before, KEY)
        self.assertTrue(verify_witness(result, KEY))
        return result["statement"]["predicate"]["status"]

    def test_scoped_authorized_update_commits_with_readback(self):
        a = self.grant()
        self.assertEqual(self.act(a), "applied")
        self.assertEqual(self.state(), (TARGET, self.original_price))
        self.assertEqual(self.proof(), "verified")
        self.assertTrue(self.consumed(a))
        self.assertEqual(self.committed(a)[:4],
                         ("incident_prod_actor", "1", self.original_email, TARGET))

    def generic_contract(self, action):
        return {
            "schema": "agent-proof-pack/generic-transaction-contract/v1",
            "id": "chinook_email_change", "action_id": str(action),
            "executor_role": "incident_prod_actor",
            "table": "public.customer", "key_column": "customer_id",
            "key_value": "1", "update_column": "email",
            "old_value": self.original_email, "new_value": TARGET,
        }

    def test_real_agent_tool_only_accepts_grant_uuid_and_witness_checks_actual_row(self):
        action = self.grant()
        execution = apply_approved(WRITER, str(action))
        self.assertEqual(execution["state"], "submitted_unverified")
        evidence = observe_approved(READER, self.generic_contract(action), KEY)
        self.assertEqual(evidence["statement"]["predicate"]["status"], "verified")
        self.assertTrue(verify_outcome(evidence, KEY))
        self.assertEqual(self.state(), (TARGET, self.original_price))
        self.assertTrue(self.consumed(action))

    def test_entra_authorized_action_real_postgres_and_independent_witness(self):
        """Signed identity + one-use grant + actual Chinook row effect.

        RSA tokens here are synthetic and issued by the test harness, not Entra.
        The independent live Entra token/resource-boundary experiment is separate.
        """
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from agentproof.entra import verify_access_token, AuthorizationDenied
        from agentproof.entra_guard import authorized_apply
        from datetime import datetime, timezone, timedelta

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        class FixedKeys:
            def get_signing_key_from_jwt(self, token):
                return type("SigningKey", (), {"key": key.public_key()})()

        tenant = "11111111-2222-4333-8444-555555555555"
        client = "22222222-3333-4444-8555-666666666666"
        principal = "33333333-4444-4555-8666-777777777777"
        api = "api://44444444-5555-4666-8777-888888888888"
        now = int(datetime.now(timezone.utc).timestamp())
        claims = {"ver": "2.0", "iss": f"https://login.microsoftonline.com/{tenant}/v2.0",
                  "tid": tenant, "aud": api, "oid": principal, "azp": client,
                  "roles": ["AgentProof.Apply"], "idtyp": "app",
                  "iat": now, "nbf": now - 10, "exp": now + 180}
        def sign(**overrides):
            return jwt.encode({**claims, **overrides}, key, algorithm="RS256",
                              headers={"kid": "testkey"})
        def verifier(token, policy):
            return verify_access_token(token, policy, jwk_client=FixedKeys())

        action = self.grant()
        env = {"AGENTPROOF_ENTRA_TENANT_ID": tenant,
               "AGENTPROOF_ENTRA_AUDIENCE": api,
               "AGENTPROOF_ENTRA_CLIENT_ID": client,
               "AGENTPROOF_ENTRA_PRINCIPAL_OID": principal,
               "AGENTPROOF_ENTRA_REQUIRED_ROLE": "AgentProof.Apply",
               "AGENTPROOF_ACTOR_DSN": WRITER,
               "AGENTPROOF_ENTRA_ACCESS_TOKEN": sign(roles=["AgentProof.Read"])}
        with self.assertRaises(AuthorizationDenied):
            authorized_apply(str(action), environ=env, verifier=verifier)
        self.assertFalse(self.consumed(action))
        self.assertEqual(self.state(), (self.original_email, self.original_price))
        self.assertIsNone(self.committed(action))
        env["AGENTPROOF_ENTRA_ACCESS_TOKEN"] = sign(
            oid="99999999-9999-4999-8999-999999999999")
        with self.assertRaises(AuthorizationDenied):
            authorized_apply(str(action), environ=env, verifier=verifier)
        self.assertFalse(self.consumed(action))

        env["AGENTPROOF_ENTRA_ACCESS_TOKEN"] = sign()
        execution = authorized_apply(str(action), environ=env, verifier=verifier)
        self.assertEqual(execution["state"], "submitted_unverified")
        self.assertFalse(execution["database_effect_verified"])
        self.assertEqual(self.state(), (TARGET, self.original_price))
        self.assertTrue(self.consumed(action))
        verified = observe_approved(READER, self.generic_contract(action), KEY)
        self.assertEqual(verified["statement"]["predicate"]["status"], "verified")
        self.assertTrue(verify_outcome(verified, KEY,
                                      contract=self.generic_contract(action)))

        # Same valid identity cannot replay consumed database permission.
        with self.assertRaises(EffectError):
            authorized_apply(str(action), environ=env, verifier=verifier)
        self.assertEqual(self.state(), (TARGET, self.original_price))

    def test_witness_cannot_call_missing_grant_verified(self):
        action = self.grant()
        evidence = observe_approved(READER, self.generic_contract(action), KEY)
        self.assertEqual(evidence["statement"]["predicate"]["status"], "failed")
        self.assertTrue(verify_outcome(evidence, KEY))

    def test_tampered_witness_receipt_is_detected(self):
        action = self.grant()
        apply_approved(WRITER, str(action))
        evidence = observe_approved(READER, self.generic_contract(action), KEY)
        evidence["statement"]["predicate"]["status"] = "failed"
        self.assertFalse(verify_outcome(evidence, KEY))

    def test_agent_tool_rejects_arbitrary_sql_as_action_id(self):
        with self.assertRaises(EffectError):
            apply_approved(WRITER, "UPDATE public.invoice_line SET unit_price=0")

    def test_direct_write_is_refused_even_if_actor_has_column_update_grant(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(WRITER) as c:
                c.execute("UPDATE public.customer SET email=%s WHERE customer_id=1",
                          (TARGET,))
        self.assertEqual(self.state(), (self.original_email, self.original_price))

    def test_missing_or_expired_grant_is_denied(self):
        with self.assertRaises(psycopg.Error):
            self.act(uuid.uuid4())
        a = self.grant(expiry=-10)
        with self.assertRaises(psycopg.Error):
            self.act(a)
        self.assertFalse(self.consumed(a))

    def test_code_freeze_revokes_an_already_issued_action_grant(self):
        grant = self.grant()
        # Trusted operator freezes all pending actions. Revocation is
        # committed before the actor attempts use of its old grant UUID.
        with psycopg.connect(ADMIN) as c:
            c.execute("""
                UPDATE agentproof_generic.grants
                   SET revoked_at = pg_catalog.clock_timestamp()
                 WHERE consumed_at IS NULL
            """)
        with self.assertRaises(psycopg.Error):
            self.act(grant)
        self.assertEqual(self.state(), (self.original_email, self.original_price))
        self.assertFalse(self.consumed(grant))
        self.assertIsNone(self.committed(grant))

    def test_wrong_login_role_and_stale_before_value_are_denied(self):
        a = self.grant(role="other_role")
        with self.assertRaises(psycopg.Error):
            self.act(a)
        b = self.grant(old="not-the-real-email")
        with self.assertRaises(psycopg.Error):
            self.act(b)
        self.assertEqual(self.state(), (self.original_email, self.original_price))

    def test_grant_replay_is_denied(self):
        a = self.grant()
        self.act(a)
        with self.assertRaises(psycopg.Error):
            self.act(a)
        self.assertEqual(self.proof(), "verified")

    def test_invoice_side_effect_trigger_rolls_back_customer_change_and_grant(self):
        with psycopg.connect(ADMIN) as c:
            c.execute("""
              CREATE FUNCTION public.chinook_bad_invoice() RETURNS trigger
              LANGUAGE plpgsql AS $$
              BEGIN
                UPDATE public.invoice_line SET unit_price=0 WHERE invoice_line_id=1;
                RETURN NEW;
              END; $$;
            """)
            c.execute("""
              CREATE TRIGGER zz_chinook_bad_invoice AFTER UPDATE ON public.customer
              FOR EACH ROW EXECUTE FUNCTION public.chinook_bad_invoice();
            """)
        action = self.grant()
        try:
            with self.assertRaises(psycopg.Error):
                self.act(action)
            self.assertEqual(self.state(), (self.original_email, self.original_price))
            self.assertFalse(self.consumed(action))
            self.assertIsNone(self.committed(action))
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("DROP TRIGGER zz_chinook_bad_invoice ON public.customer")
                c.execute("DROP FUNCTION public.chinook_bad_invoice()")
        self.assertEqual(self.act(action), "applied")
        self.assertEqual(self.proof(), "verified")

    def test_later_before_trigger_cannot_rewrite_unapproved_column(self):
        # Postgres executes same-event BEFORE triggers alphabetically. This
        # trigger runs AFTER the agentproof_exact_row guard saw the original NEW.
        with psycopg.connect(ADMIN) as c:
            c.execute("""
                CREATE FUNCTION public.zz_effect_rewrite() RETURNS trigger
                LANGUAGE plpgsql AS $body_rewrite$
                BEGIN
                  NEW.first_name := 'UNAUTHORIZED';
                  RETURN NEW;
                END; $body_rewrite$;
            """)
            c.execute("""
                CREATE TRIGGER zz_effect_rewrite BEFORE UPDATE ON public.customer
                FOR EACH ROW EXECUTE FUNCTION public.zz_effect_rewrite();
            """)
        action = self.grant()
        try:
            with self.assertRaises(psycopg.Error):
                self.act(action)
            self.assertEqual(self.state(), (self.original_email, self.original_price))
            self.assertFalse(self.consumed(action))
            self.assertIsNone(self.committed(action))
            with psycopg.connect(READER) as c:
                first_name = c.execute(
                    "SELECT first_name FROM public.customer WHERE customer_id=1"
                ).fetchone()[0]
            self.assertNotEqual(first_name, "UNAUTHORIZED")
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("DROP TRIGGER zz_effect_rewrite ON public.customer")
                c.execute("DROP FUNCTION public.zz_effect_rewrite()")

    def test_later_before_trigger_cannot_rewrite_approved_value(self):
        with psycopg.connect(ADMIN) as c:
            c.execute("""
                CREATE FUNCTION public.zz_effect_wrong_value() RETURNS trigger
                LANGUAGE plpgsql AS $body_email$
                BEGIN
                  NEW.email := 'WRONG@local.invalid';
                  RETURN NEW;
                END; $body_email$;
            """)
            c.execute("""
                CREATE TRIGGER zz_effect_wrong_value BEFORE UPDATE ON public.customer
                FOR EACH ROW EXECUTE FUNCTION public.zz_effect_wrong_value();
            """)
        action = self.grant()
        try:
            with self.assertRaises(psycopg.Error):
                self.act(action)
            self.assertEqual(self.state(), (self.original_email, self.original_price))
            self.assertFalse(self.consumed(action))
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("DROP TRIGGER zz_effect_wrong_value ON public.customer")
                c.execute("DROP FUNCTION public.zz_effect_wrong_value()")

    def test_other_customer_change_inside_trigger_rolls_back(self):
        with psycopg.connect(ADMIN) as c:
            c.execute("""
              CREATE FUNCTION public.chinook_bad_customer() RETURNS trigger
              LANGUAGE plpgsql AS $$
              BEGIN
                UPDATE public.customer SET email='wrong@local.invalid'
                WHERE customer_id=2;
                RETURN NEW;
              END; $$;
            """)
            c.execute("""
              CREATE TRIGGER zz_chinook_bad_customer AFTER UPDATE ON public.customer
              FOR EACH ROW WHEN (NEW.customer_id=1)
              EXECUTE FUNCTION public.chinook_bad_customer();
            """)
        a = self.grant()
        try:
            with self.assertRaises(psycopg.Error):
                self.act(a)
            self.assertEqual(self.state(), (self.original_email, self.original_price))
            self.assertFalse(self.consumed(a))
        finally:
            with psycopg.connect(ADMIN) as c:
                c.execute("DROP TRIGGER zz_chinook_bad_customer ON public.customer")
                c.execute("DROP FUNCTION public.chinook_bad_customer()")

    def test_revoke_after_function_returns_rolls_back_same_transaction(self):
        a = self.grant()
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(WRITER) as c:
                self.assertEqual(c.execute(
                    "SELECT agentproof_generic.apply_text_change(%s)",
                    (a,)).fetchone()[0], "applied")
                c.execute("UPDATE public.customer SET email='wrong@local.invalid' WHERE customer_id=2")
        self.assertEqual(self.state(), (self.original_email, self.original_price))
        self.assertFalse(self.consumed(a))
        self.assertIsNone(self.committed(a))

    def test_concurrent_replay_only_one_commits(self):
        a = self.grant()
        def attempt(_):
            try:
                return self.act(a)
            except psycopg.Error:
                return "denied"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, range(2)))
        self.assertCountEqual(outcomes, ["applied", "denied"])
        self.assertEqual(self.state(), (TARGET, self.original_price))
        self.assertTrue(self.consumed(a))

    def test_no_truncate_even_by_owner_without_disabling_guard(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(ADMIN) as c:
                c.execute("TRUNCATE public.invoice_line CASCADE")
        self.assertEqual(self.state(), (self.original_email, self.original_price))

    def test_invoice_line_direct_write_remains_blocked(self):
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(ADMIN) as c:
                c.execute("UPDATE public.invoice_line SET unit_price=0 WHERE invoice_line_id=1")
        self.assertEqual(self.state(), (self.original_email, self.original_price))


if __name__ == "__main__":
    unittest.main()
