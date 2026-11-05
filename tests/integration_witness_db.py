"""Real PostgreSQL 16 enforcement test for independent witness HMAC admission.

Only runs against a disposable service explicitly provided by the CI job.
Never run with a customer, shared, or long-lived PostgreSQL DSN.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

try:
    import psycopg
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agentproof.witness_db import _payload, apply_with_db_witness, mint_db_admission
    from agentproof.witness_reservations import DurableWitnessLedger, WitnessDenied
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

ADMIN = os.getenv("AGENTPROOF_WITNESS_PG_ADMIN_DSN")
ACTOR = os.getenv("AGENTPROOF_WITNESS_PG_ACTOR_DSN")
ROOT = Path(__file__).resolve().parents[1]
KEY = bytes.fromhex("a4" * 32)
ROLE = "agentproof_witness_ci_actor"


@unittest.skipUnless(HAS_DEPS and ADMIN and ACTOR, "disposable PostgreSQL 16 CI service required")
class RealWitnessGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with psycopg.connect(ADMIN, autocommit=True) as conn:
            conn.execute("CREATE ROLE " + ROLE + " LOGIN PASSWORD 'isolated-witness-actor-pass'")
            conn.execute("""
                CREATE TABLE public.witness_ci_accounts (
                    id text PRIMARY KEY, status text NOT NULL, protected_note text NOT NULL)
            """)
            conn.execute("""
                INSERT INTO public.witness_ci_accounts VALUES ('A-1', 'initial', 'do-not-edit')
            """)
            conn.execute("GRANT USAGE ON SCHEMA public TO " + ROLE)
            conn.execute("GRANT SELECT ON public.witness_ci_accounts TO " + ROLE)
            conn.execute("GRANT UPDATE(status) ON public.witness_ci_accounts TO " + ROLE)
            conn.execute((ROOT / "examples/postgres_generic_gate/install.sql").read_text())
            conn.execute("SELECT agentproof_generic.protect_table("
                         "'public.witness_ci_accounts'::regclass)")
            conn.execute("GRANT USAGE ON SCHEMA agentproof_generic TO " + ROLE)
            # Simulate the OLD permission that must be revoked at migration.
            conn.execute("GRANT EXECUTE ON FUNCTION "
                         "agentproof_generic.apply_text_change(uuid) TO " + ROLE)
            conn.execute((ROOT / "examples/postgres_witness_gate/install.sql").read_text())
            conn.execute("INSERT INTO agentproof_witnessed.config(actor_role,mac_key) "
                         "VALUES (%s,%s)", (ROLE, KEY))
            conn.execute("REVOKE EXECUTE ON FUNCTION "
                         "agentproof_generic.apply_text_change(uuid) FROM " + ROLE)
            conn.execute("GRANT USAGE ON SCHEMA agentproof_witnessed TO " + ROLE)
            conn.execute("GRANT EXECUTE ON FUNCTION "
                         "agentproof_witnessed.apply(uuid,text,bigint,text) TO " + ROLE)
            # Also verify the actor was not accidentally given MAC-key access.
            assert conn.execute("SELECT has_table_privilege(%s, "
                   "'agentproof_witnessed.config','SELECT')", (ROLE,)).fetchone()[0] is False
            assert conn.execute("SELECT has_function_privilege(%s, "
                   "'agentproof_generic.apply_text_change(uuid)','EXECUTE')",
                   (ROLE,)).fetchone()[0] is False

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = DurableWitnessLedger(
            str(Path(self.tmp.name) / "durable.sqlite"),
            Ed25519PrivateKey.generate())
        with psycopg.connect(ADMIN) as conn:
            conn.execute("ALTER TABLE public.witness_ci_accounts DISABLE TRIGGER USER")
            conn.execute("UPDATE public.witness_ci_accounts "
                         "SET status='initial',protected_note='do-not-edit' WHERE id='A-1'")
            conn.execute("DELETE FROM agentproof_generic.active")
            conn.execute("DELETE FROM agentproof_generic.committed")
            conn.execute("DELETE FROM agentproof_generic.grants")
            conn.execute("ALTER TABLE public.witness_ci_accounts ENABLE TRIGGER USER")

    def grant(self, *, old_value="initial", new_value="authorized", expiry_seconds=150):
        action_id = uuid4()
        with psycopg.connect(ADMIN) as conn:
            conn.execute("""
                INSERT INTO agentproof_generic.grants
                  (action_id,target_oid,key_column,key_value,update_column,
                   old_value,new_value,executor_role,expires_at)
                VALUES (%s, 'public.witness_ci_accounts'::regclass::oid,
                        'id','A-1','status',%s,%s,%s,%s)
            """, (action_id, old_value, new_value, ROLE,
                  datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)))
        return str(action_id)

    def admission(self, action):
        receipt = self.ledger.reserve(action, str(uuid4()), str(uuid4()).replace("-", "")[:32])
        return mint_db_admission(receipt, action_id=action, mac_key_hex=KEY.hex())

    def state(self):
        with psycopg.connect(ADMIN) as conn:
            return conn.execute("SELECT status,protected_note FROM public.witness_ci_accounts "
                                "WHERE id='A-1'").fetchone()

    def consumed(self, action):
        with psycopg.connect(ADMIN) as conn:
            return conn.execute("SELECT consumed_at IS NOT NULL FROM "
                                "agentproof_generic.grants WHERE action_id=%s",
                                (action,)).fetchone()[0]

    def test_authorized_commit_matches_independent_row_read(self):
        action = self.grant()
        admission = self.admission(action)
        result = apply_with_db_witness(ACTOR, action, admission)
        self.assertEqual(result, {"action_id": action, "state": "submitted_unverified"})
        self.assertEqual(self.state(), ("authorized", "do-not-edit"))
        self.assertTrue(self.consumed(action))

    def test_direct_legacy_and_config_access_are_denied(self):
        action = self.grant()
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(ACTOR) as conn:
                conn.execute("SELECT agentproof_generic.apply_text_change(%s)", (action,))
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(ACTOR) as conn:
                conn.execute("SELECT mac_key FROM agentproof_witnessed.config")
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(ACTOR) as conn:
                conn.execute("UPDATE public.witness_ci_accounts SET status='tampered' "
                             "WHERE id='A-1'")
        self.assertFalse(self.consumed(action))
        self.assertEqual(self.state(), ("initial", "do-not-edit"))

    def test_no_witness_proof_rejected_at_db_boundary(self):
        action = self.grant()
        for receipt_hash, timestamp, mac in [
            ("a" * 64, 1, "b" * 64), ("a" * 64, 9999999999, "b" * 64),
            ("invalid", 1, "b" * 64), ("a" * 64, 1, "invalid"),
        ]:
            with self.assertRaises(psycopg.Error):
                with psycopg.connect(ACTOR) as conn:
                    conn.execute("SELECT agentproof_witnessed.apply(%s,%s,%s,%s)",
                                 (action, receipt_hash, timestamp, mac))
        self.assertFalse(self.consumed(action))
        self.assertEqual(self.state(), ("initial", "do-not-edit"))

    def test_forged_mac_and_cross_action_token_rejected(self):
        first, second = self.grant(), self.grant()
        attestation = self.admission(first)
        for action, mac in ((first, "f" * 64), (second, attestation["mac_sha256"])):
            with self.assertRaises(psycopg.Error):
                with psycopg.connect(ACTOR) as conn:
                    conn.execute("SELECT agentproof_witnessed.apply(%s,%s,%s,%s)",
                                 (action, attestation["receipt_sha256"],
                                  attestation["issued_at_epoch"], mac))
        self.assertFalse(self.consumed(first))
        self.assertFalse(self.consumed(second))

    def test_expired_and_future_signed_admission_rejected(self):
        action = self.grant()
        receipt = self.admission(action)
        for seconds in (receipt["issued_at_epoch"] - 200,
                        receipt["issued_at_epoch"] + 200):
            forged_as_witness = {
                **receipt,
                "issued_at_epoch": seconds,
                "mac_sha256": hmac.new(KEY, _payload(
                    action, receipt["receipt_sha256"], seconds),
                    hashlib.sha256).hexdigest(),
            }
            with self.assertRaises(WitnessDenied):
                apply_with_db_witness(ACTOR, action, forged_as_witness)
        self.assertFalse(self.consumed(action))

    def test_replay_denied_after_successful_transaction(self):
        action = self.grant()
        token = self.admission(action)
        apply_with_db_witness(ACTOR, action, token)
        with self.assertRaises(WitnessDenied):
            apply_with_db_witness(ACTOR, action, token)
        self.assertEqual(self.state(), ("authorized", "do-not-edit"))

    def test_concurrent_same_action_exactly_one_commit(self):
        action = self.grant()
        token = self.admission(action)
        def attempt(_):
            try:
                apply_with_db_witness(ACTOR, action, token)
                return True
            except WitnessDenied:
                return False
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(self.state(), ("authorized", "do-not-edit"))
        self.assertTrue(self.consumed(action))

    def test_failed_underlying_row_guard_rolls_back_without_consumption(self):
        action = self.grant(old_value="not-current")
        with self.assertRaises(WitnessDenied):
            apply_with_db_witness(ACTOR, action, self.admission(action))
        self.assertFalse(self.consumed(action))
        self.assertEqual(self.state(), ("initial", "do-not-edit"))


    def test_authenticated_gateway_signed_witness_real_database_effect(self):
        """One synthetic JWT -> signed ledger -> DB HMAC -> real transaction.

        JWK issuance and witness HTTP transport are replaced with deterministic
        synthetic adapters. Database SQL and proof verification are real.
        """
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from agentproof.entra import EntraPolicy, verify_access_token
        from agentproof.mcp_gateway import GatewayConfig, GuardedActionGateway, GatewayDenied
        from agentproof.witness_http import WitnessClient
        from agentproof.witness_reservations import witness_public_key, receipt_hash

        tenant = "11111111-1111-4111-8111-111111111111"
        client_id = "22222222-2222-4222-8222-222222222222"
        principal = "33333333-3333-4333-8333-333333333333"
        policy = EntraPolicy(
            tenant_id=tenant, audience="api://agent-proof-witness-test",
            application_id=client_id, principal_object_id=principal,
            required_role="AgentProof.Apply")
        identity_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        class FakeJwks:
            def get_signing_key_from_jwt(self, token):
                return type("SignedKey", (), {"key": identity_key.public_key()})()

        now = int(datetime.now(timezone.utc).timestamp())
        claims = {"ver": "2.0",
                  "iss": "https://login.microsoftonline.com/" + tenant + "/v2.0",
                  "tid": tenant, "aud": policy.audience,
                  "azp": client_id, "oid": principal,
                  "roles": ["AgentProof.Apply"], "idtyp": "app",
                  "iat": now, "nbf": now - 10, "exp": now + 120}

        def token(**overrides):
            return jwt.encode({**claims, **overrides}, identity_key,
                              algorithm="RS256", headers={"kid": "synthetic"})

        action = self.grant()
        pubkey = witness_public_key(self.ledger.private_key)
        witness_called = []
        def signed_sender(payload):
            witness_called.append(payload["action_id"])
            receipt = self.ledger.reserve(payload["action_id"],
                                          payload["principal_id"], payload["nonce"])
            return {"receipt": receipt,
                    "db_admission": mint_db_admission(
                        receipt, action_id=payload["action_id"],
                        mac_key_hex=KEY.hex())}

        wclient = WitnessClient(
            "https://witness.example.invalid/v1/reservations",
            "s" * 48, pubkey, sender=signed_sender)
        cfg = GatewayConfig(
            policy=policy, actor_dsn=ACTOR,
            resource_url="https://gateway.example.invalid/mcp",
            witness_url="https://witness.example.invalid/v1/reservations",
            witness_bearer="s" * 48,
            witness_public_key_hex=pubkey, require_db_witness=True)
        gate = GuardedActionGateway(
            cfg, verifier=lambda t, p: verify_access_token(
                t, p, jwk_client=FakeJwks()), witness=wclient,
            executor=lambda *a: self.fail("unwitnessed SQL function called"))

        with self.assertRaises(GatewayDenied):
            gate.apply(token(aud="https://graph.microsoft.com"), action)
        self.assertEqual(witness_called, [])
        self.assertFalse(self.consumed(action))

        result = gate.apply(token(), action)
        self.assertEqual(result["state"], "submitted_unverified")
        self.assertEqual(witness_called, [action])
        self.assertTrue(self.consumed(action))
        self.assertEqual(self.state(), ("authorized", "do-not-edit"))
        self.assertEqual(len(self.ledger.read_all()), 1)
        self.assertEqual(result["witness_reservation_sha256"],
                         receipt_hash(self.ledger.read_all()[0]))
        self.assertFalse(result["independent_effect_verified"])
        with self.assertRaises(GatewayDenied):
            gate.apply(token(), action)
        self.assertEqual(witness_called, [action])


if __name__ == "__main__":
    unittest.main()
