"""Witness-to-database admission protocol and protected gateway tests.

All cryptography and database credentials in this module are synthetic.
PostgreSQL real-transaction tests are in integration_witness_db.py.
"""
import hashlib
import hmac
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agentproof.mcp_gateway import GatewayConfig, GatewayDenied, GuardedActionGateway
    from agentproof.witness_db import (
        SCHEMA, mint_db_admission, validate_db_admission, _payload,
    )
    from agentproof.witness_http import WitnessClient, make_handler
    from agentproof.witness_reservations import (
        DurableWitnessLedger, WitnessDenied, receipt_hash, witness_public_key,
    )
    HAS_DEPENDENCIES = True
except ImportError:
    HAS_DEPENDENCIES = False

from test_mcp_gateway import ACTION, PRINCIPAL, APP, TENANT, POLICY

MAC_KEY = "a4" * 32


@unittest.skipUnless(HAS_DEPENDENCIES, "install optional cryptography/gateway dependencies")
class WitnessDatabaseAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = DurableWitnessLedger(str(Path(self.tmp.name) / "witness.sqlite"),
                                           Ed25519PrivateKey.generate())
        self.public_key_hex = witness_public_key(self.ledger.private_key)
        self.receipt = self.ledger.reserve(ACTION, PRINCIPAL, "c" * 32)
        self.admission = mint_db_admission(self.receipt, action_id=ACTION, mac_key_hex=MAC_KEY)

    def test_signed_receipt_mac_is_deterministic_and_bound(self):
        self.assertEqual(self.admission["schema"], SCHEMA)
        self.assertEqual(self.admission["receipt_sha256"], receipt_hash(self.receipt))
        expected = hmac.new(bytes.fromhex(MAC_KEY),
                            _payload(ACTION, self.admission["receipt_sha256"],
                                     self.admission["issued_at_epoch"]),
                            hashlib.sha256).hexdigest()
        self.assertEqual(self.admission["mac_sha256"], expected)
        self.assertEqual(validate_db_admission(self.admission,
                         signed_receipt_sha256=receipt_hash(self.receipt)), self.admission)

    def test_wrong_action_key_and_tamper_rejected(self):
        with self.assertRaises(WitnessDenied):
            mint_db_admission(self.receipt, action_id=str(uuid4()), mac_key_hex=MAC_KEY)
        with self.assertRaises(WitnessDenied):
            mint_db_admission(self.receipt, action_id=ACTION, mac_key_hex="bad")
        for key, value in (("schema", "bad"), ("receipt_sha256", "0" * 64),
                           ("issued_at_epoch", -1), ("mac_sha256", "xx")):
            bad = {**self.admission, key: value}
            with self.assertRaises(WitnessDenied):
                validate_db_admission(bad, signed_receipt_sha256=receipt_hash(self.receipt))

    def test_gateway_strict_path_uses_only_witnessed_sql_executor(self):
        effects = []
        class StrictWitness:
            def reserve(_, action, principal):
                raise AssertionError("legacy unsigned path must not run")
            def reserve_for_database(_, action, principal):
                self.assertEqual((action, principal), (ACTION, PRINCIPAL))
                return dict(self.admission)
        cfg = GatewayConfig(
            POLICY, "postgresql://synthetic-gate", "https://gateway.example.invalid/mcp",
            "https://witness.example.invalid/v1/reservations",
            "w" * 48, self.public_key_hex, require_db_witness=True,
        )
        expected_identity = {
            "tenant_id": TENANT, "application_id": APP,
            "principal_object_id": PRINCIPAL, "authorized_role": "AgentProof.Apply",
        }
        def strict_executor(dsn, action, admission):
            self.assertEqual(dsn, "postgresql://synthetic-gate")
            self.assertEqual(action, ACTION)
            self.assertEqual(admission["receipt_sha256"], receipt_hash(self.receipt))
            effects.append(action)
            return {"action_id": action, "state": "submitted_unverified"}
        gate = GuardedActionGateway(
            cfg, verifier=lambda t, p: expected_identity,
            executor=lambda *args: self.fail("legacy SQL entry bypassed strict mode"),
            witnessed_executor=strict_executor,
            witness=StrictWitness(),
        )
        result = gate.apply("synthetic-valid", ACTION)
        self.assertEqual(effects, [ACTION])
        self.assertEqual(result["state"], "submitted_unverified")
        self.assertFalse(result["independent_effect_verified"])
        self.assertEqual(result["witness_reservation_sha256"], receipt_hash(self.receipt))

    def test_gateway_cli_always_uses_strict_database_mode(self):
        cfg = GatewayConfig.from_env({
            "AGENTPROOF_ENTRA_TENANT_ID": TENANT,
            "AGENTPROOF_ENTRA_AUDIENCE": POLICY.audience,
            "AGENTPROOF_ENTRA_CLIENT_ID": APP,
            "AGENTPROOF_ENTRA_PRINCIPAL_OID": PRINCIPAL,
            "AGENTPROOF_ACTOR_DSN": "postgresql://synthetic-gate",
            "AGENTPROOF_MCP_RESOURCE_URL": "https://gateway.example.invalid/mcp",
            "AGENTPROOF_WITNESS_URL": "https://witness.example.invalid/v1/reservations",
            "AGENTPROOF_WITNESS_OUTBOUND_TOKEN": "w" * 48,
            "AGENTPROOF_WITNESS_PUBLIC_KEY": self.public_key_hex,
        })
        self.assertTrue(cfg.require_db_witness)

    def test_strict_mode_rejects_missing_mac_and_never_executes(self):
        effects = []
        class AbsentMac:
            def reserve_for_database(_, a, p):
                raise WitnessDenied("witness returned no DB admission")
        cfg = GatewayConfig(
            POLICY, "postgresql://synthetic-gate", "https://gateway.example.invalid/mcp",
            "https://witness.example.invalid/v1/reservations", "w" * 48,
            self.public_key_hex, require_db_witness=True,
        )
        identity = {"tenant_id": TENANT, "application_id": APP,
                    "principal_object_id": PRINCIPAL, "authorized_role": "AgentProof.Apply"}
        gate = GuardedActionGateway(cfg, verifier=lambda t, p: identity,
                                    witness=AbsentMac(),
                                    witnessed_executor=lambda *a: effects.append(a))
        with self.assertRaisesRegex(GatewayDenied, "action denied"):
            gate.apply("synthetic", ACTION)
        self.assertEqual(effects, [])

    def test_real_client_validates_both_signed_receipt_and_db_proof(self):
        def good_sender(payload):
            action = str(uuid4())
            nonce = payload["nonce"]
            receipt = self.ledger.reserve(action, PRINCIPAL, nonce)
            return {"receipt": receipt, "db_admission": mint_db_admission(
                receipt, action_id=action, mac_key_hex=MAC_KEY)}
        client = WitnessClient("https://witness.example.invalid/v1/reservations",
                               "s" * 48, self.public_key_hex, sender=good_sender)
        # The ledger is durable and the request's fresh challenge is signed.
        # Fixture UUID must match what the mocked sender stores.
        another = str(uuid4())
        def matching_sender(payload):
            receipt = self.ledger.reserve(payload["action_id"],
                                          payload["principal_id"], payload["nonce"])
            return {"receipt": receipt, "db_admission": mint_db_admission(
                receipt, action_id=payload["action_id"], mac_key_hex=MAC_KEY)}
        client._sender = matching_sender
        result = client.reserve_for_database(another, PRINCIPAL)
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(len(result["mac_sha256"]), 64)

        missing = WitnessClient("https://witness.example.invalid/v1/reservations",
                                "s" * 48, self.public_key_hex,
                                sender=lambda payload: {"receipt": self.receipt})
        with self.assertRaises(WitnessDenied):
            missing.reserve_for_database(ACTION, PRINCIPAL)


if __name__ == "__main__":
    unittest.main()
